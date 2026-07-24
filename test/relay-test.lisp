;;;; test/relay-test.lisp
;;;;
;;;; Slice-1 oracle for the skep relay + NIP-29 message model. Proves the Buzz
;;;; interop CORE with no agent in the loop: a signed kind-9 message with an
;;;; ["h",<channel>] tag round-trips through the relay and comes back on a REQ
;;;; filtered by #h; #p mention-routing tag survives; NIP-10 threading tags are
;;;; preserved; a bad-signature event is rejected. Exit 0 iff all pass.
;;;;
;;;;   sbcl --script test/relay-test.lisp

(let ((here (or *load-truename* *compile-file-truename*)))
  (load (merge-pathnames "../src/skep.lisp" here)))
(in-package #:skep)

(defvar *fails* 0)
(defmacro check (name form)
  `(handler-case (if ,form (format t "  ok   ~A~%" ,name)
                     (progn (incf *fails*) (format t "  FAIL ~A~%" ,name)))
     (error (e) (incf *fails*) (format t "  ERR  ~A: ~A~%" ,name e))))

(setf *relay-port* 8399)
(reset-store!)
(start-relay *relay-port*)
(sleep 0.4)

(format t "~&== a kind-9 message round-trips on #h ==~%")
(let* ((human (n:gen-key)) (agent (n:gen-key))
       (hpub (n:hex-pubkey human)) (apub (n:hex-pubkey agent))
       (chan (new-channel :name "general" :members (list hpub apub)))
       (ev (build-message human chan "hello @agent, are you there?" :mentions (list apub))))
  (check "channel id is 32 hex chars" (and (stringp chan) (= 32 (length chan))))
  (check "message is kind 9"          (kind-9-p ev))
  (check "message carries the h tag"  (equal chan (h-tag ev)))
  (check "message mentions the agent" (member apub (mentions-of ev) :test #'equal))
  (check "message self-verifies"      (n:verify-event ev))
  ;; post it, then read it back through the relay by #h filter
  (check "relay ACKs the post" (plusp (post-message ev :url (relay-url *relay-port*))))
  (sleep 0.2)
  (let* ((filt (let ((h (make-hash-table :test 'equal)))
                 (setf (gethash "kinds" h) (vector 9) (gethash "#h" h) (vector chan))
                 h))
         (back (n:fetch-events (n:json filt) :secs 2 :relays (list (relay-url *relay-port*)))))
    (check "exactly one event returned on #h" (= 1 (length back)))
    (check "round-tripped id matches"   (and back (equal (id-of ev) (id-of (first back)))))
    (check "round-tripped content intact"
           (and back (search "are you there" (content-of (first back)))))
    (check "relay stored exactly one event" (= 1 (event-count)))

    ;; the mention filter (#p = the agent) is how a host wakes: it must find it
    (let* ((pf (let ((h (make-hash-table :test 'equal)))
                 (setf (gethash "kinds" h) (vector 9) (gethash "#p" h) (vector apub)) h))
           (mine (n:fetch-events (n:json pf) :secs 2 :relays (list (relay-url *relay-port*)))))
      (check "agent finds its mention via #p" (and mine (equal (id-of ev) (id-of (first mine))))))

    ;; a threaded reply: NIP-10 root/reply e-tags, mention back to the human
    (let* ((anchor (reply-anchor ev))
           (reply (build-message agent chan "yes — here. what do you need?"
                                 :root anchor :reply-to (id-of ev) :mentions (list hpub))))
      (check "reply anchor is the source id (no root tag yet)" (equal (id-of ev) anchor))
      (check "reply threads with a reply e-tag"
             (loop for tg across (gethash "tags" reply)
                   thereis (and (equal (aref tg 0) "e") (equal (aref tg 1) (id-of ev))
                                (equal (aref tg 3) "reply"))))
      (check "reply mentions the human back" (member hpub (mentions-of reply) :test #'equal))
      (check "relay ACKs the reply" (plusp (post-message reply :url (relay-url *relay-port*))))
      (sleep 0.2)
      (check "channel now has two stored events" (= 2 (event-count))))))

(format t "~&== a tampered event is rejected ==~%")
(let* ((k (n:gen-key)) (chan (new-channel :name "x"))
       (ev (build-message k chan "legit")))
  (setf (gethash "content" ev) "tampered after signing")   ; break the signature
  (check "relay does NOT store a bad-sig event"
         (progn (post-message ev :url (relay-url *relay-port*)) (sleep 0.2)
                (null (gethash (id-of ev) *events*)))))

(stop-relay)
(format t "~&~%relay-test: ~A failure~:P~%" *fails*)
(sb-ext:exit :code (if (zerop *fails*) 0 1))
