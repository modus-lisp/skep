;;;; test/cli-test.lisp
;;;;
;;;; Slice-2 oracle for the buzz-compatible CLI (skep.cli):
;;;;   - parse-secret handles 64-hex and nsec1… (NIP-19 test vector).
;;;;   - parse-args splits buzz-style positionals + repeated --flags.
;;;;   - send-message signs a well-formed kind-9 that round-trips on the relay.
;;;;   - main "messages send …" drives the same path end to end.
;;;; Exit 0 iff all pass.   sbcl --script test/cli-test.lisp

(let ((here (or *load-truename* *compile-file-truename*)))
  (load (merge-pathnames "../src/cli.lisp" here)))
(defpackage #:skep-cli-test
  (:use #:cl) (:local-nicknames (#:skep #:skep) (#:cli #:skep.cli) (#:n #:skep.nostr)))
(in-package #:skep-cli-test)

(defvar *fails* 0)
(defmacro check (name form)
  `(handler-case (if ,form (format t "  ok   ~A~%" ,name)
                     (progn (incf *fails*) (format t "  FAIL ~A~%" ,name)))
     (error (e) (incf *fails*) (format t "  ERR  ~A: ~A~%" ,name e))))

(format t "~&== parse-secret ==~%")
;; NIP-19 test vector (from the spec): nsec ↔ hex
(let ((nsec "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe7")
      (hex  "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"))
  (check "nsec decodes to the spec's hex key"
         (= (cli:parse-secret nsec) (parse-integer hex :radix 16)))
  (check "64-hex parses to the same integer"
         (= (cli:parse-secret hex) (parse-integer hex :radix 16))))

(format t "~&== parse-args ==~%")
(multiple-value-bind (pos flags)
    (cli:parse-args '("messages" "send" "--channel" "abc" "--text" "hello there"
                      "--mention" "p1" "--mention" "p2"))
  (check "positionals are messages/send" (equal pos '("messages" "send")))
  (check "single flag captured"          (equal "abc" (first (gethash "channel" flags))))
  (check "text with spaces captured"     (equal "hello there" (first (gethash "text" flags))))
  (check "repeated --mention collects a list"
         (equal '("p1" "p2") (gethash "mention" flags))))

(setf skep:*relay-port* 8408)
(skep:reset-store!)
(skep:start-relay skep:*relay-port*)
(sleep 0.4)
(defparameter *url* (skep:relay-url skep:*relay-port*))
(defparameter *k* (n:gen-key))
(defparameter *hex* (string-downcase (format nil "~64,'0X" *k*)))

(format t "~&== send-message round-trips on the relay ==~%")
(defparameter *chan* (skep:new-channel :name "cli" :members (list (n:hex-pubkey *k*))))
(let ((ev (cli:send-message :channel *chan* :text "sent via the buzz CLI"
                            :private-key *hex* :relay *url*)))
  (check "returned a kind-9 event" (skep:kind-9-p ev))
  (check "carries the channel h-tag" (equal *chan* (skep:h-tag ev)))
  (sleep 0.3)
  (let ((filt (let ((h (make-hash-table :test 'equal)))
                (setf (gethash "kinds" h) (vector 9) (gethash "#h" h) (vector *chan*)) h)))
    (let ((back (n:fetch-events (n:json filt) :secs 2 :relays (list *url*))))
      (check "message landed on the relay"
             (find (skep:id-of ev) back :key #'skep:id-of :test #'equal)))))

(format t "~&== main: `messages send …` posts a threaded reply ==~%")
(defparameter *anchor* (skep:build-message *k* *chan* "root message"))
(skep:post-message *anchor* :url *url*)
(sleep 0.2)
(let ((code (cli:main (list "messages" "send" "--channel" *chan* "--text" "a threaded reply"
                            "--reply-to" (skep:id-of *anchor*) "--mention" (n:hex-pubkey *k*)
                            "--private-key" *hex* "--relay" *url*))))
  (check "main returns exit code 0" (eql 0 code))
  (sleep 0.3)
  (let ((filt (let ((h (make-hash-table :test 'equal)))
                (setf (gethash "kinds" h) (vector 9) (gethash "#h" h) (vector *chan*)) h)))
    (let* ((evs (n:fetch-events (n:json filt) :secs 2 :relays (list *url*)))
           (reply (find-if (lambda (e) (search "threaded reply" (skep:content-of e))) evs)))
      (check "the reply is on the channel" reply)
      (check "reply threads to the anchor"
             (and reply (loop for tg across (gethash "tags" reply)
                             thereis (and (equal (aref tg 0) "e")
                                          (equal (aref tg 1) (skep:id-of *anchor*))))))
      (check "reply verifies" (and reply (n:verify-event reply))))))

(skep:stop-relay)
(format t "~&~%cli-test: ~A failure~:P~%" *fails*)
(sb-ext:exit :code (if (zerop *fails*) 0 1))
