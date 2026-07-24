;;;; test/auth-test.lisp
;;;;
;;;; Slice-2 oracle: NIP-42 auth + membership gating.
;;;;   - verify-auth accepts a good kind-22242 (matching challenge, fresh, signed)
;;;;     and rejects wrong-challenge / tampered / stale ones.
;;;;   - a private channel is members-only: a member's write is stored; an
;;;;     outsider's write is rejected & not stored.
;;;;   - a private channel's events fan out ONLY to a NIP-42-authed member: an
;;;;     unauthed reader and an authed non-member both see nothing; a member sees it.
;;;;   - open channels stay public (unauthed reads still work).
;;;; Exit 0 iff all pass.   sbcl --script test/auth-test.lisp

(let ((here (or *load-truename* *compile-file-truename*)))
  (load (merge-pathnames "../src/skep.lisp" here)))
(in-package #:skep)

(defvar *fails* 0)
(defmacro check (name form)
  `(handler-case (if ,form (format t "  ok   ~A~%" ,name)
                     (progn (incf *fails*) (format t "  FAIL ~A~%" ,name)))
     (error (e) (incf *fails*) (format t "  ERR  ~A: ~A~%" ,name e))))

(setf *relay-port* 8405)
(reset-store!)
(start-relay *relay-port*)
(sleep 0.4)
(defparameter *url* (relay-url *relay-port*))

(defparameter *agent* (n:gen-key))   (defparameter *apub* (n:hex-pubkey *agent*))
(defparameter *human* (n:gen-key))   (defparameter *hpub* (n:hex-pubkey *human*))
(defparameter *outsider* (n:gen-key))(defparameter *opub* (n:hex-pubkey *outsider*))

(format t "~&== NIP-42 verify-auth ==~%")
(let ((conn (list :challenge "deadbeefcafe")))
  (check "good auth verifies"
         (verify-auth conn (signed-auth-event *agent* "deadbeefcafe" *url*)))
  (check "wrong challenge rejected"
         (not (verify-auth conn (signed-auth-event *agent* "00000000" *url*))))
  (let ((ev (signed-auth-event *agent* "deadbeefcafe" *url*)))
    (setf (gethash "content" ev) "tampered")            ; break the signature
    (check "tampered auth rejected" (not (verify-auth conn ev))))
  (let ((stale (n:sign-event *agent* *apub* (- (n:unix-now) 200) 22242
                             (vector (vector "relay" *url*) (vector "challenge" "deadbeefcafe")) "")))
    (check "stale auth (created_at too old) rejected" (not (verify-auth conn stale)))))

(format t "~&== private channel is members-only for WRITES ==~%")
(defparameter *priv* (new-channel :name "war-room" :visibility :private :members (list *apub* *hpub*)))
(let ((good (build-message *human* *priv* "members only in here"))
      (bad  (build-message *outsider* *priv* "let me in")))
  (check "member write is ACKed"        (plusp (post-message good :url *url*)))
  (sleep 0.2)
  (check "member write is stored"       (gethash (id-of good) *events*))
  (check "outsider write is NOT ACKed"  (zerop (post-message bad :url *url*)))
  (sleep 0.2)
  (check "outsider write is NOT stored" (null (gethash (id-of bad) *events*))))

(format t "~&== private channel fans out only to authed members (READS) ==~%")
(let ((filt (let ((h (make-hash-table :test 'equal)))
              (setf (gethash "kinds" h) (vector 9) (gethash "#h" h) (vector *priv*)) h)))
  (let ((flt (n:json filt)))
    (check "member (authed) sees the private message"
           (plusp (length (nip42-fetch *human* flt *url* :secs 2))))
    (check "unauthed reader sees nothing"
           (zerop (length (n:fetch-events flt :secs 2 :relays (list *url*)))))
    (check "authed non-member sees nothing"
           (zerop (length (nip42-fetch *outsider* flt *url* :secs 2))))))

(format t "~&== open channels stay public ==~%")
(defparameter *open* (new-channel :name "lobby" :visibility :open :members (list *apub*)))
(let ((msg (build-message *outsider* *open* "hello lobby")))    ; non-member may post to an open channel
  (check "anyone can write an open channel" (plusp (post-message msg :url *url*)))
  (sleep 0.2)
  (let ((filt (let ((h (make-hash-table :test 'equal)))
                (setf (gethash "kinds" h) (vector 9) (gethash "#h" h) (vector *open*)) h)))
    (check "unauthed reader sees open-channel messages"
           (plusp (length (n:fetch-events (n:json filt) :secs 2 :relays (list *url*)))))))

(stop-relay)
(format t "~&~%auth-test: ~A failure~:P~%" *fails*)
(sb-ext:exit :code (if (zerop *fails*) 0 1))
