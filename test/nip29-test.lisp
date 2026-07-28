;;;; test/nip29-test.lisp
;;;;
;;;; Oracle for relay-side NIP-29 group management. A client posts kind-9007
;;;; (create) and kind-9021 (join); skep must turn those into relay-signed
;;;; addressable events — 39000 (metadata), 39001 (admins), 39002 (members) —
;;;; that buzz-acp discovers (query 39002 by #p, read channel from the `d` tag).
;;;; No buzz binary needed. Exit 0 iff all pass.
;;;;   sbcl --script test/nip29-test.lisp

(let ((here (or *load-truename* *compile-file-truename*)))
  (load (merge-pathnames "../src/skep.lisp" here)))
(in-package #:skep)

(defvar *fails* 0)
(defmacro check (name form)
  `(handler-case (if ,form (format t "  ok   ~A~%" ,name)
                     (progn (incf *fails*) (format t "  FAIL ~A~%" ,name)))
     (error (e) (incf *fails*) (format t "  ERR  ~A: ~A~%" ,name e))))

(setf *relay-port* 8630)
(reset-store!)
(start-relay *relay-port*)
(sleep 0.4)
(defparameter *url* (relay-url *relay-port*))

(defparameter *human* (n:gen-key)) (defparameter *hpub* (n:hex-pubkey *human*))
(defparameter *agent* (n:gen-key)) (defparameter *apub* (n:hex-pubkey *agent*))
(defparameter *chan* "8fc2684a-7c4b-4e9f-8f5b-51ae665a7605")

(defun q (filter) (n:fetch-events (n:json filter) :secs 2 :relays (list *url*)))
(defun members-filter (pub)
  (let ((h (make-hash-table :test 'equal)))
    (setf (gethash "kinds" h) (vector 39002) (gethash "#p" h) (vector pub)) h))

(format t "~&== kind-9007 create -> relay emits 39000/39001/39002 ==~%")
(let ((create (n:sign-event *human* *hpub* (n:unix-now) 9007
                (vector (vector "h" *chan*) (vector "name" "interop")
                        (vector "visibility" "open") (vector "channel_type" "stream")) "")))
  (check "relay accepts the 9007" (plusp (post-message create :url *url*)))
  (sleep 0.3)
  (let* ((meta (q (let ((h (make-hash-table :test 'equal)))
                    (setf (gethash "kinds" h) (vector 39000) (gethash "#d" h) (vector *chan*)) h)))
         (mem (q (members-filter *hpub*)))
         (m0 (first mem)) (md0 (first meta)))
    (check "39000 metadata emitted"        md0)
    (check "39000 is relay-signed"         (and md0 (equal (sender-of md0) (relay-pubkey))))
    (check "39000 carries the name"        (and md0 (equal "interop" (tag-val md0 "name"))))
    (check "39000 marks it public"         (and md0 (loop for tg across (gethash "tags" md0)
                                                          thereis (equal (aref tg 0) "public"))))
    (check "39002 members emitted"         m0)
    (check "39002 is relay-signed"         (and m0 (equal (sender-of m0) (relay-pubkey))))
    (check "creator is a member (found via #p)" m0)
    (check "39002 channel is in the d-tag" (and m0 (equal *chan* (tag-val m0 "d"))))
    (check "creator's role is owner"
           (and m0 (loop for tg across (gethash "tags" m0)
                         thereis (and (equal (aref tg 0) "p") (equal (aref tg 1) *hpub*)
                                      (equal (aref tg 2) "owner")))))
    ;; the agent is NOT a member yet
    (check "agent not yet discoverable"    (null (q (members-filter *apub*))))))

(format t "~&== kind-9021 join -> agent added, 39002 re-emitted ==~%")
(let ((join (n:sign-event *agent* *apub* (n:unix-now) 9021 (vector (vector "h" *chan*)) "")))
  (check "relay accepts the 9021" (plusp (post-message join :url *url*)))
  (sleep 0.3)
  (let* ((mem (q (members-filter *apub*))) (m0 (first mem)))
    (check "agent now discoverable via #p on 39002" m0)
    (check "the agent's channel is the created one" (and m0 (equal *chan* (tag-val m0 "d"))))
    (check "both human and agent are members"
           (and m0 (let ((ps (tag-vals m0 "p")))
                     (and (member *hpub* ps :test #'equal) (member *apub* ps :test #'equal)))))
    (check "skep's own membership reflects the join" (member *apub* (channel-members *chan*) :test #'equal))))

(format t "~&== join to a PRIVATE channel is refused ==~%")
(let* ((pchan "11111111-2222-4333-8444-555555555555")
       (create (n:sign-event *human* *hpub* (n:unix-now) 9007
                 (vector (vector "h" pchan) (vector "name" "secret") (vector "visibility" "private")) ""))
       (outsider (n:gen-key)) (opub (n:hex-pubkey outsider)))
  (post-message create :url *url*) (sleep 0.3)
  (let ((join (n:sign-event outsider opub (n:unix-now) 9021 (vector (vector "h" pchan)) "")))
    (post-message join :url *url*) (sleep 0.3)
    (check "outsider did NOT join the private channel"
           (not (member opub (channel-members pchan) :test #'equal)))))

(stop-relay)
(format t "~&~%nip29-test: ~A failure~:P~%" *fails*)
(sb-ext:exit :code (if (zerop *fails*) 0 1))
