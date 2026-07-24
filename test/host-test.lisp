;;;; test/host-test.lisp
;;;;
;;;; Slice-1b oracle for the full skep LOOP: a human posts a kind-9 message that
;;;; mentions the agent; the host sees the #p mention, runs the agent (stubbed —
;;;; no live model), and posts a NIP-10-threaded kind-9 reply back to the channel
;;;; that mentions the human. Proves the watch→answer→reply wiring end to end on
;;;; our own relay. Exit 0 iff all pass.
;;;;
;;;;   sbcl --script test/host-test.lisp

(let ((here (or *load-truename* *compile-file-truename*)))
  (load (merge-pathnames "../src/host.lisp" here)))
(defpackage #:skep-host-test
  (:use #:cl) (:local-nicknames (#:skep #:skep) (#:host #:skep.host) (#:n #:skep.nostr)))
(in-package #:skep-host-test)

(defvar *fails* 0)
(defmacro check (name form)
  `(handler-case (if ,form (format t "  ok   ~A~%" ,name)
                     (progn (incf *fails*) (format t "  FAIL ~A~%" ,name)))
     (error (e) (incf *fails*) (format t "  ERR  ~A: ~A~%" ,name e))))

(setf skep:*relay-port* 8402)
(skep:reset-store!)
(skep:start-relay skep:*relay-port*)
(sleep 0.4)

;; identities + channel
(defparameter *human* (n:gen-key))
(defparameter *agent* (n:gen-key))
(defparameter *hpub* (n:hex-pubkey *human*))
(defparameter *apub* (n:hex-pubkey *agent*))
(defparameter *chan* (skep:new-channel :name "build" :members (list *hpub* *apub*)))

;; wire the host to this agent + relay, stub the model (deterministic, tokenless)
(setf host:*agent-sec* *agent*
      host:*relay* (skep:relay-url skep:*relay-port*)
      host:*respond-to* :anyone)
(defparameter *seen-context* nil)
(setf host:*answer-fn*
      (lambda (ctx)
        (setf *seen-context* ctx)
        "On it — spinning up the build now. I'll report back when it's green."))

(format t "~&== the agent context is built from the triggering message ==~%")
(let ((probe (skep:build-message *human* *chan* "hey @agent, can you kick off the build?"
                                 :mentions (list *apub*))))
  (let ((ctx (host:context-for probe)))
    (check "context includes the channel"  (search *chan* ctx))
    (check "context includes the message"  (search "kick off the build" ctx))))

(format t "~&== full loop: human mentions agent -> host replies in-thread ==~%")
(let ((ask (skep:build-message *human* *chan* "hey @agent, can you kick off the build?"
                               :mentions (list *apub*))))
  (check "human post ACKed" (plusp (skep:post-message ask :url (skep:relay-url skep:*relay-port*))))
  (sleep 0.2)
  ;; drive one poll cycle explicitly (deterministic)
  (let ((answered (host:poll-once)))
    (check "host answered exactly one mention" (= 1 answered))
    (check "the stubbed model saw the human's text" (and *seen-context* (search "kick off the build" *seen-context*)))
    (sleep 0.2)
    ;; the reply must now be on the channel: kind 9, by the agent, threaded, mentioning the human
    (let* ((filt (let ((h (make-hash-table :test 'equal)))
                   (setf (gethash "kinds" h) (vector 9) (gethash "#h" h) (vector *chan*)) h))
           (evs (n:fetch-events (n:json filt) :secs 2 :relays (list (skep:relay-url skep:*relay-port*))))
           (reply (find *apub* evs :key #'skep:sender-of :test #'equal)))
      (check "channel now holds two messages" (= 2 (length evs)))
      (check "a reply authored by the agent exists" reply)
      (check "reply is kind 9"                 (and reply (skep:kind-9-p reply)))
      (check "reply content is the agent's answer"
             (and reply (search "spinning up the build" (skep:content-of reply))))
      (check "reply mentions the human back"   (and reply (member *hpub* (skep:mentions-of reply) :test #'equal)))
      (check "reply threads to the human's message"
             (and reply (loop for tg across (gethash "tags" reply)
                              thereis (and (equal (aref tg 0) "e")
                                           (equal (aref tg 1) (skep:id-of ask))
                                           (equal (aref tg 3) "reply")))))
      (check "reply self-verifies"             (and reply (n:verify-event reply))))))

(format t "~&== the host does not answer itself (no infinite loop) ==~%")
(let ((before (host:poll-once)))
  ;; nothing new mentions the agent (the reply mentions the human, not the agent)
  (check "a second poll answers nothing new" (= 0 before)))

(skep:stop-relay)
(format t "~&~%host-test: ~A failure~:P~%" *fails*)
(sb-ext:exit :code (if (zerop *fails*) 0 1))
