;;;; test/acp-client-test.lisp
;;;;
;;;; Slice-3 oracle: skep as a PROPER ACP host. skep.acp spawns an ACP agent
;;;; subprocess (a deterministic stub — no model/token) and drives it over stdio:
;;;;   - initialize handshake,
;;;;   - a turn streams agent_message_chunk updates that we accumulate,
;;;;   - a mid-turn session/request_permission is answered while the turn is still
;;;;     streaming (the bidirectional path a naive blocking client would deadlock),
;;;;   - the whole thing wired as skep.host:*answer-fn* runs the full channel loop
;;;;     with the agent OUT of process.
;;;; Exit 0 iff all pass.   sbcl --script test/acp-client-test.lisp

(let ((here (or *load-truename* *compile-file-truename*)))
  (load (merge-pathnames "../src/acp-client.lisp" here))
  (load (merge-pathnames "../src/host.lisp" here)))
(defpackage #:skep-acp-test
  (:use #:cl) (:local-nicknames (#:skep #:skep) (#:acp #:skep.acp)
                                (#:host #:skep.host) (#:n #:skep.nostr)))
(in-package #:skep-acp-test)

(defvar *fails* 0)
(defmacro check (name form)
  `(handler-case (if ,form (format t "  ok   ~A~%" ,name)
                     (progn (incf *fails*) (format t "  FAIL ~A~%" ,name)))
     (error (e) (incf *fails*) (format t "  ERR  ~A: ~A~%" ,name e))))

(defparameter *stub*
  (namestring (merge-pathnames "stub-acp-agent.lisp"
                               (or *load-truename* *compile-file-truename*))))
(defun spawn-stub () (acp:make-client "sbcl" :args (list "--script" *stub*)))

(format t "~&== initialize handshake ==~%")
(let ((cl (spawn-stub)))
  (unwind-protect
       (let ((r (acp:initialize cl)))
         (check "agent is alive"           (acp:client-alive-p cl))
         (check "initialize returns protocolVersion 1"
                (eql 1 (acp::m@ r "result" "protocolVersion"))))
    (acp:shutdown cl)))

(format t "~&== a turn streams chunks we accumulate ==~%")
(let ((cl (spawn-stub)))
  (unwind-protect
       (progn (acp:initialize cl)
              (let ((text (acp:run-turn cl "hello there" :system "you are a stub")))
                (check "turn returns the streamed assistant text"
                       (search "ACP-STUB: heard hello there" text))))
    (acp:shutdown cl)))

(format t "~&== mid-turn permission is answered (no deadlock) ==~%")
(let ((cl (spawn-stub)))
  (unwind-protect
       (progn (acp:initialize cl)
              ;; the stub blocks on our permission reply before it finishes the turn;
              ;; if our reader thread answers it, the turn completes and returns text.
              (let ((text (acp:run-turn cl "please run the build")))
                (check "permission-gated turn completes"
                       (search "heard please run the build" text))))
    (acp:shutdown cl)))

(format t "~&== full channel loop with the agent OUT of process ==~%")
(setf skep:*relay-port* 8412)
(skep:reset-store!)
(skep:start-relay skep:*relay-port*)
(sleep 0.4)
(multiple-value-bind (fn cl) (acp:make-acp-answer-fn "sbcl" :args (list "--script" *stub*)
                                                    :system "skep channel agent")
  (unwind-protect
       (let* ((human (n:gen-key)) (agent (n:gen-key))
              (hpub (n:hex-pubkey human)) (apub (n:hex-pubkey agent))
              (chan (skep:new-channel :name "acp" :members (list hpub apub))))
         (setf host:*agent-sec* agent
               host:*relay* (skep:relay-url skep:*relay-port*)
               host:*answer-fn* fn
               host:*respond-to* :anyone)
         (let ((ask (skep:build-message human chan "hey @agent, status?" :mentions (list apub))))
           (skep:post-message ask :url (skep:relay-url skep:*relay-port*))
           (sleep 0.2)
           (check "host answered one mention via ACP" (= 1 (host:poll-once)))
           (sleep 0.2)
           (let* ((filt (let ((h (make-hash-table :test 'equal)))
                          (setf (gethash "kinds" h) (vector 9) (gethash "#h" h) (vector chan)) h))
                  (evs (n:fetch-events (n:json filt) :secs 2 :relays (list (skep:relay-url skep:*relay-port*))))
                  (reply (find apub evs :key #'skep:sender-of :test #'equal)))
             (check "an agent reply is on the channel" reply)
             (check "reply carries the ACP agent's streamed text"
                    (and reply (search "ACP-STUB: heard" (skep:content-of reply))))
             (check "reply threads to the human's message"
                    (and reply (loop for tg across (gethash "tags" reply)
                                     thereis (and (equal (aref tg 0) "e")
                                                  (equal (aref tg 1) (skep:id-of ask)))))))))
    (acp:shutdown cl)
    (skep:stop-relay)))

(format t "~&~%acp-client-test: ~A failure~:P~%" *fails*)
(sb-ext:exit :code (if (zerop *fails*) 0 1))
