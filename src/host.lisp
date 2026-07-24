;;;; src/host.lisp
;;;;
;;;; The skep HOST — the Buzz-acp equivalent. It watches the relay for kind-9
;;;; messages that mention the agent (a ["p",<agent-pubkey>] tag), runs the agent
;;;; on the message, and posts a NIP-10-threaded kind-9 reply back to the channel.
;;;; This is the "agent lives in the workspace" loop, all on our own stack.
;;;;
;;;; The model call is injected via *answer-fn* (default drives operandi's engine),
;;;; so the watch→reply wiring is testable with no live model. Same shape as the
;;;; the same watch->run->reply shape, generalized from DMs to channels.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((here (or *load-truename* *compile-file-truename*)))
    (unless (find-package :skep) (load (merge-pathnames "skep.lisp" here)))))

(defpackage #:skep.host
  (:use #:cl)
  (:local-nicknames (#:skep #:skep) (#:n #:skep.nostr))
  (:export #:*agent-sec* #:*relay* #:*owner* #:*poll-secs* #:*system-prompt*
           #:*answer-fn* #:*tool-names* #:*respond-to*
           #:agent-pubkey #:context-for #:handle-event #:poll-once
           #:run-loop #:start #:stop #:running-p))
(in-package #:skep.host)

;;; ------------------------------- config -------------------------------
(defvar *agent-sec* nil "the agent's secp256k1 secret (integer). Set before start.")
(defvar *relay* nil "skep relay ws url; defaults to the local relay.")
(defvar *owner* nil "owner pubkey hex (NIP-OA); when set + *respond-to* = :owner, only the owner triggers.")
(defparameter *poll-secs* 4)
(defparameter *respond-to* :anyone "who may trigger the agent: :anyone | :owner.")
(defparameter *system-prompt*
  "You are an AI agent living in a skep workspace — a shared Nostr channel with
humans and other agents. You are replying to a message that mentioned you. Keep
replies conversational and concise (this is a chat channel, not a document): lead
with the answer, add a short supporting detail only if it helps. If a request is
ambiguous or you lack the information, say so plainly rather than guessing.")
(defvar *tool-names* nil "tool set for the engine; NIL = engine default.")

;;; The model seam. Default: run operandi's engine on the context. Bind to a stub
;;; in tests. Loaded lazily so host.lisp needs no operandi at load time.
(defvar *answer-fn*
        (lambda (context)
        (let ((run (or (find-symbol "RUN" "OPERANDI.ENGINE")
                       (error "operandi.engine not loaded — load operandi before starting the host, ~
                               or bind skep.host:*answer-fn*."))))
          (funcall run context :system *system-prompt* :tool-names *tool-names* :verbose nil)))
  "the model seam: (context-string) -> reply-string. Default drives operandi.")

(defun relay () (or *relay* (skep:relay-url)))
(defun agent-pubkey () (n:hex-pubkey *agent-sec*))

;;; ------------------------------- watch --------------------------------
(defvar *watermark* 0 "highest created_at we've processed.")
(defvar *seen* (make-hash-table :test 'equal) "processed event ids (dedupe within a second).")
(defvar *running* nil)
(defvar *thread* nil)
(defun running-p () *running*)

(defun triggered-by-ok-p (ev)
  (or (eq *respond-to* :anyone)
      (and (eq *respond-to* :owner) *owner* (equal (skep:sender-of ev) *owner*))))

(defun context-for (ev)
  "Render the triggering message as the agent's prompt. Concise, Buzz-shaped:
   channel + author + text, then the ask."
  (format nil "[skep channel ~a]~%from ~a:~%~a~%~%Reply to this message in the channel."
          (or (skep:h-tag ev) "?")
          (subseq (skep:sender-of ev) 0 (min 12 (length (skep:sender-of ev))))
          (skep:content-of ev)))

(defun handle-event (ev)
  "Run the agent on EV and post a threaded reply. Returns the reply event or NIL."
  (let* ((reply-text (let ((s (funcall *answer-fn* (context-for ev))))
                       (string-trim '(#\Space #\Newline #\Return #\Tab) (or s ""))))
         (reply-text (if (plusp (length reply-text)) reply-text "(no reply produced)"))
         (reply (skep:build-message *agent-sec* (skep:h-tag ev) reply-text
                                    :root (skep:reply-anchor ev)
                                    :reply-to (skep:id-of ev)
                                    :mentions (list (skep:sender-of ev)))))
    (skep:post-message reply :url (relay))
    reply))

(defun poll-once ()
  "Fetch mentions newer than the watermark, answer each (skipping our own posts),
   advance the watermark. Returns the number answered. Best-effort; never signals."
  (handler-case
      (let* ((me (agent-pubkey))
             (filt (let ((h (make-hash-table :test 'equal)))
                     (setf (gethash "kinds" h) (vector 9) (gethash "#p" h) (vector me))
                     (when (plusp *watermark*) (setf (gethash "since" h) *watermark*))
                     h))
             (evs (sort (n:fetch-events (n:json filt) :secs 3 :relays (list (relay)))
                        #'< :key (lambda (e) (truncate (gethash "created_at" e)))))
             (answered 0))
        (dolist (ev evs answered)
          (let ((id (skep:id-of ev)) (created (truncate (gethash "created_at" ev))))
            (when (and (not (gethash id *seen*))
                       (not (equal (skep:sender-of ev) me))   ; never answer ourselves
                       (triggered-by-ok-p ev))
              (setf (gethash id *seen*) t)
              (handler-case (progn (handle-event ev) (incf answered))
                (serious-condition (e)
                  (format *error-output* "~&[skep.host] answer failed: ~A~%" e)))
              (when (> created *watermark*) (setf *watermark* created))))))
    (serious-condition (e)
      (format *error-output* "~&[skep.host] poll error: ~A~%" e) 0)))

(defun run-loop ()
  (setf *running* t)
  (loop while *running* do
    (poll-once)
    (handler-case (sleep *poll-secs*) (serious-condition () nil))))

(defun start ()
  (unless *agent-sec* (error "set skep.host:*agent-sec* first"))
  (unless (and *thread* (sb-thread:thread-alive-p *thread*))
    (setf *thread* (sb-thread:make-thread #'run-loop :name "skep-host")))
  *thread*)
(defun stop ()
  (setf *running* nil)
  (ignore-errors (when (and *thread* (sb-thread:thread-alive-p *thread*))
                   (sb-thread:join-thread *thread* :timeout 6)))
  (setf *thread* nil))
