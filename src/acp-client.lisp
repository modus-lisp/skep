;;;; src/acp-client.lisp
;;;;
;;;; skep's ACP CLIENT — the piece that makes skep an agent-agnostic host, like
;;;; buzz-acp. It spawns an ACP agent (e.g. operandi-acp, goose, claude-code) as a
;;;; subprocess and drives it over JSON-RPC-2.0 / ndjson on stdio: initialize →
;;;; session/new (with the channel's systemPrompt) → session/prompt, accumulating
;;;; agent_message_chunk updates into the reply, and answering the agent's
;;;; session/request_permission requests.
;;;;
;;;; A dedicated READER thread drains the agent's stdout continuously — a turn
;;;; both streams output AND asks for permission mid-turn, so a client that stops
;;;; reading to write would deadlock the pipe (the exact lesson from operandi's
;;;; ACP work). Producers here only ever enqueue behind the write lock.
;;;;
;;;; `make-acp-answer-fn` returns a closure that plugs straight into
;;;; skep.host:*answer-fn*, so the host loop is unchanged — the agent just runs
;;;; out-of-process now.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (unless (find-package :ql)
    (load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (funcall (read-from-string "ql:quickload") '(:com.inuoe.jzon) :silent t))

(defpackage #:skep.acp
  (:use #:cl)
  (:local-nicknames (#:jzon #:com.inuoe.jzon))
  (:export #:make-client #:initialize #:run-turn #:shutdown #:make-acp-answer-fn
           #:*permission-policy* #:client-alive-p))
(in-package #:skep.acp)

(defun ht (&rest kvs)
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kvs by #'cddr do (setf (gethash k h) v)) h))
(defun m@ (m &rest path)
  (dolist (k path m)
    (setf m (cond ((and (integerp k) (vectorp m) (< k (length m))) (aref m k))
                  ((hash-table-p m) (gethash k m))
                  (t nil)))))

;;; Permission policy: how we answer the agent's session/request_permission.
;;; Default auto-allows (Buzz's default is bypassPermissions) — the workspace, not
;;; the pipe, is the trust boundary. Bind to :deny to reject everything.
(defparameter *permission-policy* :allow)

;;; ------------------------------ transport ------------------------------
(defun send-msg (cl obj)
  (let ((s (jzon:stringify obj)))
    (sb-thread:with-mutex ((getf cl :wlock))
      (write-string s (getf cl :in)) (write-char #\Newline (getf cl :in))
      (force-output (getf cl :in)))))

(defun choose-allow (options)
  "Pick an allow-ish optionId from a request_permission options array."
  (when (and (vectorp options) (plusp (length options)))
    (or (loop for o across options
              when (and (stringp (gethash "kind" o))
                        (search "allow" (gethash "kind" o)))
                return (gethash "optionId" o))
        (gethash "optionId" (aref options 0)))))

(defun handle-agent-request (cl msg)
  "The agent asked US something (has method + id). Answer it."
  (let ((id (gethash "id" msg)) (method (gethash "method" msg)) (params (gethash "params" msg)))
    (cond
      ((equal method "session/request_permission")
       (let ((choice (and (eq *permission-policy* :allow) (choose-allow (gethash "options" params)))))
         (send-msg cl (ht "jsonrpc" "2.0" "id" id
                          "result" (if choice
                                       (ht "outcome" (ht "outcome" "selected" "optionId" choice))
                                       (ht "outcome" (ht "outcome" "cancelled")))))))
      ((equal method "fs/read_text_file")
       (send-msg cl (ht "jsonrpc" "2.0" "id" id "error" (ht "code" -32601 "message" "no fs capability"))))
      (t (send-msg cl (ht "jsonrpc" "2.0" "id" id "error" (ht "code" -32601 "message" "method not found")))))))

(defun handle-notification (cl msg)
  "A session/update notification: accumulate assistant text per session."
  (when (equal (gethash "method" msg) "session/update")
    (let* ((params (gethash "params" msg))
           (sid (gethash "sessionId" params))
           (upd (gethash "update" params)))
      (when (and upd (equal (gethash "sessionUpdate" upd) "agent_message_chunk"))
        (let ((text (m@ upd "content" "text")))
          (when (stringp text)
            (sb-thread:with-mutex ((getf cl :block))
              (push text (gethash sid (getf cl :buffers))))))))))

(defun fulfill (cl id msg)
  (let ((box (gethash id (getf cl :pending))))
    (when box
      (remhash id (getf cl :pending))
      (sb-thread:with-mutex ((getf box :lock))
        (setf (getf box :value) msg (getf box :done) t)
        (sb-thread:condition-notify (getf box :cv))))))

(defun dispatch (cl msg)
  (let ((id (gethash "id" msg)) (method (gethash "method" msg)))
    (cond ((and method id) (handle-agent-request cl msg))   ; request from agent
          (method           (handle-notification cl msg))    ; notification
          (id               (fulfill cl id msg)))))          ; response to us

(defun reader-loop (cl)
  (handler-case
      (loop for line = (read-line (getf cl :out) nil nil) while line do
        (let ((msg (ignore-errors (jzon:parse line))))
          (when (hash-table-p msg) (dispatch cl msg))))
    (serious-condition () nil))
  (setf (getf cl :dead) t))

;;; -------------------------------- client -------------------------------
(defun make-client (command &key args env)
  "Spawn an ACP agent subprocess and start draining its stdout. ENV is a list of
   \"VAR=VALUE\" strings merged onto the current environment."
  (let* ((proc (sb-ext:run-program command args
                                   :search t :wait nil
                                   :input :stream :output :stream :error *error-output*
                                   :external-format :utf-8
                                   :environment (append env (sb-ext:posix-environ))))
         (cl (list :proc proc
                   :in  (sb-ext:process-input proc)
                   :out (sb-ext:process-output proc)
                   :wlock (sb-thread:make-mutex :name "skep-acp-write")
                   :block (sb-thread:make-mutex :name "skep-acp-buf")
                   :pending (make-hash-table)
                   :buffers (make-hash-table :test 'equal)
                   :seq 0 :dead nil)))
    (setf (getf cl :reader) (sb-thread:make-thread (lambda () (reader-loop cl))
                                                   :name "skep-acp-reader"))
    cl))

(defun client-alive-p (cl)
  (and cl (not (getf cl :dead)) (sb-ext:process-alive-p (getf cl :proc))))

(defun call-agent (cl method params &key (timeout 300))
  "Send a JSON-RPC request and block until the reader thread fulfills it."
  (let ((id (sb-thread:with-mutex ((getf cl :wlock)) (incf (getf cl :seq))))
        (box (list :done nil :value nil
                   :cv (sb-thread:make-waitqueue) :lock (sb-thread:make-mutex))))
    (setf (gethash id (getf cl :pending)) box)
    (send-msg cl (ht "jsonrpc" "2.0" "id" id "method" method "params" params))
    (sb-thread:with-mutex ((getf box :lock))
      (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
        (loop until (getf box :done)
              do (when (or (getf cl :dead)
                           (>= (get-internal-real-time) deadline))
                   (return))
                 (sb-thread:condition-wait (getf box :cv) (getf box :lock) :timeout 1))))
    (getf box :value)))

(defun initialize (cl)
  (call-agent cl "initialize"
              (ht "protocolVersion" 1
                  "clientCapabilities" (ht "fs" (ht "readTextFile" nil "writeTextFile" nil)))))

(defun run-turn (cl prompt &key system (cwd (namestring (truename "."))))
  "One turn: session/new (+ optional systemPrompt) then session/prompt; return the
   agent's accumulated assistant text."
  (let* ((newp (apply #'ht "cwd" cwd "mcpServers" #()
                      (when system (list "systemPrompt" system))))
         (snew (call-agent cl "session/new" newp))
         (sid (m@ snew "result" "sessionId")))
    (unless sid (return-from run-turn ""))
    (sb-thread:with-mutex ((getf cl :block)) (setf (gethash sid (getf cl :buffers)) nil))
    (call-agent cl "session/prompt"
                (ht "sessionId" sid "prompt" (vector (ht "type" "text" "text" prompt))))
    (sb-thread:with-mutex ((getf cl :block))
      (apply #'concatenate 'string (reverse (gethash sid (getf cl :buffers)))))))

(defun shutdown (cl)
  (ignore-errors (close (getf cl :in)))
  (ignore-errors (sb-ext:process-kill (getf cl :proc) 15))
  (ignore-errors (sb-ext:process-wait (getf cl :proc)))
  (setf (getf cl :dead) t))

;;; ---------------------- integration with the host ----------------------
(defun make-acp-answer-fn (command &key args env system cwd)
  "Spawn+initialize an ACP agent and return (values ANSWER-FN CLIENT). ANSWER-FN
   plugs into skep.host:*answer-fn* — each call runs one ACP turn. CLIENT is
   returned so the caller can shutdown."
  (let ((cl (make-client command :args args :env env)))
    (initialize cl)
    (values (lambda (context) (run-turn cl context :system system
                                        :cwd (or cwd (namestring (truename ".")))))
            cl)))
