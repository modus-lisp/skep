;;;; test/stub-acp-agent.lisp
;;;;
;;;; A minimal ACP AGENT (server side) for testing skep's ACP client. Speaks
;;;; JSON-RPC-2.0 / ndjson on stdio: initialize, session/new, session/prompt.
;;;; On a prompt it streams two agent_message_chunk updates then answers
;;;; end_turn. If the prompt text contains "please run", it first sends a
;;;; session/request_permission request and waits for the client's response
;;;; BEFORE finishing — exercising the bidirectional / mid-turn-permission path.
;;;; Writes ONLY JSON-RPC to stdout.  Run:  sbcl --script stub-acp-agent.lisp

(require :asdf)
(unless (find-package :ql) (load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
(funcall (read-from-string "ql:quickload") '(:com.inuoe.jzon) :silent t)
(defpackage #:stub (:use #:cl) (:local-nicknames (#:jzon #:com.inuoe.jzon)))
(in-package #:stub)

(defun ht (&rest kvs)
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kvs by #'cddr do (setf (gethash k h) v)) h))
(defun m@ (m &rest path)
  (dolist (k path m)
    (setf m (cond ((and (integerp k) (vectorp m) (< k (length m))) (aref m k))
                  ((hash-table-p m) (gethash k m)) (t nil)))))
(defun emit (obj)
  (write-string (jzon:stringify obj) *standard-output*)
  (write-char #\Newline *standard-output*)
  (force-output *standard-output*))
(defun respond (id result) (emit (ht "jsonrpc" "2.0" "id" id "result" result)))
(defun notify (method params) (emit (ht "jsonrpc" "2.0" "method" method "params" params)))
(defun chunk (sid text)
  (notify "session/update"
          (ht "sessionId" sid
              "update" (ht "sessionUpdate" "agent_message_chunk"
                           "content" (ht "type" "text" "text" text)))))

(loop for line = (read-line *standard-input* nil nil) while line do
  (let ((msg (ignore-errors (jzon:parse line))))
    (when (hash-table-p msg)
      (let ((id (gethash "id" msg)) (method (gethash "method" msg))
            (params (gethash "params" msg)))
        (cond
          ((equal method "initialize")
           (respond id (ht "protocolVersion" 1
                           "agentCapabilities" (ht "loadSession" t)
                           "agentInfo" (ht "name" "stub"))))
          ((equal method "session/new")
           (respond id (ht "sessionId" "stub-session-1")))
          ((equal method "session/prompt")
           (let* ((sid (gethash "sessionId" params))
                  (ptext (or (m@ params "prompt" 0 "text") "")))
             (when (search "please run" ptext)
               ;; ask for permission and BLOCK on the client's reply before finishing
               (emit (ht "jsonrpc" "2.0" "id" 9001 "method" "session/request_permission"
                         "params" (ht "sessionId" sid
                                      "toolCall" (ht "toolCallId" "t1" "title" "run build" "kind" "execute")
                                      "options" (vector (ht "optionId" "allow" "name" "Allow" "kind" "allow_once")
                                                        (ht "optionId" "deny"  "name" "Deny"  "kind" "reject_once")))))
               (read-line *standard-input* nil nil))   ; consume the permission response
             (chunk sid "ACP-STUB: ")
             (chunk sid (format nil "heard ~a" ptext))
             (respond id (ht "stopReason" "end_turn"))))
          (id (respond id (ht))))))))
