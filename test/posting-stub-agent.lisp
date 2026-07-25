;;;; test/posting-stub-agent.lisp
;;;;
;;;; A stub ACP agent that behaves like a real Buzz agent for the buzz-acp interop
;;;; harness: on a prompt it parses the channel UUID + triggering event id from the
;;;; [Context]/[Buzz event] blocks buzz-acp injects, then shells out to
;;;; `buzz messages send --channel <uuid> --content <…> --reply-to <event-id>`
;;;; (BUZZ_PRIVATE_KEY + BUZZ_RELAY_URL are inherited from buzz-acp; the buzz
;;;; binary is $BUZZ_CLI_BIN or `buzz` on PATH). Writes ONLY JSON-RPC to stdout;
;;;; the buzz invocation's output goes to stderr. This stands in for a real agent
;;;; (operandi + a model), which would decide to call buzz on its own.

(require :asdf)
(unless (find-package :ql) (load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
(funcall (read-from-string "ql:quickload") '(:com.inuoe.jzon) :silent t)
(defpackage #:pstub (:use #:cl) (:local-nicknames (#:jzon #:com.inuoe.jzon)))
(in-package #:pstub)

(defun ht (&rest kvs) (let ((h (make-hash-table :test 'equal)))
  (loop for (k v) on kvs by #'cddr do (setf (gethash k h) v)) h))
(defun emit (o) (write-string (jzon:stringify o) *standard-output*)
  (write-char #\Newline *standard-output*) (force-output))
(defun all-text (params)
  "Join every text block of the prompt (buzz-acp sends [Base], [Context], [event])."
  (let ((bl (gethash "prompt" params)) (acc ""))
    (when (vectorp bl)
      (loop for b across bl for tx = (and (hash-table-p b) (gethash "text" b))
            when (stringp tx) do (setf acc (concatenate 'string acc tx (string #\Newline)))))
    acc))
(defun after (hay needle)
  (let ((p (search needle hay)))
    (when p (let* ((s (+ p (length needle)))
                   (e (or (position-if (lambda (c) (member c '(#\Space #\Newline #\Return #\Tab #\)))) hay :start s)
                          (length hay))))
              (subseq hay s e)))))
(defun ws->http (u)
  (cond ((and u (>= (length u) 5) (string= (subseq u 0 5) "ws://"))  (concatenate 'string "http://" (subseq u 5)))
        ((and u (>= (length u) 6) (string= (subseq u 0 6) "wss://")) (concatenate 'string "https://" (subseq u 6)))
        (t u)))
(defun post-reply (ptext)
  (let* ((pk (sb-ext:posix-getenv "BUZZ_PRIVATE_KEY"))
         (http (ws->http (sb-ext:posix-getenv "BUZZ_RELAY_URL")))
         (buzz (or (sb-ext:posix-getenv "BUZZ_CLI_BIN") "buzz"))
         (ch (let ((p (search "(#" ptext))) (and p (after ptext "(#"))))
         (eid (after ptext "Event ID: ")))
    (when (and pk http ch)
      (sb-ext:run-program buzz
        (append (list "--relay" http "--private-key" pk "messages" "send"
                      "--channel" ch "--content" "On it — reply from the buzz-acp-driven agent.")
                (when (and eid (= (length eid) 64)) (list "--reply-to" eid)))
        :search t :wait t :output *error-output* :error *error-output*))))

(loop for line = (read-line *standard-input* nil nil) while line do
  (let ((msg (ignore-errors (jzon:parse line))))
    (when (hash-table-p msg)
      (let ((id (gethash "id" msg)) (method (gethash "method" msg)) (params (gethash "params" msg)))
        (cond
          ((equal method "initialize")
           (emit (ht "jsonrpc" "2.0" "id" id "result"
                     (ht "protocolVersion" 1 "agentCapabilities" (ht "loadSession" t)
                         "agentInfo" (ht "name" "pstub")))))
          ((equal method "session/new")
           (emit (ht "jsonrpc" "2.0" "id" id "result" (ht "sessionId" "pstub-1"))))
          ((equal method "session/prompt")
           (let ((sid (gethash "sessionId" params)))
             (ignore-errors (post-reply (all-text params)))
             (emit (ht "jsonrpc" "2.0" "method" "session/update"
                       "params" (ht "sessionId" sid "update"
                                    (ht "sessionUpdate" "agent_message_chunk"
                                        "content" (ht "type" "text" "text" "posted reply")))))
             (emit (ht "jsonrpc" "2.0" "id" id "result" (ht "stopReason" "end_turn")))))
          (id (emit (ht "jsonrpc" "2.0" "id" id "result" (ht)))))))))
