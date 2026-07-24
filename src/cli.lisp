;;;; src/cli.lisp
;;;;
;;;; A `buzz`-compatible send CLI. This is the shim an ACP agent shells out to in
;;;; order to reach the channel — Buzz's contract is that the agent replies with:
;;;;   buzz messages send --channel <uuid> --content <str> [--reply-to <id>] [--mention <pk>]…
;;;; reading BUZZ_RELAY_URL / BUZZ_PRIVATE_KEY / BUZZ_AUTH_TAG from the env. With
;;;; this present in the agent's cwd, an unmodified Buzz agent (or operandi as the
;;;; ACP agent) can post into skep exactly as it would into a real Buzz relay.
;;;;
;;;; It signs a NIP-29 kind-9 (skep:build-message) and publishes NIP-42-aware
;;;; (skep:authed-publish), so it works against both skep and a real Buzz relay.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((here (or *load-truename* *compile-file-truename*)))
    (unless (find-package :skep) (load (merge-pathnames "skep.lisp" here)))))

(defpackage #:skep.cli
  (:use #:cl)
  (:local-nicknames (#:skep #:skep) (#:n #:skep.nostr) (#:ic #:ironclad)
                    (#:jzon #:com.inuoe.jzon) (#:b32 #:skep.crypto.bech32))
  (:export #:parse-secret #:send-message #:parse-args #:main))
(in-package #:skep.cli)

;;; ---------------------------- key parsing -----------------------------
(defparameter +bech32-charset+ "qpzry9x8gf2tvdw0s3jn54khce6mua7l")
(defun bech32->hex (s expect-hrp)
  (let* ((s (string-downcase s)) (sep (position #\1 s :from-end t)))
    (unless (and sep (string= (subseq s 0 sep) expect-hrp)) (error "bad bech32 hrp"))
    (let* ((vals (loop for c across (subseq s (1+ sep)) collect (position c +bech32-charset+)))
           (bytes (b32:convert-bits (subseq vals 0 (- (length vals) 6)) 5 8 :pad nil)))
      (ic:byte-array-to-hex-string
       (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes)))))
(defun parse-secret (s)
  "A secp256k1 secret (integer) from a 64-hex string or an nsec1… (NIP-19)."
  (cond ((and (= (length s) 64) (every (lambda (c) (digit-char-p c 16)) s))
         (parse-integer s :radix 16))
        ((and (> (length s) 4) (string-equal (subseq s 0 4) "nsec"))
         (parse-integer (bech32->hex s "nsec") :radix 16))
        (t (error "private key must be 64-hex or nsec1…"))))

(defun auth-tag-from-env ()
  "Parse BUZZ_AUTH_TAG (a NIP-OA [\"auth\",owner,conditions,sig] JSON array) into a
   tag vector, or NIL if unset/unparseable."
  (let ((raw (sb-ext:posix-getenv "BUZZ_AUTH_TAG")))
    (when (and raw (plusp (length raw)))
      (ignore-errors
        (let ((a (jzon:parse raw)))
          (when (and (vectorp a) (plusp (length a))) a))))))

;;; ----------------------------- send -----------------------------------
(defun send-message (&key channel text reply-to mention private-key relay auth-tag)
  "Sign + publish a kind-9 message. MENTION may be a pubkey or a list. Returns the
   signed event."
  (let* ((sec (parse-secret private-key))
         (url (or relay (sb-ext:posix-getenv "BUZZ_RELAY_URL") "ws://localhost:3000"))
         (mentions (cond ((null mention) nil) ((listp mention) mention) (t (list mention))))
         (extra (and auth-tag (list auth-tag)))
         (ev (skep:build-message sec channel text
                                 :reply-to reply-to :mentions mentions :extra-tags extra))
         (ok (or (skep:authed-publish sec ev url) (plusp (skep:post-message ev :url url)))))
    (values ev ok)))

;;; ---------------------------- arg parsing -----------------------------
(defun parse-args (argv)
  "Return (values positionals flags-hash). Repeated --flag collects a list."
  (let ((pos '()) (flags (make-hash-table :test 'equal)) (i 0) (v (coerce argv 'vector)))
    (loop while (< i (length v)) do
      (let ((a (aref v i)))
        (if (and (> (length a) 2) (string= (subseq a 0 2) "--"))
            (let ((key (subseq a 2)) (val (and (< (1+ i) (length v)) (aref v (1+ i)))))
              (push val (gethash key flags)) (incf i 2))
            (progn (push a pos) (incf i)))))
    (maphash (lambda (k vs) (setf (gethash k flags) (nreverse vs))) flags)
    (values (nreverse pos) flags)))

(defun main (argv)
  "Entry point: `messages send …`. Returns a Unix exit code."
  (multiple-value-bind (pos flags) (parse-args argv)
    (flet ((flag1 (k) (first (gethash k flags))))
      (cond
        ((and (equal (first pos) "messages") (equal (second pos) "send"))
         (let ((channel (flag1 "channel")) (text (or (flag1 "content") (flag1 "text")))
               (reply (flag1 "reply-to")) (mentions (gethash "mention" flags))
               (relay (or (flag1 "relay") (sb-ext:posix-getenv "BUZZ_RELAY_URL")))
               (pk (or (flag1 "private-key") (sb-ext:posix-getenv "BUZZ_PRIVATE_KEY"))))
           (unless (and channel text pk)
             (format *error-output* "usage: messages send --channel <id> --content <str> ~
                                     [--reply-to <id>] [--mention <pk>]…  ~
                                     (needs BUZZ_PRIVATE_KEY)~%")
             (return-from main 2))
           (multiple-value-bind (ev ok)
               (send-message :channel channel :text text :reply-to reply
                             :mention mentions :private-key pk :relay relay
                             :auth-tag (auth-tag-from-env))
             (let ((h (make-hash-table :test 'equal)))
               (setf (gethash "id" h) (skep:id-of ev) (gethash "channel" h) channel
                     (gethash "ok" h) (and ok t))
               (format t "~a~%" (n:json h)))
             (if ok 0 (progn (format *error-output* "publish failed: relay ~a unreachable?~%"
                                     (or relay (sb-ext:posix-getenv "BUZZ_RELAY_URL") "ws://localhost:3000"))
                             3)))))
        (t (format *error-output* "skep buzz-CLI: only `messages send` is implemented~%") 1)))))
