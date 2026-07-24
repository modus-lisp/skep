;;;; src/nostr.lisp — skep's minimal, self-contained Nostr client.
;;;;
;;;; Event id/serialization + Schnorr (BIP-340) signing/verification over the
;;;; vendored crypto (skep.crypto.{secp256k1,schnorr,bech32}), plus a tiny
;;;; websocket publish/fetch. This is the whole Nostr layer skep needs; the relay,
;;;; channel model, ACP host and CLI build on it.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (unless (find-package :ql)
    (load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (funcall (read-from-string "ql:quickload")
           '(:ironclad :com.inuoe.jzon :cl-base64 :bordeaux-threads :websocket-driver-client)
           :silent t)
  (let ((here (or *load-truename* *compile-file-truename*)))
    (load (merge-pathnames "secp256k1.lisp" here))
    (load (merge-pathnames "schnorr.lisp" here))
    (load (merge-pathnames "bech32.lisp" here))))

(defpackage #:skep.nostr
  (:use #:cl)
  (:local-nicknames (#:jzon #:com.inuoe.jzon) (#:ic #:ironclad)
                    (#:secp #:skep.crypto.secp256k1)
                    (#:schnorr #:skep.crypto.schnorr)
                    (#:b32 #:skep.crypto.bech32)
                    (#:wsd #:websocket-driver))
  (:export #:*relays* #:unix-now #:urandom #:json #:utf8
           #:event-id-hex #:sign-event #:verify-event #:hex-pubkey #:gen-key
           #:publish #:fetch-events #:npub->hex #:hex->npub))
(in-package #:skep.nostr)

(defparameter *relays* '() "default relays; skep uses its own local relay, so usually passed explicitly.")
(defparameter *charset* "qpzry9x8gf2tvdw0s3jn54khce6mua7l")

(defun utf8 (s) (sb-ext:string-to-octets s :external-format :utf-8))
(defun unix-now () (- (get-universal-time) (encode-universal-time 0 0 0 1 1 1970 0)))
(defun json (obj) (with-output-to-string (s) (jzon:stringify obj :stream s)))
(defun urandom (n)
  (with-open-file (s #P"/dev/urandom" :element-type '(unsigned-byte 8))
    (let ((v (make-array n :element-type '(unsigned-byte 8)))) (read-sequence v s) v)))

(defun hex-pubkey (sec-int)
  (ic:byte-array-to-hex-string (schnorr:pubkey-xonly sec-int)))
(defun gen-key ()
  "Mint a fresh keypair. (values sec-int pubkey-hex npub)."
  (let* ((sec (secp:bytes-to-int (urandom 32))) (hex (hex-pubkey sec)))
    (values sec hex (hex->npub hex))))

;;; --------------------------- events (NIP-01) --------------------------
(defun event-id-hex (pub created kind tags content)
  "Canonical NIP-01 event id: sha256 of [0,pubkey,created_at,kind,tags,content]."
  (let ((ser (with-output-to-string (s)
               (jzon:stringify (vector 0 pub created kind tags content) :stream s))))
    (ic:byte-array-to-hex-string (ic:digest-sequence :sha256 (utf8 ser)))))

(defun sign-event (sec-int pub created kind tags content)
  "Return a fully-signed event hash-table."
  (let* ((id (event-id-hex pub created kind tags content))
         (sig (ic:byte-array-to-hex-string
               (schnorr:schnorr-sign sec-int (ic:hex-string-to-byte-array id))))
         (h (make-hash-table :test 'equal)))
    (setf (gethash "id" h) id (gethash "pubkey" h) pub (gethash "created_at" h) created
          (gethash "kind" h) kind (gethash "tags" h) tags (gethash "content" h) content
          (gethash "sig" h) sig)
    h))

(defun verify-event (ev)
  "T iff EV (hash-table) has a canonical id and a valid Schnorr signature."
  (ignore-errors
    (let* ((pub (gethash "pubkey" ev)) (id (gethash "id" ev)) (sig (gethash "sig" ev))
           (calc (event-id-hex pub (truncate (gethash "created_at" ev))
                               (truncate (gethash "kind" ev))
                               (gethash "tags" ev) (gethash "content" ev))))
      (and (string-equal id calc)
           (schnorr:schnorr-verify (ic:hex-string-to-byte-array pub)
                                   (ic:hex-string-to-byte-array id)
                                   (ic:hex-string-to-byte-array sig))))))

;;; ----------------------------- bech32 keys ----------------------------
(defun npub->hex (npub)
  (let* ((s (string-downcase npub)) (sep (position #\1 s :from-end t))
         (vals (loop for c across (subseq s (1+ sep)) collect (position c *charset*))))
    (unless (string= (subseq s 0 sep) "npub") (error "not an npub"))
    (let ((bytes (b32:convert-bits (subseq vals 0 (- (length vals) 6)) 5 8 :pad nil)))
      (ic:byte-array-to-hex-string
       (make-array (length bytes) :element-type '(unsigned-byte 8) :initial-contents bytes)))))
(defun bech32-poly (values)
  (let ((gen #(#x3b6a57b2 #x26508e6d #x1ea119fa #x3d4233dd #x2a1462b3)) (chk 1))
    (dolist (v values chk)
      (let ((top (ash chk -25)))
        (setf chk (logand (logxor (ash (logand chk #x1ffffff) 5) v) #x3fffffff))
        (dotimes (i 5) (when (logbitp i top) (setf chk (logxor chk (aref gen i)))))))))
(defun hex->npub (hex)
  "Encode a 32-byte hex pubkey as a bech32 npub."
  (let* ((bytes (coerce (loop for i from 0 below (length hex) by 2
                              collect (parse-integer hex :start i :end (+ i 2) :radix 16))
                        'list))
         (data (b32:convert-bits bytes 8 5 :pad t))
         (hrp-exp (append '(3 3 3 3) '(0) (mapcar (lambda (c) (logand (char-code c) 31)) (coerce "npub" 'list))))
         (poly (logxor (bech32-poly (append hrp-exp data '(0 0 0 0 0 0))) 1))
         (cs (loop for i from 0 below 6 collect (logand (ash poly (- (* 5 (- 5 i)))) 31))))
    (format nil "npub1~{~a~}~{~a~}"
            (mapcar (lambda (v) (char *charset* v)) data)
            (mapcar (lambda (v) (char *charset* v)) cs))))

;;; ----------------------------- relay i/o ------------------------------
(defun publish (event-json &optional (relays *relays*))
  "Publish ['EVENT', event] to RELAYS; return ACK count. (skep's own relay/CLI use
   the NIP-42-aware publish-event in src/skep.lisp; this is the generic client.)"
  (let ((oks 0))
    (dolist (relay relays oks)
      (handler-case
          (sb-ext:with-timeout 8
            (let ((c (wsd:make-client relay)) (done nil))
              (wsd:on :message c (lambda (m) (when (search "true" m) (incf oks)) (setf done t)))
              (wsd:start-connection c)
              (loop repeat 20 until (eq (wsd:ready-state c) :open) do (sleep 0.1))
              (wsd:send-text c (format nil "[\"EVENT\",~a]" event-json))
              (loop repeat 30 until done do (sleep 0.1))
              (ignore-errors (wsd:close-connection c))))
        (serious-condition () nil)))))

(defun fetch-events (filters &key (secs 3) (relays *relays*))
  "REQ FILTERS (JSON) against RELAYS for SECS; deduped list of event hash-tables."
  (let ((seen (make-hash-table :test 'equal)) (out '()))
    (dolist (relay relays out)
      (handler-case
          (sb-ext:with-timeout (+ secs 6)
            (let ((c (wsd:make-client relay)))
              (wsd:on :message c
                      (lambda (m)
                        (handler-case
                            (let ((a (jzon:parse m)))
                              (when (and (vectorp a) (>= (length a) 3) (equal (aref a 0) "EVENT"))
                                (let* ((ev (aref a 2)) (id (gethash "id" ev)))
                                  (unless (gethash id seen) (setf (gethash id seen) t) (push ev out)))))
                          (error () nil))))
              (wsd:start-connection c)
              (loop repeat 40 until (eq (wsd:ready-state c) :open) do (sleep 0.1))
              (wsd:send-text c (format nil "[\"REQ\",\"q\",~a]" filters))
              (sleep secs)
              (ignore-errors (wsd:close-connection c))))
        (serious-condition () nil)))))
