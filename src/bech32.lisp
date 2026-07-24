;;; src/bech32.lisp
;;;
;;; Bech32 encoding (BIP-173) and bech32m encoding (BIP-350).
;;;
;;; Bech32 strings have the form:
;;;
;;;   <hrp> "1" <data-part> <6-char-checksum>
;;;
;;; where:
;;;
;;;   hrp           e.g. "bc" (mainnet) / "tb" (testnet)
;;;   data-part     payload bytes regrouped from 8-bit to 5-bit
;;;                 chunks, then mapped through the bech32 charset
;;;   checksum      6 chars derived from a BCH code over (hrp + data),
;;;                 computed with one of two polynomial constants:
;;;                   1          → bech32  (witness version 0)
;;;                   0x2bc830a3 → bech32m (witness version >= 1)
;;;
;;; For BTC:
;;;
;;;   P2WPKH (witver 0, 20-byte program)  → bech32
;;;   P2WSH  (witver 0, 32-byte program)  → bech32
;;;   P2TR   (witver 1, 32-byte program)  → bech32m
;;;
;;; Cross-checked against python's `bitcoin.bech32.encode` for the
;;; standard test vectors and for our priv-derived P2WPKH addresses.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf))

(defpackage #:skep.crypto.bech32
  (:use #:cl)
  (:export #:bech32-encode
           #:bech32m-encode
           #:segwit-address-encode
           #:segwit-address-decode
           #:convert-bits
           #:bech32-error))

(in-package #:skep.crypto.bech32)

(defparameter *charset* "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  "Bech32 5-bit-value-to-character mapping (32 chars, idx 0..31).")

(defparameter *gen* '(#x3b6a57b2 #x26508e6d #x1ea119fa #x3d4233dd #x2a1462b3)
  "Generator constants for the bech32 BCH polynomial.")

(defun polymod (values)
  "BCH polymod over the given 5-bit values. Returns a 30-bit integer."
  (let ((chk 1))
    (dolist (v values)
      (let ((b (ldb (byte 5 25) chk)))
        (setf chk (logxor (ash (logand chk #x1ffffff) 5) v))
        (loop for i from 0 below 5
              when (logbitp i b)
                do (setf chk (logxor chk (nth i *gen*))))))
    chk))

(defun hrp-expand (hrp)
  "Expand HRP for checksum computation: high-bits, 0, low-bits."
  (let ((high (loop for c across hrp collect (ash (char-code c) -5)))
        (low  (loop for c across hrp collect (logand (char-code c) 31))))
    (append high (list 0) low)))

(defun checksum (hrp data const)
  "Compute the 6-element bech32 checksum for HRP + DATA under CONST.
   CONST is 1 for bech32, #x2bc830a3 for bech32m."
  (let* ((values (append (hrp-expand hrp) data (list 0 0 0 0 0 0)))
         (mod (logxor (polymod values) const))
         (out '()))
    (dotimes (i 6)
      (push (logand (ash mod (- (* 5 (- 5 i)))) 31) out))
    (nreverse out)))

(defun encode (hrp data const)
  "Encode HRP + DATA (5-bit values) into the final bech32(m) string."
  (let* ((cks (checksum hrp data const))
         (full (append data cks))
         (chars (loop for v in full collect (char *charset* v))))
    (concatenate 'string hrp "1" (coerce chars 'string))))

(defun bech32-encode (hrp data)
  "BIP-173 bech32 encoding."
  (encode hrp data 1))

(defun bech32m-encode (hrp data)
  "BIP-350 bech32m encoding."
  (encode hrp data #x2bc830a3))

(defun convert-bits (data from-bits to-bits &key (pad t))
  "Regroup bytes (or other small ints) from FROM-BITS-wide chunks
   to TO-BITS-wide chunks. Used to convert 8-bit byte data into the
   5-bit alphabet bech32 uses (with pad=T)."
  (let ((acc 0)
        (bits 0)
        (max-v (1- (ash 1 to-bits)))
        (max-acc (1- (ash 1 (+ from-bits to-bits -1))))
        (result '()))
    (dolist (b data)
      (when (or (< b 0) (>= b (ash 1 from-bits)))
        (error "convert-bits: value out of range: ~A" b))
      (setf acc (logand (logior (ash acc from-bits) b) max-acc))
      (incf bits from-bits)
      (loop while (>= bits to-bits) do
        (decf bits to-bits)
        (push (logand (ash acc (- bits)) max-v) result)))
    (cond
      (pad
       (when (plusp bits)
         (push (logand (ash acc (- to-bits bits)) max-v) result)))
      ((or (>= bits from-bits)
           (plusp (logand (ash acc (- to-bits bits)) max-v)))
       (error "convert-bits: residual bits would be lost")))
    (nreverse result)))

(defun segwit-address-encode (hrp witver witprog)
  "Encode a SegWit address. HRP is 'bc' (mainnet) or 'tb' (testnet).
   WITVER is the witness version (0 for P2WPKH/P2WSH, 1 for P2TR).
   WITPROG is the program bytes (a list or vector of (unsigned-byte 8)).
   Uses bech32 for v0, bech32m for v1+."
  (let* ((bytes (etypecase witprog
                  (list witprog)
                  (vector (coerce witprog 'list))))
         (data (cons witver (convert-bits bytes 8 5))))
    (if (zerop witver)
        (bech32-encode hrp data)
        (bech32m-encode hrp data))))

(define-condition bech32-error (error)
  ((message :initarg :message :reader bech32-error-message))
  (:report (lambda (c s) (princ (bech32-error-message c) s))))

(defun bech32-charset-pos (c)
  (or (position c *charset*)
      (error 'bech32-error :message
             (format nil "char ~S not in bech32 charset" c))))

(defun segwit-address-decode (addr)
  "Decode a SegWit address. Returns (values hrp witver witprog) where
   WITPROG is a byte vector. Verifies the bech32(m) checksum (with
   the right constant for the witness version) and the BIP-173/350
   structural rules.

   Signals BECH32-ERROR on any malformed input — use this as the
   verification gate before sending money to an address."
  (let* ((addr (string-downcase addr))
         (sep (position #\1 addr :from-end t)))
    (unless (and sep (>= sep 1) (<= (- (length addr) sep 1) 90))
      (error 'bech32-error :message "no separator '1' or wrong length"))
    (let* ((hrp (subseq addr 0 sep))
           (data-part (subseq addr (1+ sep)))
           (data (loop for c across data-part
                       collect (bech32-charset-pos c))))
      (when (< (length data) 6)
        (error 'bech32-error :message "data too short"))
      (let* ((witver (first data))
             (payload (subseq data 1 (- (length data) 6)))
             (full (append (hrp-expand hrp) data))
             (mod (polymod full)))
        (cond ((zerop witver)
               (unless (= mod 1)
                 (error 'bech32-error :message "bech32 checksum mismatch")))
              (t
               (unless (= mod #x2bc830a3)
                 (error 'bech32-error :message "bech32m checksum mismatch"))))
        (let ((witprog (handler-case (convert-bits payload 5 8 :pad nil)
                         (error (e)
                           (error 'bech32-error :message (princ-to-string e))))))
          (cond
            ((zerop witver)
             (unless (or (= (length witprog) 20) (= (length witprog) 32))
               (error 'bech32-error :message "v0 program must be 20 or 32 bytes")))
            (t
             (unless (and (>= (length witprog) 2) (<= (length witprog) 40))
               (error 'bech32-error :message "v1+ program out of bounds"))))
          (values hrp witver
                  (make-array (length witprog)
                              :element-type '(unsigned-byte 8)
                              :initial-contents witprog)))))))
