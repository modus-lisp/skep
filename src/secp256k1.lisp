;;; src/secp256k1.lisp
;;;
;;; secp256k1 curve operations.
;;;
;;; Constants, modular arithmetic, point operations, and scalar multiplication
;;; over the secp256k1 field — the math skep's BIP-340 Schnorr signatures build
;;; on (see schnorr.lisp). Depends only on ironclad.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (ql:quickload '(:ironclad) :silent t))

(defpackage #:skep.crypto.secp256k1
  (:use #:cl)
  (:local-nicknames (#:ic #:ironclad))
  (:export ;; constants and basic conversions
           #:*secp256k1-p* #:*secp256k1-n*
           #:secp-init #:secp-generator
           #:bytes-to-int #:int-to-bytes32
           ;; field & curve ops (re-exported for callers building on top)
           #:secp-mod #:secp-add #:secp-sub #:secp-mul #:secp-sq #:secp-neg
           #:secp-inv #:secp-double #:secp-add-points #:secp-mul-point
           #:secp-on-curve-p #:secp-pubkey))

(in-package #:skep.crypto.secp256k1)

;;; -----------------------------------------------------------------------
;;; Curve math
;;; -----------------------------------------------------------------------

(defparameter *secp256k1-p* nil)
(defparameter *secp256k1-n* nil)
(defparameter *secp256k1-gx* nil)
(defparameter *secp256k1-gy* nil)

(defun bytes-to-int (bytes)
  "Convert byte array to integer (big-endian)."
  (let ((result 0))
    (dotimes (i (length bytes))
      (setf result (+ (ash result 8) (aref bytes i))))
    result))

(defun int-to-bytes32 (n)
  "Convert integer to 32-byte array (big-endian)."
  (let ((result (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element 0)))
    (dotimes (i 32)
      (setf (aref result (- 31 i)) (ldb (byte 8 (* i 8)) n)))
    result))

(defun secp-init ()
  "Initialize secp256k1 constants from canonical big-endian byte arrays."
  (unless *secp256k1-p*
    (setf *secp256k1-p*
          (bytes-to-int #(#xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFE #xFF #xFF #xFC #x2F)))
    (setf *secp256k1-n*
          (bytes-to-int #(#xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFE
                          #xBA #xAE #xDC #xE6 #xAF #x48 #xA0 #x3B
                          #xBF #xD2 #x5E #x8C #xD0 #x36 #x41 #x41)))
    (setf *secp256k1-gx*
          (bytes-to-int #(#x79 #xBE #x66 #x7E #xF9 #xDC #xBB #xAC
                          #x55 #xA0 #x62 #x95 #xCE #x87 #x0B #x07
                          #x02 #x9B #xFC #xDB #x2D #xCE #x28 #xD9
                          #x59 #xF2 #x81 #x5B #x16 #xF8 #x17 #x98)))
    (setf *secp256k1-gy*
          (bytes-to-int #(#x48 #x3A #xDA #x77 #x26 #xA3 #xC4 #x65
                          #x5D #xA4 #xFB #xFC #x0E #x11 #x08 #xA8
                          #xFD #x17 #xB4 #x48 #xA6 #x85 #x54 #x19
                          #x9C #x47 #xD0 #x8F #xFB #x10 #xD4 #xB8))))
  t)

(defparameter *secp256k1-infinity* (cons :infinity nil))

(defun secp-mod (x) (mod x *secp256k1-p*))
(defun secp-add (a b) (secp-mod (+ a b)))
(defun secp-sub (a b) (secp-mod (- a b)))
(defun secp-mul (a b) (secp-mod (* a b)))
(defun secp-sq  (a)   (secp-mod (* a a)))
(defun secp-neg (a)   (secp-mod (- *secp256k1-p* a)))

(defun secp-inv (a)
  "Modular inverse using extended Euclidean algorithm."
  (let ((t0 0) (t1 1)
        (r0 *secp256k1-p*) (r1 (mod a *secp256k1-p*)))
    (loop while (not (zerop r1)) do
      (let* ((q (floor r0 r1))
             (new-r1 (- r0 (* q r1)))
             (new-t1 (- t0 (* q t1))))
        (setf r0 r1
              r1 new-r1
              t0 t1
              t1 new-t1)))
    (if (< t0 0) (+ t0 *secp256k1-p*) t0)))

(defun secp-inf-p (p) (eq (car p) :infinity))
(defun secp-x (p) (car p))
(defun secp-y (p) (cdr p))

(defun secp-double (p)
  "Double a point."
  (when (secp-inf-p p) (return-from secp-double p))
  (let ((x (secp-x p)) (y (secp-y p)))
    (when (zerop y) (return-from secp-double *secp256k1-infinity*))
    (let* ((lam (secp-mul (secp-mul 3 (secp-sq x))
                          (secp-inv (secp-mul 2 y))))
           (x3 (secp-sub (secp-sq lam) (secp-mul 2 x)))
           (y3 (secp-sub (secp-mul lam (secp-sub x x3)) y)))
      (cons x3 y3))))

(defun secp-add-points (p1 p2)
  "Add two points."
  (cond
    ((secp-inf-p p1) p2)
    ((secp-inf-p p2) p1)
    (t
     (let ((x1 (secp-x p1)) (y1 (secp-y p1))
           (x2 (secp-x p2)) (y2 (secp-y p2)))
       (cond
         ((and (= x1 x2) (= y1 (secp-neg y2))) *secp256k1-infinity*)
         ((and (= x1 x2) (= y1 y2)) (secp-double p1))
         (t
          (let* ((lam (secp-mul (secp-sub y2 y1)
                                (secp-inv (secp-sub x2 x1))))
                 (x3 (secp-sub (secp-sub (secp-sq lam) x1) x2))
                 (y3 (secp-sub (secp-mul lam (secp-sub x1 x3)) y1)))
            (cons x3 y3))))))))

(defun secp-mul-point (k p)
  "Scalar multiplication k*P via double-and-add."
  (secp-init)
  (let ((result *secp256k1-infinity*)
        (temp p)
        (n (mod k *secp256k1-n*)))
    (loop while (> n 0) do
      (when (oddp n)
        (setf result (secp-add-points result temp)))
      (setf temp (secp-double temp))
      (setf n (ash n -1)))
    result))

(defun secp-generator ()
  "Return generator point G."
  (secp-init)
  (cons *secp256k1-gx* *secp256k1-gy*))

(defun secp-pubkey (privkey)
  "Compute public key point from private-key integer."
  (secp-mul-point privkey (secp-generator)))

(defun secp-on-curve-p (p)
  "Check if point is on curve y² = x³ + 7."
  (secp-init)
  (if (secp-inf-p p) t
      (let ((x (secp-x p)) (y (secp-y p)))
        (= (secp-sq y) (secp-mod (+ (secp-mul x (secp-sq x)) 7))))))

