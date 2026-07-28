;;;; skep — an interoperable, from-scratch reimplementation of Block's Buzz
;;;; (github.com/block/buzz): a Nostr-relay-native workspace where humans and AI
;;;; agents share channels. "skep" = a woven straw beehive (the hive → Buzz; the
;;;; weave → our weft/loom/shuttle family; a real object → cairn/conch).
;;;;
;;;; This file is the RELAY + the NIP-29 message model. Buzz's wire contract
;;;; (verified against block/buzz source):
;;;;   - channels are NIP-29 groups; a chat message is kind 9 with an ["h",<chan>]
;;;;     tag; content is PLAINTEXT (membership, not encryption, is the gate).
;;;;   - an agent is addressed by a ["p",<agent-pubkey-hex>] tag (the routing key).
;;;;   - threading is NIP-10 e-tags (root/reply).
;;;;   - relay auth is NIP-42 (kind 22242); identity IS the keypair (no tokens).
;;;;
;;;; This file: the NIP-01 relay (a GENERAL event store that accepts kind 9 and
;;;; fans out on #h/#p), NIP-42 auth + private-channel membership gating, and the
;;;; NIP-29 message/channel builders.
;;;;
;;;; Built on skep's own Nostr client (src/nostr.lisp) and vendored crypto
;;;; (src/{secp256k1,schnorr,bech32}.lisp) — no external crypto dependency.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :asdf)
  (unless (find-package :ql)
    (load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (funcall (read-from-string "ql:quickload")
           '(:usocket :fast-websocket :cl-ppcre :ironclad :cl-base64
                  :com.inuoe.jzon :bordeaux-threads :websocket-driver-client)
                 :silent t)
  (let ((here (or *load-truename* *compile-file-truename*)))
    (load (merge-pathnames "nostr.lisp" here))))

(defpackage #:skep
  (:use #:cl)
  (:local-nicknames (#:jzon #:com.inuoe.jzon) (#:ic #:ironclad)
                    (#:ppcre #:cl-ppcre) (#:n #:skep.nostr)
                    (#:wsd #:websocket-driver))
  (:export #:start-relay #:stop-relay #:*relay-port* #:relay-url #:reset-store!
           #:*events* #:all-stored-events #:event-count
           #:new-channel #:add-member #:channel-members #:*channels*
           #:build-message #:post-message #:mentions-of #:h-tag #:tag-val
           #:kind-9-p #:content-of #:sender-of #:id-of #:reply-anchor
           #:signed-auth-event #:nip42-fetch #:authed-publish
           #:relay-pubkey #:process-admin-event #:emit-group-discovery #:ensure-relay-key))
(in-package #:skep)

;;; ------------------------------- config -------------------------------
(defparameter *relay-port* 8095 "skep relay ws port (a free high port).")
(defparameter *nip11*
  (n:json (let ((h (make-hash-table :test 'equal)))
            (setf (gethash "name" h) "skep"
                  (gethash "description" h) "skep — a Buzz-interoperable Nostr agent workspace"
                  (gethash "software" h) "https://github.com/modus-lisp/skep"
                  (gethash "supported_nips" h) (vector 1 9 10 11 29 42)
                  (gethash "version" h) "0.1")
            h)))
(defun relay-url (&optional (port *relay-port*)) (format nil "ws://127.0.0.1:~d" port))

;;; ------------------------------- store --------------------------------
;;; A general event store: id -> event. Replaceable/param-replaceable kinds
;;; (0, 3, 1xxxx, 3xxxx) additionally track a coord -> id map so a newer version
;;; supersedes the old. Everything else (kind 9 chat, kind 7 reactions, …) is
;;; append-by-id. Held in hash-tables (reload-safe — no defstruct live state).
(defvar *events* (make-hash-table :test 'equal) "id -> event hash-table.")
(defvar *replaceables* (make-hash-table :test 'equal) "\"pub:kind:d\" -> id.")
(defvar *channels* (make-hash-table :test 'equal) "chan-id -> plist(:name :members list).")
(defvar *store-lock* (sb-thread:make-mutex :name "skep-store"))

(defun reset-store! ()
  (sb-thread:with-mutex (*store-lock*)
    (clrhash *events*) (clrhash *replaceables*) (clrhash *channels*)))
(defun all-stored-events ()
  ;; snapshot under the store lock — relay-ingest mutates *events* concurrently,
  ;; and maphash during a setf on the same table is undefined.
  (sb-thread:with-mutex (*store-lock*)
    (let (out) (maphash (lambda (k v) (declare (ignore k)) (push v out)) *events*) out)))
(defun event-count () (hash-table-count *events*))

(defun tag-val (ev letter)
  "First value of the first tag whose name = LETTER, or NIL."
  (loop for tg across (gethash "tags" ev)
        when (and (vectorp tg) (>= (length tg) 2) (equal (aref tg 0) letter))
          return (aref tg 1)))
(defun tag-vals (ev letter)
  (loop for tg across (gethash "tags" ev)
        when (and (vectorp tg) (>= (length tg) 2) (equal (aref tg 0) letter))
          collect (aref tg 1)))
(defun d-tag (ev) (or (tag-val ev "d") ""))
(defun coord-key (ev kind) (format nil "~a:~a:~a" (gethash "pubkey" ev) kind (d-tag ev)))
(defun replaceable-p (kind) (or (member kind '(0 3)) (<= 10000 kind 19999) (<= 30000 kind 39999)))
(defun ephemeral-p (kind) (<= 20000 kind 29999))

;;; Gating: private channels are members-only. A WRITE to a private
;;; channel requires the author to be a member (the signature proves the author).
;;; READS of a private channel's events (REQ history + live broadcast) fan out
;;; only to connections NIP-42-authenticated as a member. Open channels — and any
;;; event with no channel (h-tag) — stay public.
(defun event-channel (ev) (tag-val ev "h"))
(defun channel-private-p (chan)
  (and chan (eq (getf (gethash chan *channels*) :visibility) :private)))
(defun may-write-p (ev)
  (let ((chan (event-channel ev)))
    (or (not (channel-private-p chan))
        (member (gethash "pubkey" ev) (channel-members chan) :test #'equal))))
(defun conn-may-see-p (conn ev)
  (let ((chan (event-channel ev)))
    (or (not (channel-private-p chan))
        (let ((who (getf conn :authed-pubkey)))
          (and who (member who (channel-members chan) :test #'equal))))))

(defun relay-ingest (ev)
  "Store an inbound (already signature-verified) event. Returns T if the store
   changed (→ broadcast). Ephemeral kinds return NIL here but are broadcast by
   the caller."
  (let ((kind (truncate (gethash "kind" ev))) (id (gethash "id" ev)))
    (sb-thread:with-mutex (*store-lock*)
      (cond
        ((gethash id *events*) nil)                          ; duplicate
        ((ephemeral-p kind) nil)                             ; presence/typing/auth: never stored
        ((replaceable-p kind)
         (let* ((ck (coord-key ev kind)) (old (gethash ck *replaceables*))
                (oldev (and old (gethash old *events*))))
           (when (or (not oldev)
                     (>= (truncate (gethash "created_at" ev)) (truncate (gethash "created_at" oldev))))
             (when old (remhash old *events*))
             (setf (gethash id *events*) ev (gethash ck *replaceables*) id)
             t)))
        (t (setf (gethash id *events*) ev) t)))))

;;; ----------------------------- WS transport ---------------------------
;;; (generic RFC6455 + NIP-01 plumbing)
(defvar *relay-listener* nil)
(defvar *relay-thread* nil)
(defvar *relay-conns* nil "live connections — each a plist (:stream :wlock :subs).")
(defvar *relay-lock* (sb-thread:make-mutex :name "skep-relay"))

(defparameter +ws-guid+ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
(defun ws-accept-key (key)
  (cl-base64:usb8-array-to-base64-string
   (ic:digest-sequence :sha1 (sb-ext:string-to-octets (concatenate 'string key +ws-guid+)
                                                       :external-format :latin-1))))
(defun read-http-request (stream)
  "Read the request head (up to CRLFCRLF); return (values request-line headers-alist)."
  (let ((buf (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (read-byte stream nil nil) while b do
      (vector-push-extend b buf)
      (when (and (>= (length buf) 4)
                 (= (aref buf (- (length buf) 4)) 13) (= (aref buf (- (length buf) 3)) 10)
                 (= (aref buf (- (length buf) 2)) 13) (= (aref buf (- (length buf) 1)) 10))
        (return))
      (when (> (length buf) 65536) (return)))
    (let* ((lines (ppcre:split "\\r\\n" (sb-ext:octets-to-string buf :external-format :latin-1)))
           (req-line (first lines)) (out '()))
      (dolist (l (cdr lines))
        (let ((c (position #\: l)))
          (when c (push (cons (string-downcase (string-trim " " (subseq l 0 c)))
                              (string-trim " " (subseq l (1+ c)))) out))))
      (values req-line (nreverse out)))))
;;; ---------------------- Buzz HTTP facade (REST) -----------------------
;;; The real Buzz CLI talks to the relay over HTTP, not the ws Nostr protocol:
;;;   POST /events  — publish a signed Nostr event (body = the JSON event)
;;;   POST /query   — read events (body = a JSON array of Nostr filters)
;;;   POST /count   — count matching events
;;; each authenticated with NIP-98 (an Authorization: Nostr <base64 kind-27235
;;; event> header). We serve these on the SAME listener as the ws relay — one
;;; port does ws + HTTP, exactly like a real Buzz relay — so `buzz messages
;;; send`/`get` interoperate with skep directly.
(defun parse-request-line (line)
  (let* ((s1 (and line (position #\Space line)))
         (s2 (and s1 (position #\Space line :start (1+ s1)))))
    (if (and s1 s2) (values (subseq line 0 s1) (subseq line (1+ s1) s2))
        (values nil nil))))
(defun http-write (stream status body &optional (ctype "application/json"))
  (let* ((crlf (coerce '(#\Return #\Newline) 'string))
         (bytes (sb-ext:string-to-octets body :external-format :utf-8))
         (head (concatenate 'string
                 "HTTP/1.1 " status crlf "Content-Type: " ctype crlf
                 "Access-Control-Allow-Origin: *" crlf
                 "Content-Length: " (princ-to-string (length bytes)) crlf
                 "Connection: close" crlf crlf)))
    (write-sequence (sb-ext:string-to-octets head :external-format :latin-1) stream)
    (write-sequence bytes stream)
    (force-output stream)))
(defun sha256-hex (bytes) (ic:byte-array-to-hex-string (ic:digest-sequence :sha256 bytes)))
(defun verify-nip98 (auth method path body)
  "Verify a NIP-98 header ('Nostr <base64(kind-27235 event)>'): valid sig, method
   tag, `u` path, and payload = sha256(body). Returns the signer pubkey or NIL."
  (ignore-errors
    (when (and auth (>= (length auth) 6) (string-equal (subseq auth 0 6) "Nostr "))
      (let* ((bytes (cl-base64:base64-string-to-usb8-array (string-trim " " (subseq auth 6))))
             (ev (jzon:parse (sb-ext:octets-to-string bytes :external-format :utf-8))))
        (when (and (= 27235 (truncate (gethash "kind" ev)))
                   (n:verify-event ev)
                   (equal method (tag-val ev "method"))
                   (let ((u (tag-val ev "u"))) (and u (search path u)))
                   (let ((pl (tag-val ev "payload")))
                     (or (zerop (length body))
                         (and pl (string-equal pl (sha256-hex body))))))
          (gethash "pubkey" ev))))))
(defun rest-events (body pub stream)
  (declare (ignore pub))
  (let ((ev (ignore-errors (jzon:parse (sb-ext:octets-to-string body :external-format :utf-8)))))
    (cond
      ((not (and (hash-table-p ev) (n:verify-event ev)))
       (http-write stream "400 Bad Request" "{\"error\":\"invalid event\"}"))
      ((not (may-write-p ev))
       (http-write stream "403 Forbidden" "{\"error\":\"restricted: not a member\"}"))
      (t (let ((accepted (relay-ingest ev)) (kind (truncate (gethash "kind" ev))))
           (when (or accepted (ephemeral-p kind)) (relay-broadcast ev))
           (when (and accepted (admin-kind-p kind)) (process-admin-event ev))
           (http-write stream "200 OK"
                       (n:json (let ((h (make-hash-table :test 'equal)))
                                 (setf (gethash "id" h) (gethash "id" ev)) h))))))))
(defun query-filters (body)
  (let ((f (ignore-errors (jzon:parse (sb-ext:octets-to-string body :external-format :utf-8)))))
    (cond ((vectorp f) (coerce f 'list)) ((listp f) f) ((hash-table-p f) (list f)) (t nil))))
(defun rest-query (body pub stream)
  (let ((conn (list :authed-pubkey pub)) (matches '()) (flist (query-filters body)))
    (dolist (ev (all-stored-events))
      (when (and (some (lambda (f) (event-matches ev f)) flist) (conn-may-see-p conn ev))
        (push ev matches)))
    (setf matches (sort matches #'> :key (lambda (e) (truncate (gethash "created_at" e)))))
    (http-write stream "200 OK" (n:json (coerce matches 'vector)))))
(defun rest-count (body pub stream)
  (declare (ignore pub))
  (let* ((flist (query-filters body))
         (n (count-if (lambda (ev) (some (lambda (f) (event-matches ev f)) flist)) (all-stored-events))))
    (http-write stream "200 OK" (format nil "{\"count\":~d}" n))))
(defun handle-rest (path body auth stream)
  (let ((pub (verify-nip98 auth "POST" path body)))
    (cond ((null pub) (http-write stream "401 Unauthorized" "{\"error\":\"nip98 auth required\"}"))
          ((equal path "/events") (rest-events body pub stream))
          ((equal path "/query")  (rest-query body pub stream))
          ((equal path "/count")  (rest-count body pub stream))
          (t (http-write stream "404 Not Found" "{}")))))

(defun http-serve (stream)
  "Handle one request on STREAM. Returns :ws to hand off to the websocket loop,
   or :done after serving a NIP-11 / Buzz-REST response."
  (multiple-value-bind (req-line headers) (read-http-request stream)
    (let ((key (cdr (assoc "sec-websocket-key" headers :test #'equal)))
          (crlf (coerce '(#\Return #\Newline) 'string)))
      (cond
        (key
         (write-sequence (sb-ext:string-to-octets
                          (concatenate 'string
                            "HTTP/1.1 101 Switching Protocols" crlf
                            "Upgrade: websocket" crlf "Connection: Upgrade" crlf
                            "Sec-WebSocket-Accept: " (ws-accept-key key) crlf crlf)
                          :external-format :latin-1)
                         stream)
         (force-output stream) :ws)
        (t
         (multiple-value-bind (method path) (parse-request-line req-line)
           (if (and (equal method "POST")
                    (member path '("/events" "/query" "/count") :test #'equal))
               (let* ((clen (let ((v (cdr (assoc "content-length" headers :test #'equal))))
                              (or (and v (parse-integer v :junk-allowed t)) 0)))
                      (body (if (plusp clen) (read-n stream clen)
                                (make-array 0 :element-type '(unsigned-byte 8))))
                      (auth (cdr (assoc "authorization" headers :test #'equal))))
                 (handle-rest path body auth stream))
               (http-write stream "200 OK" *nip11* "application/nostr+json")))
         :done)))))
(defun relay-send (conn string)
  (let ((frame (fast-websocket:compose-frame (sb-ext:string-to-octets string :external-format :utf-8) :type :text)))
    (sb-thread:with-mutex ((getf conn :wlock))
      (ignore-errors (write-sequence frame (getf conn :stream)) (force-output (getf conn :stream))))))
(defun relay-send-ctrl (conn payload type)
  (let ((frame (fast-websocket:compose-frame payload :type type)))
    (sb-thread:with-mutex ((getf conn :wlock))
      (ignore-errors (write-sequence frame (getf conn :stream)) (force-output (getf conn :stream))))))

;;; ----------------------------- filters --------------------------------
(defun in-seq (x seq &key (test #'equal)) (and seq (find x seq :test test)))
(defun event-matches (ev filter)
  (and (let ((v (gethash "ids" filter)))     (or (null v) (in-seq (gethash "id" ev) v)))
       (let ((v (gethash "authors" filter))) (or (null v) (in-seq (gethash "pubkey" ev) v)))
       (let ((v (gethash "kinds" filter)))   (or (null v) (find (truncate (gethash "kind" ev)) v
                                                                 :test (lambda (a b) (= a (truncate b))))))
       (let ((v (gethash "since" filter)))   (or (null v) (>= (truncate (gethash "created_at" ev)) (truncate v))))
       (let ((v (gethash "until" filter)))   (or (null v) (<= (truncate (gethash "created_at" ev)) (truncate v))))
       (tag-filters-match ev filter)))
(defun tag-filters-match (ev filter)
  (let ((ok t))
    (maphash (lambda (k vals)
               (when (and (stringp k) (> (length k) 1) (char= (char k 0) #\#))
                 (let ((letter (subseq k 1)))
                   (unless (loop for tg across (gethash "tags" ev)
                                 thereis (and (vectorp tg) (>= (length tg) 2)
                                              (equal (aref tg 0) letter) (in-seq (aref tg 1) vals)))
                     (setf ok nil)))))
             filter)
    ok))

;;; ----------------------------- protocol -------------------------------
(defun relay-on-req (conn a)
  (let* ((sub (aref a 1)) (filters (coerce (subseq a 2) 'list)) (matches '()))
    (setf (gethash sub (getf conn :subs)) filters)
    (dolist (ev (all-stored-events))
      (when (and (some (lambda (f) (event-matches ev f)) filters)
                 (conn-may-see-p conn ev))
        (push ev matches)))
    (setf matches (sort matches #'> :key (lambda (e) (truncate (gethash "created_at" e)))))
    (let ((lim (reduce #'min (mapcar (lambda (f) (let ((l (gethash "limit" f)))
                                                   (if (numberp l) (truncate l) most-positive-fixnum)))
                                     filters)
                       :initial-value most-positive-fixnum)))
      (when (< lim (length matches)) (setf matches (subseq matches 0 lim))))
    (dolist (ev (reverse matches))
      (relay-send conn (format nil "[\"EVENT\",~a,~a]" (jzon:stringify sub) (n:json ev))))
    (relay-send conn (format nil "[\"EOSE\",~a]" (jzon:stringify sub)))))
(defun relay-broadcast (ev)
  (let ((conns (sb-thread:with-mutex (*relay-lock*) (copy-list *relay-conns*))))
    (dolist (conn conns)
      (when (conn-may-see-p conn ev)
        (maphash (lambda (sub filters)
                   (when (some (lambda (f) (event-matches ev f)) filters)
                     (relay-send conn (format nil "[\"EVENT\",~a,~a]" (jzon:stringify sub) (n:json ev)))))
                 (getf conn :subs))))))
(defun relay-on-event (conn ev)
  (let ((id (gethash "id" ev)) (kind (truncate (gethash "kind" ev))))
    (cond
      ((not (n:verify-event ev))
       (relay-send conn (format nil "[\"OK\",~a,false,\"invalid: bad signature\"]" (jzon:stringify id))))
      ((not (may-write-p ev))
       (relay-send conn (format nil "[\"OK\",~a,false,\"restricted: not a member of this channel\"]" (jzon:stringify id))))
      (t
       (let ((accepted (relay-ingest ev)))
         (relay-send conn (format nil "[\"OK\",~a,true,~a]" (jzon:stringify id)
                                  (if (or accepted (ephemeral-p kind)) "\"\"" "\"duplicate: have this event\"")))
         (when (or accepted (ephemeral-p kind)) (relay-broadcast ev))
         (when (and accepted (admin-kind-p kind)) (process-admin-event ev)))))))
(defun relay-on-message (conn msg)
  (handler-case
      (let ((a (jzon:parse (if (stringp msg) msg (sb-ext:octets-to-string msg :external-format :utf-8)))))
        (when (and (vectorp a) (plusp (length a)))
          (let ((typ (aref a 0)))
            (cond ((equal typ "EVENT") (relay-on-event conn (aref a 1)))
                  ((equal typ "REQ")   (relay-on-req conn a))
                  ((equal typ "CLOSE") (remhash (aref a 1) (getf conn :subs)))
                  ((equal typ "AUTH")  (relay-on-auth conn (aref a 1)))))))
    (error () nil)))

;;; NIP-42: the relay challenged on connect (see relay-handle); the client replies
;;; with a signed kind-22242 event echoing the challenge. On success we bind this
;;; connection's identity, which read-gating consults (conn-may-see-p).
(defun verify-auth (conn ev)
  (ignore-errors
    (and (hash-table-p ev)
         (= 22242 (truncate (gethash "kind" ev)))
         (let ((ch (tag-val ev "challenge")))
           (and ch (getf conn :challenge) (equal ch (getf conn :challenge))))
         (tag-val ev "relay")                                   ; must name a relay (URL not hard-matched)
         (<= (abs (- (n:unix-now) (truncate (gethash "created_at" ev)))) 60)
         (n:verify-event ev))))
(defun relay-on-auth (conn ev)
  (if (verify-auth conn ev)
      (progn (setf (getf conn :authed-pubkey) (gethash "pubkey" ev))
             (relay-send conn (format nil "[\"OK\",~a,true,\"\"]" (jzon:stringify (gethash "id" ev)))))
      (relay-send conn (format nil "[\"OK\",~a,false,\"auth failed\"]"
                               (jzon:stringify (if (hash-table-p ev) (gethash "id" ev) ""))))))

(defun read-n (stream n)
  (if (zerop n) (make-array 0 :element-type '(unsigned-byte 8))
      (let ((b (make-array n :element-type '(unsigned-byte 8))))
        (when (= n (read-sequence b stream)) b))))
(defun read-ws-frame (stream)
  (let ((h (read-n stream 2)))
    (when h
      (let* ((len (logand (aref h 1) #x7f)) (masked (logbitp 7 (aref h 1)))
             (ext (cond ((= len 126) 2) ((= len 127) 8) (t 0)))
             (extb (read-n stream ext))
             (paylen (cond ((= ext 2) (+ (ash (aref extb 0) 8) (aref extb 1)))
                           ((= ext 8) (let ((v 0)) (dotimes (i 8 v) (setf v (+ (ash v 8) (aref extb i))))))
                           (t len)))
             (maskb (and masked (read-n stream 4)))
             (payload (read-n stream paylen)))
        (when (and extb (or (not masked) maskb) payload)
          (let* ((total (+ 2 ext (if masked 4 0) paylen))
                 (frame (make-array total :element-type '(unsigned-byte 8))) (o 0))
            (replace frame h) (setf o 2)
            (when (plusp ext) (replace frame extb :start1 o) (incf o ext))
            (when masked (replace frame maskb :start1 o) (incf o 4))
            (when (plusp paylen) (replace frame payload :start1 o))
            frame))))))
(defun relay-handle (sock)
  (let* ((stream (usocket:socket-stream sock))
         (conn (list :stream stream :wlock (sb-thread:make-mutex) :subs (make-hash-table :test 'equal)
                     :authed-pubkey nil :challenge nil)))
    (unwind-protect
         (when (eq :ws (handler-case (http-serve stream) (serious-condition () nil)))
           (sb-thread:with-mutex (*relay-lock*) (push conn *relay-conns*))
           ;; NIP-42: challenge immediately on connect (Buzz-style).
           (let ((challenge (rand-hex 16)))
             (setf (getf conn :challenge) challenge)
             (relay-send conn (format nil "[\"AUTH\",~a]" (jzon:stringify challenge))))
           (let* ((ws (fast-websocket:make-ws))
                  (parser (fast-websocket:make-parser
                           ws :require-masking t
                           :message-callback (lambda (m) (relay-on-message conn m))
                           :ping-callback (lambda (p) (relay-send-ctrl conn p :pong))
                           :close-callback (lambda (p &key code) (declare (ignore p code)) (error "ws-closed")))))
             (handler-case
                 (loop for frame = (read-ws-frame stream) while frame do (funcall parser frame))
               (serious-condition () nil))))
      (sb-thread:with-mutex (*relay-lock*) (setf *relay-conns* (remove conn *relay-conns*)))
      (ignore-errors (usocket:socket-close sock)))))
(defun start-relay (&optional (port *relay-port*))
  (ensure-relay-key)
  (unless (and *relay-thread* (sb-thread:thread-alive-p *relay-thread*))
    (setf *relay-listener* (usocket:socket-listen "127.0.0.1" port :reuse-address t :element-type '(unsigned-byte 8)))
    (setf *relay-thread*
          (sb-thread:make-thread
           (lambda ()
             (handler-case
                 (loop (let ((c (usocket:socket-accept *relay-listener* :element-type '(unsigned-byte 8))))
                         (sb-thread:make-thread (lambda () (handler-case (relay-handle c) (serious-condition () nil)))
                                                :name "skep-relay-conn")))
               (serious-condition () nil)))
           :name "skep-relay-accept"))
    (format t "~&[skep] nostr relay (ws) on :~d~%" port))
  *relay-thread*)
(defun stop-relay ()
  (ignore-errors (when *relay-listener* (usocket:socket-close *relay-listener*)))
  (ignore-errors (when (and *relay-thread* (sb-thread:thread-alive-p *relay-thread*))
                   (sb-thread:terminate-thread *relay-thread*)))
  (setf *relay-thread* nil *relay-listener* nil))

;;; --------------------------- channel model ----------------------------
(defun rand-hex (nbytes) (ic:byte-array-to-hex-string (n:urandom nbytes)))
(defun new-channel (&key (name "channel") (members '()) (visibility :open))
  "Create a NIP-29-style channel; returns its id (the value that rides in the
   ['h', …] tag). VISIBILITY is :open (public) or :private
   (members-only — see may-write-p / conn-may-see-p)."
  (let ((id (rand-hex 16)))
    (sb-thread:with-mutex (*store-lock*)
      (setf (gethash id *channels*)
            (list :name name :visibility visibility
                  :members (remove-duplicates members :test #'equal))))
    id))
(defun add-member (channel pubkey)
  (sb-thread:with-mutex (*store-lock*)
    (let ((c (gethash channel *channels*)))
      (when c (setf (getf c :members) (adjoin pubkey (getf c :members) :test #'equal)
                    (gethash channel *channels*) c))))
  pubkey)
(defun channel-members (channel) (getf (gethash channel *channels*) :members))

;;; --------------------- NIP-29 relay-side groups -----------------------
;;; A real Buzz relay turns client commands — kind 9007 (create), 9021 (join),
;;; 9000 (put-user/add-member), 9002 (edit-metadata) — into RELAY-SIGNED
;;; addressable group events: 39000 (metadata), 39001 (admins), 39002 (members).
;;; Clients (buzz-cli's `channels create`, buzz-acp's channel discovery) read
;;; those. skep reproduces this so a channel forms here directly — no seeding.
(defvar *relay-sec* nil "the relay's own signing key (integer) for 39xxx events.")
(defparameter *relay-key-file* (merge-pathnames ".skep/relay.key" (user-homedir-pathname)))
(defun ensure-relay-key ()
  (or *relay-sec*
      (setf *relay-sec*
            (if (probe-file *relay-key-file*)
                (with-open-file (s *relay-key-file*) (parse-integer (read-line s) :radix 16))
                (let ((k (nth-value 0 (n:gen-key))))
                  (ignore-errors
                    (ensure-directories-exist *relay-key-file*)
                    (with-open-file (s *relay-key-file* :direction :output
                                       :if-exists :supersede :if-does-not-exist :create)
                      (format s "~(~64,'0x~)~%" k)))
                  k)))))
(defun relay-pubkey () (n:hex-pubkey (ensure-relay-key)))
(defun admin-kind-p (kind) (<= 9000 kind 9022))

(defun grp-create (ev chan actor)
  (sb-thread:with-mutex (*store-lock*)
    (unless (gethash chan *channels*)
      (setf (gethash chan *channels*)
            (list :name (or (tag-val ev "name") "channel")
                  :visibility (if (equal (tag-val ev "visibility") "private") :private :open)
                  :type (or (tag-val ev "channel_type") "stream")
                  :description (tag-val ev "about")
                  :members (list actor) :owner actor :admins (list actor))))))
(defun grp-join (chan actor)
  (let ((g (gethash chan *channels*)))
    (when (and g (eq (getf g :visibility) :open))
      (sb-thread:with-mutex (*store-lock*)
        (setf (getf g :members) (adjoin actor (getf g :members) :test #'equal)
              (gethash chan *channels*) g)))))
(defun grp-put-user (ev chan)
  (let ((g (gethash chan *channels*)) (target (tag-val ev "p")) (role (tag-val ev "role")))
    (when (and g target)
      (sb-thread:with-mutex (*store-lock*)
        (setf (getf g :members) (adjoin target (getf g :members) :test #'equal))
        (when (member role '("admin" "owner") :test #'equal)
          (setf (getf g :admins) (adjoin target (getf g :admins) :test #'equal)))
        (setf (gethash chan *channels*) g)))))
(defun grp-edit (ev chan)
  (let ((g (gethash chan *channels*)))
    (when g
      (sb-thread:with-mutex (*store-lock*)
        (let ((name (tag-val ev "name")) (about (tag-val ev "about")) (vis (tag-val ev "visibility")))
          (when name (setf (getf g :name) name))
          (when about (setf (getf g :description) about))
          (when vis (setf (getf g :visibility) (if (equal vis "private") :private :open))))
        (setf (gethash chan *channels*) g)))))

(defvar *disc-ts* (make-hash-table :test 'equal) "\"kind:chan\" -> last emitted created_at (monotonic).")
(defun disc-ts (kind chan)
  (let* ((k (format nil "~a:~a" kind chan)) (prev (gethash k *disc-ts* 0))
         (ts (max (n:unix-now) (1+ prev))))
    (setf (gethash k *disc-ts*) ts) ts))
(defun member-role (g pub)
  (cond ((equal pub (getf g :owner)) "owner")
        ((member pub (getf g :admins) :test #'equal) "admin")
        (t "member")))
(defun emit-signed (rsec rpub kind tags chan)
  (let ((ev (n:sign-event rsec rpub (disc-ts kind chan) kind (coerce tags 'vector) "")))
    (when (relay-ingest ev) (relay-broadcast ev))))
(defun emit-group-discovery (chan)
  "Emit relay-signed 39000/39001/39002 for CHAN's current group state."
  (let ((g (gethash chan *channels*)) (rsec (ensure-relay-key)))
    (when g
      (let ((rpub (n:hex-pubkey rsec)) (members (getf g :members)))
        ;; 39000 metadata
        (let ((tags (list (vector "d" chan) (vector "name" (getf g :name)))))
          (when (getf g :description) (setf tags (append tags (list (vector "about" (getf g :description))))))
          (setf tags (append tags (list (if (eq (getf g :visibility) :private) (vector "private") (vector "public"))
                                         (vector "closed") (vector "t" (getf g :type)))))
          (emit-signed rsec rpub 39000 tags chan))
        ;; 39001 admins
        (let ((tags (list (vector "d" chan))))
          (dolist (m members)
            (when (member m (cons (getf g :owner) (getf g :admins)) :test #'equal)
              (setf tags (append tags (list (vector "p" m (member-role g m)))))))
          (emit-signed rsec rpub 39001 tags chan))
        ;; 39002 members
        (let ((tags (list (vector "d" chan))))
          (dolist (m members) (setf tags (append tags (list (vector "p" m (member-role g m))))))
          (emit-signed rsec rpub 39002 tags chan))))))

(defun process-admin-event (ev)
  "After a NIP-29 command (9007/9021/9000/9002) is ingested, update group state
   and (re-)emit the relay-signed discovery events."
  (let ((kind (truncate (gethash "kind" ev))) (chan (h-tag ev)) (actor (sender-of ev)))
    (when chan
      (case kind
        (9007 (grp-create ev chan actor))
        (9021 (grp-join chan actor))
        (9000 (grp-put-user ev chan))
        (9002 (grp-edit ev chan)))
      (emit-group-discovery chan))))

;;; --------------------------- message model ----------------------------
;;; kind 9 group chat, Buzz-exact: h-tag binds the channel, NIP-10 e-tags thread,
;;; p-tags mention (route to agents), content is plaintext.
(defun build-message (sec channel text &key reply-to root mentions extra-tags)
  (let* ((pub (n:hex-pubkey sec))
         (tags (list (vector "h" channel))))
    (cond ((and root reply-to (not (equal root reply-to)))
           (setf tags (append tags (list (vector "e" root "" "root")
                                          (vector "e" reply-to "" "reply")))))
          (reply-to
           (setf tags (append tags (list (vector "e" reply-to "" "reply"))))))
    (setf tags (append tags (mapcar (lambda (m) (vector "p" m)) mentions) extra-tags))
    (n:sign-event sec pub (n:unix-now) 9 (coerce tags 'vector) text)))
(defun publish-event (ev url &key (secs 6))
  "Publish EV and wait for ITS Ok. Unlike a naive publish that finishes on any
   frame), this waits for the [\"OK\",<this-id>,…] specifically and ignores the
   relay's proactive NIP-42 [\"AUTH\",…] — a relay that challenges on connect would
   otherwise trick a finish-on-any-frame client into closing before the OK. T iff
   the relay OK'd the event."
  (let ((ok nil) (done nil) (c nil) (id (gethash "id" ev)))
    (handler-case
        (sb-ext:with-timeout (+ secs 3)
          (setf c (wsd:make-client url))
          (wsd:on :message c
                  (lambda (m)
                    (handler-case
                        (let ((a (jzon:parse m)))
                          (when (and (vectorp a) (>= (length a) 3)
                                     (equal (aref a 0) "OK") (equal (aref a 1) id))
                            (setf ok (eq (aref a 2) t) done t)))
                      (error () nil))))
          (wsd:start-connection c)
          (loop repeat 40 until (eq (wsd:ready-state c) :open) do (sleep 0.1))
          (wsd:send-text c (format nil "[\"EVENT\",~a]" (n:json ev)))
          (loop repeat (* secs 10) until done do (sleep 0.1))
          (ignore-errors (wsd:close-connection c)))
      (serious-condition () nil))
    ok))

(defun post-message (ev &key (url (relay-url)))
  "Publish EV to the skep relay; returns ACK count (0/1). Writes don't need conn
   auth — the signature proves the author (membership is checked on the author)."
  (if (publish-event ev url) 1 0))

;;; ---------------------------- NIP-42 client ---------------------------
(defun signed-auth-event (sec challenge relay-url)
  "A kind-22242 auth event echoing CHALLENGE, signed by SEC (NIP-42)."
  (n:sign-event sec (n:hex-pubkey sec) (n:unix-now) 22242
                (vector (vector "relay" relay-url) (vector "challenge" challenge)) ""))

(defun nip42-fetch (sec filters-json url &key (secs 3))
  "Like a plain fetch, but complete a NIP-42 challenge (sign with SEC)
   BEFORE issuing the REQ, so a gated relay fans private-channel events out to us.
   Falls back to an unauthed REQ if the relay never challenges (open relay)."
  (let ((seen (make-hash-table :test 'equal)) (out '()) (req-sent nil) (c nil))
    (handler-case
        (sb-ext:with-timeout (+ secs 6)
          (setf c (wsd:make-client url))
          (flet ((send-req () (unless req-sent
                                (setf req-sent t)
                                (wsd:send-text c (format nil "[\"REQ\",\"q\",~a]" filters-json)))))
            (wsd:on :message c
                    (lambda (m)
                      (handler-case
                          (let ((a (jzon:parse m)))
                            (when (and (vectorp a) (plusp (length a)))
                              (cond
                                ((equal (aref a 0) "AUTH")
                                 (wsd:send-text c (format nil "[\"AUTH\",~a]"
                                                          (n:json (signed-auth-event sec (aref a 1) url))))
                                 ;; (re-)issue the REQ now that we're authed, even if the
                                 ;; open-relay fallback already sent an unauthed one — a
                                 ;; duplicate REQ just re-runs the query (seen[] dedupes).
                                 (setf req-sent t)
                                 (wsd:send-text c (format nil "[\"REQ\",\"q\",~a]" filters-json)))
                                ((and (equal (aref a 0) "EVENT") (>= (length a) 3))
                                 (let* ((ev (aref a 2)) (id (gethash "id" ev)))
                                   (unless (gethash id seen)
                                     (setf (gethash id seen) t) (push ev out)))))))
                        (error () nil))))
            (wsd:start-connection c)
            (loop repeat 40 until (eq (wsd:ready-state c) :open) do (sleep 0.1))
            (sleep 0.7) (send-req)                                ; open-relay fallback (no AUTH seen)
            (sleep secs)
            (ignore-errors (wsd:close-connection c))))
      (serious-condition () nil))
    out))

(defun authed-publish (sec ev url &key (secs 5))
  "Publish EV, completing a NIP-42 challenge first (for relays that gate writes on
   connection identity). Returns T on an OK-true. skep itself gates writes on the
   author, so plain post-message suffices here; this is for stricter relays."
  (let ((ok nil) (c nil) (sent nil))
    (handler-case
        (sb-ext:with-timeout (+ secs 4)
          (setf c (wsd:make-client url))
          (flet ((send-ev () (unless sent (setf sent t)
                               (wsd:send-text c (format nil "[\"EVENT\",~a]" (n:json ev))))))
            (wsd:on :message c
                    (lambda (m)
                      (handler-case
                          (let ((a (jzon:parse m)))
                            (when (and (vectorp a) (plusp (length a)))
                              (cond
                                ((equal (aref a 0) "AUTH")
                                 (wsd:send-text c (format nil "[\"AUTH\",~a]"
                                                          (n:json (signed-auth-event sec (aref a 1) url))))
                                 (send-ev))
                                ((and (equal (aref a 0) "OK") (>= (length a) 3)
                                      (equal (aref a 1) (gethash "id" ev))    ; ours, not the auth OK
                                      (eq (aref a 2) t))
                                 (setf ok t)))))
                        (error () nil))))
            (wsd:start-connection c)
            (loop repeat 40 until (eq (wsd:ready-state c) :open) do (sleep 0.1))
            (sleep 0.4) (send-ev)
            (loop repeat 30 until ok do (sleep 0.1))
            (ignore-errors (wsd:close-connection c))))
      (serious-condition () nil))
    ok))

;;; accessors used by the host / tests
(defun kind-9-p (ev) (= 9 (truncate (gethash "kind" ev))))
(defun content-of (ev) (gethash "content" ev))
(defun sender-of  (ev) (gethash "pubkey" ev))
(defun id-of      (ev) (gethash "id" ev))
(defun h-tag      (ev) (tag-val ev "h"))
(defun mentions-of (ev) (tag-vals ev "p"))
(defun reply-anchor (ev)
  "NIP-10 anchor a reply should thread to: the root e-tag if present, else the
   event's own id — mirrors Buzz's resolve_reply_anchor()."
  (let ((root (loop for tg across (gethash "tags" ev)
                    when (and (vectorp tg) (>= (length tg) 4)
                              (equal (aref tg 0) "e") (equal (aref tg 3) "root"))
                      return (aref tg 1))))
    (or root (id-of ev))))
