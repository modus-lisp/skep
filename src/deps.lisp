;;;; src/deps.lisp — where skep finds the modus-lisp libraries it builds on.
;;;;
;;;; natrium, secp256k1-fast and json-simple are looked for beside this
;;;; checkout (../<lib>/), or under $MODUS_LISP when that is set, and registered
;;;; with ASDF so the QUICKLOAD / LOAD-SYSTEM calls in the other files find them.
;;;; Loading this file twice is harmless.

(require :asdf)
(let* ((here (or *load-truename* *compile-file-truename*))
       (env (uiop:getenv "MODUS_LISP"))
       (root (if (and env (plusp (length env)))
                 (uiop:ensure-directory-pathname env)
                 (merge-pathnames "../../" (make-pathname :name nil :type nil :defaults here)))))
  (dolist (lib '("natrium" "secp256k1-fast" "json-simple"))
    (let ((dir (merge-pathnames (concatenate 'string lib "/") root)))
      (when (probe-file (merge-pathnames (concatenate 'string lib ".asd") dir))
        (pushnew dir asdf:*central-registry* :test #'equal)))))
