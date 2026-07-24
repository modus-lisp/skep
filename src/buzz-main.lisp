;;;; src/buzz-main.lisp — entry point for the `buzz`-compatible CLI shim.
;;;; Invoked by bin/buzz:  sbcl --script buzz-main.lisp <args…>
(let ((here (or *load-truename* *compile-file-truename*)))
  (load (merge-pathnames "cli.lisp" here)))
(sb-ext:exit :code (funcall (find-symbol "MAIN" "SKEP.CLI") (rest sb-ext:*posix-argv*)))
