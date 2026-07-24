;;;; load.lisp — load the whole skep image.
;;;;   sbcl --load load.lisp
;;;; Brings up the Nostr client, the relay + NIP-29 model, the ACP host, and the
;;;; buzz-compatible CLI. Then e.g. (skep:start-relay) or (skep.host:start).
(let ((here (or *load-truename* *compile-file-truename*)))
  (load (merge-pathnames "src/skep.lisp" here))
  (load (merge-pathnames "src/host.lisp" here))
  (load (merge-pathnames "src/acp-client.lisp" here))
  (load (merge-pathnames "src/cli.lisp" here)))
(format t "~&skep loaded: packages SKEP, SKEP.HOST, SKEP.ACP, SKEP.CLI, SKEP.NOSTR~%")
