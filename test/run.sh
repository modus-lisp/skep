#!/usr/bin/env bash
# Run every skep oracle; exit non-zero if any fails. skep's fitness gate.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."   # -> repo root
fails=0
for t in relay host auth cli acp-client nip29; do
  echo "### $t-test ###"
  out="$(timeout 300 sbcl --script "test/$t-test.lisp" 2>&1)"; code=$?
  echo "$out" | grep -E '  (ok|FAIL|ERR )|: [0-9]+ failure'
  if [ "$code" -ne 0 ]; then echo "  -> $t FAILED (exit $code)"; fails=$((fails+1)); fi
done
echo "==============================="
if [ "$fails" -eq 0 ]; then echo "skep: ALL ORACLES GREEN"; else echo "skep: $fails oracle(s) failed"; fi
exit "$fails"
