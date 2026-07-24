#!/usr/bin/env bash
# Real-Buzz interop: drive skep with the UNMODIFIED `buzz` CLI (Block's Rust
# client) over its actual HTTP + NIP-98 protocol, in both directions.
#
# skep serves ws (Nostr) AND the Buzz HTTP REST API (/events, /query) on one
# port, so the real `buzz` binary publishes to and reads from skep directly —
# no Docker, no Buzz relay (skep IS the relay).
#
# Needs the `buzz` binary. Build it once (Rust toolchain + network):
#   git clone --depth 1 https://github.com/block/buzz && cd buzz
#   cargo build -p buzz-cli            # -> target/debug/buzz
# then: BUZZ_BIN=/path/to/buzz  bash test/interop-buzz.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
BUZZ="${BUZZ_BIN:-$HOME/buzz-src/target/debug/buzz}"
PORT="${SKEP_PORT:-8601}"
HEX="67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"
CH="8fc2684a-7c4b-4e9f-8f5b-51ae665a7605"

if [ ! -x "$BUZZ" ]; then
  echo "SKIP: buzz binary not found at $BUZZ (set BUZZ_BIN or build it — see header)."
  exit 0
fi

fails=0; ok(){ echo "  ok   $1"; }; bad(){ echo "  FAIL $1"; fails=$((fails+1)); }

cat > /tmp/skep-interop-up.lisp <<LISP
(load "$(pwd)/src/skep.lisp")
(in-package #:skep) (start-relay $PORT) (loop (sleep 3600))
LISP
sbcl --script /tmp/skep-interop-up.lisp >/tmp/skep-interop.log 2>&1 &
SKEP=$!; trap 'kill $SKEP 2>/dev/null' EXIT
sleep 6

echo "== real buzz -> skep (POST /events, NIP-98) =="
SEND=$(timeout 30 "$BUZZ" --relay http://127.0.0.1:$PORT --private-key $HEX \
  messages send --channel $CH --content "interop check from real buzz" 2>&1)
echo "$SEND" | grep -q '"id"' && ok "buzz send accepted by skep" || bad "buzz send ($SEND)"

echo "== real buzz <- skep (POST /query) =="
GET=$(timeout 30 "$BUZZ" --relay http://127.0.0.1:$PORT --private-key $HEX messages get --channel $CH 2>&1)
echo "$GET" | grep -q 'interop check from real buzz' && ok "buzz reads back its own message from skep" || bad "buzz get ($GET)"

echo "== skep's OWN event is readable by real buzz =="
cat > /tmp/skep-interop-post.lisp <<LISP
(load "$(pwd)/src/skep.lisp")
(in-package #:skep)
(let* ((k (n:gen-key)) (ev (build-message k "$CH" "authored by skep itself")))
  (post-message ev :url "ws://127.0.0.1:$PORT"))
LISP
sbcl --script /tmp/skep-interop-post.lisp >/dev/null 2>&1
GET2=$(timeout 30 "$BUZZ" --relay http://127.0.0.1:$PORT --private-key $HEX messages get --channel $CH 2>&1)
echo "$GET2" | grep -q 'authored by skep itself' && ok "real buzz reads a skep-authored event" || bad "buzz get2 ($GET2)"

echo "==============================="
if [ "$fails" -eq 0 ]; then echo "buzz interop: ALL GREEN (real buzz CLI <-> skep, both directions)"; else echo "buzz interop: $fails failed"; fi
exit "$fails"
