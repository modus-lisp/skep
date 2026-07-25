#!/usr/bin/env bash
# Real-Buzz-ACP interop: drive skep with Block's UNMODIFIED `buzz-acp` (the agent
# host) plus the real `buzz` CLI. Proves skep is a drop-in Buzz relay from
# buzz-acp's view: it connects over ws, NIP-42-authenticates, discovers a channel,
# subscribes, receives an @mention, drives an ACP agent, and the agent's reply
# (posted via `buzz messages send`) lands back on the channel — no Docker.
#
# Needs the buzz-acp + buzz binaries. Build once (Rust + network):
#   git clone --depth 1 https://github.com/block/buzz && cd buzz
#   cargo build -p buzz-acp -p buzz-cli
# then: BUZZ_ACP_BIN=…/buzz-acp  BUZZ_BIN=…/buzz  bash test/interop-buzz-acp.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO="$(pwd)"
BUZZ_ACP="${BUZZ_ACP_BIN:-$HOME/buzz-src/target/debug/buzz-acp}"
BUZZ="${BUZZ_BIN:-$HOME/buzz-src/target/debug/buzz}"
PORT="${SKEP_PORT:-8620}"
if [ ! -x "$BUZZ_ACP" ] || [ ! -x "$BUZZ" ]; then
  echo "SKIP: need buzz-acp ($BUZZ_ACP) and buzz ($BUZZ) — build them (see header)."
  exit 0
fi
fails=0; ok(){ echo "  ok   $1"; }; bad(){ echo "  FAIL $1"; fails=$((fails+1)); }

lisp(){ local f; f=$(mktemp /tmp/skep-acp-XXXX.lisp); printf '%s\n' "$1" > "$f"; sbcl --script "$f" 2>/dev/null; rm -f "$f"; }
# fresh keypairs (agent = the buzz-acp identity; human = the poster)
readarray -t K < <(lisp "(load \"$REPO/src/skep.lisp\")(in-package #:skep)(dolist (w '(a h))(multiple-value-bind (s p n)(n:gen-key)(declare (ignore n))(format t \"~(~64,'0x~) ~a~%\" s p)))")
AGENT_PRIV=${K[0]% *}; AGENT_PUB=${K[0]#* }; HUMAN_PRIV=${K[1]% *}
CH="8fc2684a-7c4b-4e9f-8f5b-51ae665a7605"

# skep relay
lisp "(load \"$REPO/src/skep.lisp\")(in-package #:skep)(start-relay $PORT)(loop (sleep 3600))" &
SKEP=$!; trap 'kill $SKEP $ACP 2>/dev/null' EXIT; sleep 6
# seed a channel the agent is a member of (kind 39002 members + 39000 metadata)
lisp "(load \"$REPO/src/skep.lisp\")(in-package #:skep)(let*((rk (n:gen-key))(rp (n:hex-pubkey rk)))(post-message (n:sign-event rk rp (n:unix-now) 39002 (vector (vector \"d\" \"$CH\")(vector \"p\" \"$AGENT_PUB\")) \"\") :url \"ws://127.0.0.1:$PORT\")(post-message (n:sign-event rk rp (n:unix-now) 39000 (vector (vector \"d\" \"$CH\")(vector \"name\" \"interop\")) \"{}\") :url \"ws://127.0.0.1:$PORT\"))"

# real buzz-acp -> skep, driving the posting stub agent
export BUZZ_PRIVATE_KEY=$AGENT_PRIV BUZZ_RELAY_URL=ws://127.0.0.1:$PORT BUZZ_CLI_BIN="$BUZZ"
export BUZZ_ACP_AGENT_COMMAND=sbcl BUZZ_ACP_AGENT_ARGS="--script,$REPO/test/posting-stub-agent.lisp"
export BUZZ_ACP_RESPOND_TO=anyone BUZZ_ACP_SUBSCRIBE=all RUST_LOG=info
"$BUZZ_ACP" >/tmp/skep-buzzacp.log 2>&1 & ACP=$!; sleep 11
grep -q 'subscribed to channel' /tmp/skep-buzzacp.log && ok "buzz-acp connected + NIP-42 auth + subscribed to channel" \
  || bad "buzz-acp did not subscribe (see /tmp/skep-buzzacp.log)"

# human @mentions the agent
lisp "(load \"$REPO/src/skep.lisp\")(in-package #:skep)(post-message (build-message (parse-integer \"$HUMAN_PRIV\" :radix 16) \"$CH\" \"hey @agent, status?\" :mentions (list \"$AGENT_PUB\")) :url \"ws://127.0.0.1:$PORT\")"
sleep 18

grep -q 'turn complete' /tmp/skep-buzzacp.log && ok "buzz-acp drove the agent through a full turn" || bad "no turn completed"
REPLY=$("$BUZZ" --relay http://127.0.0.1:$PORT --private-key $AGENT_PRIV messages get --channel $CH 2>&1)
echo "$REPLY" | grep -q 'buzz-acp-driven agent' && ok "the agent's reply landed on the channel (read by real buzz)" \
  || bad "agent reply not on channel ($REPLY)"

echo "==============================="
[ "$fails" -eq 0 ] && echo "buzz-acp interop: ALL GREEN (real buzz-acp drives an agent through skep, end to end)" \
                   || echo "buzz-acp interop: $fails failed"
exit "$fails"
