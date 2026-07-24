# skep

A from-scratch, **wire-interoperable** reimplementation of Block's
[Buzz](https://github.com/block/buzz) — a Nostr-relay-native workspace where
humans and AI agents share channels. Named for a woven straw beehive (the hive →
Buzz; woven → its sibling weft/loom/shuttle projects; a real object → cairn/conch).

Pure Common Lisp (SBCL), self-contained: it vendors its own Nostr crypto
(secp256k1 + Schnorr/BIP-340 + bech32) and carries no external crypto dependency.
It speaks Buzz's real wire protocol (verified against block/buzz source):

- channels are **NIP-29 groups**; a chat message is **kind 9** with an
  `["h",<channel>]` tag; content is plaintext (membership, not encryption, is the gate).
- an agent is addressed by a `["p",<agent-pubkey>]` tag — the routing key.
- threading is **NIP-10** `e` tags; relay auth is **NIP-42** (kind 22242);
  identity is the keypair (no tokens).

Because skep drives the ACP wire protocol rather than any one agent's API, it is
**agent-agnostic**: it can host [operandi](https://github.com/modus-lisp/operandi),
goose, or claude-code — anything that speaks the
[Agent Client Protocol](https://agentclientprotocol.com).

## Pieces

| file | what |
|---|---|
| `src/nostr.lisp` | minimal Nostr client — event id/sign/verify (Schnorr), keys, ws publish/fetch. |
| `src/secp256k1.lisp` · `schnorr.lisp` · `bech32.lisp` | vendored, dependency-free crypto (BIP-340 + bech32). |
| `src/skep.lisp` | the **relay** (general event store, NIP-01 REQ/EVENT, `#h`/`#p` filters, NIP-42 auth, private-channel membership gating) + the NIP-29 message/channel model + a NIP-42-aware client. |
| `src/host.lisp` | the `buzz-acp` equivalent — watches for `#p` mentions of the agent, runs it, posts a NIP-10-threaded reply. Model call injected via `*answer-fn*`. |
| `src/acp-client.lisp` | the **ACP client** that makes skep an agent-agnostic host: spawns an ACP agent subprocess and drives it over stdio (initialize → session/new → session/prompt, streaming + permission). |
| `src/cli.lisp` + `bin/buzz` | the `buzz`-compatible send CLI: `buzz messages send --channel <id> --text <str> [--reply-to <id>] [--mention <pk>]…`, reading `BUZZ_RELAY_URL`/`BUZZ_PRIVATE_KEY`/`BUZZ_AUTH_TAG`. Put `bin/buzz` on an ACP agent's PATH and an unmodified Buzz agent can post into skep. |

## Run

```sh
sbcl --load load.lisp        # bring up the whole image
bash test/run.sh             # relay + host + auth + cli + acp oracles (64 checks)
```

Requires SBCL + Quicklisp (`usocket`, `fast-websocket`, `websocket-driver`,
`com.inuoe.jzon`, `ironclad`, `cl-ppcre`, `cl-base64`, `bordeaux-threads`).

## Status

The full loop works on its own stack: a human mentions the agent → skep spawns
and drives the agent over ACP → a threaded reply lands on the channel. Private
channels are members-only (NIP-42 + membership). The `buzz` CLI round-trips, so a
real Buzz agent can join, and skep's client can authenticate into a real Buzz
relay. **64/64 oracles green.**

Roadmap: presence/typing + reactions (kind 7); session-per-thread reuse
(`session/load`); a live interop test against real `buzz-acp` + goose.

## License

MIT — see `LICENSE`.
