# xmip-core-transport-cotp

COTP transport: ISO transport class 0 over TCP, RFC 1006 — TPKT framing, connect request and confirm with TSAPs, data TPDUs segmented and reassembled — the carrier S7 and other ISO-on-TCP protocols ride on. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Receive Location keeps its listener, bound as its transport is opened (`Configured::listening`; on its first receive until 2026-11-16), and its callers' connections between their messages (`transport::serving::Serving`, `caller::Caller`): a peer that connects between two receives is queued and taken by the next, where until 2026-09-27 each receive bound a listener of its own and a peer between receives was refused. A connection's CR is one turn and each message one more, every turn bounded whole by the node's `[tuning] receive_turn`, so a caller that stops partway is turned away and audited and the next is served (ADR-0018, amendment 2026-11-14). Until then a receive accepted one caller and read its messages until it disconnected, on the Location's own thread, every other caller waiting behind it.

A `Connection` is `transport::Pooled`, so a protocol that answers every job over it — s7comm — keeps one between sends (`transport::Pool`). A COTP Send Location itself connects per message: its receiver takes a caller's messages until the caller disconnects, and class 0 acknowledges none, so a kept connection could not tell a message that landed from one written into a closing socket.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls, and its query is decoded there. Until 2026-09-28 this technology split the query off itself, without percent-decoding it.

## Acknowledgement

Acceptance is at-most-once here. COTP class 0 acknowledges no data TPDU, and
the caller's DR ends the connection without waiting for an answer, so nobody
is told how the receive cycle ended. Each message arrives whole, as its TPDUs
carried it. A receive takes one message, from whichever caller sends first;
what a caller sent after it waits in its kept connection for the next
receive, and a stopping Location drains it as it drains what any far end
already let go of (`[tuning] receive_drain`). A protocol above it that
answers, such as S7 or MMS, answers in its own terms.

## The declaration

What a Location of this technology is configured with is two `const`s in its `declaration` module, `src/declaration.rs`, beside the code, which `Configured` reads (ADR-0064, amendment 2026-11-26): `declaration::SETTINGS`, `src_tsap`, `dst_tsap`, `tpdu_size_code` and `timeout`, and `SCHEMES`, `cotp`; `tpdu_size_code`'s default, `declaration::DEFAULT_SIZE_CODE`, is declared there too, where it was the TPDU's until then, and `tpdu` still names it, as the protocols riding on COTP take it. Built with its `declaration` feature alone (`--no-default-features --features declaration`), the crate is those and nothing more: its code and every crate the code is built on are behind the default feature. So the library the surfaces load carries it without the code, through the gathering crate xmip-core-declaration (open problem 48), and the language server and the desktop suggest and check a COTP Location's settings though no node in their process loaded the technology. `test/Declaration.Test.ps1` in the estate holds that the declaration builds nothing the transport capability does not.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
