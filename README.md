# xmip-core-transport-cotp

COTP transport: ISO transport class 0 over TCP, RFC 1006 — TPKT framing, connect request and confirm with TSAPs, data TPDUs segmented and reassembled — the carrier S7 and other ISO-on-TCP protocols ride on. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Receive Location keeps its listener, bound on the first receive (`transport::kept::Kept`): a peer that connects between two receives is queued and taken by the next, where until 2026-09-27 each receive bound a listener of its own and a peer between receives was refused.

A `Connection` is `transport::Pooled`, so a protocol that answers every job over it — s7comm — keeps one between sends (`transport::Pool`). A COTP Send Location itself connects per message: its receiver takes a caller's messages until the caller disconnects, and class 0 acknowledges none, so a kept connection could not tell a message that landed from one written into a closing socket.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls, and its query is decoded there. Until 2026-09-28 this technology split the query off itself, without percent-decoding it.

## Acknowledgement

Acceptance is at-most-once here. COTP class 0 acknowledges no data TPDU, and
the caller's DR ends the connection without waiting for an answer, so nobody
is told how the receive cycle ended. Each message arrives whole, as its TPDUs
carried it. A receive takes every message its connection carries, whatever room the
runtime gives it (`Transport::receive_up_to`): the sender let go of each as
it sent it, so none can wait at the far end. A protocol above it that answers, such as S7 or MMS, answers in its
own terms.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
