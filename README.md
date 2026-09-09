# xmip-core-transport-cotp

COTP transport: ISO transport class 0 over TCP, RFC 1006 — TPKT framing, connect request and confirm with TSAPs, data TPDUs segmented and reassembled — the carrier S7 and other ISO-on-TCP protocols ride on. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
