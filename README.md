# vettd-skill-scanner

Pure, I/O-free skill scanner engine for the vettd pipeline.

This crate performs no filesystem I/O, no network access, and no stdout/stderr
output — all inputs are pre-loaded by the caller. That boundary is intentional:
the scanner is designed to be embedded by any consumer (CLI, service, WASM
module) without modification.

## Contents

| Path | What it is |
|---|---|
| `crates/vettd-skill-scanner/` | the scanner engine — see [`lib.rs`](crates/vettd-skill-scanner/src/lib.rs) for the entry point and contract |
| `crates/http-shim/` | localhost HTTP sidecar exposing the scanner to the scanner suite — `GET /health` + `POST /scan` on `127.0.0.1` (`VETTD_SHIM_PORT`, default 8788); response carries findings, structural flags, and the scanner version |
| `crates/parity-adapter/` | a small stdin/stdout JSON binary used **only** by the `parity/` test harness — a testing tool, not a production integration path (that's `http-shim`) |
| `parity/` | **temporary.** A Python test harness that diffs this engine's output against a hand-ported TypeScript reimplementation in the `vettd` web app, used only while both versions exist during the TS→Rust migration. Removed once that migration is complete |

## Build & test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Consumers

- `vettd-cli` depends on this crate directly via a pinned Cargo `git` dependency.
- The scanner suite (`vettd-scanner-suite`) calls the scanner through the `http-shim` crate — see AgenticHighway/vettd#643.
