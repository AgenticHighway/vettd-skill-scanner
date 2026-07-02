# vettd-skill-scanner

Pure, I/O-free skill scanner engine for the vettd pipeline.

This crate performs no filesystem I/O, no network access, and no stdout/stderr
output — all inputs are pre-loaded by the caller. That boundary is intentional:
the scanner is designed to be embedded by any consumer (CLI, service, WASM
module) without modification.

**Status:** private repo. Source-available vs. open-source licensing is an
open decision — the `license` field is intentionally left unset until that's
resolved.

## Contents

| Path | What it is |
|---|---|
| `crates/vettd-skill-scanner/` | the scanner engine — see [`lib.rs`](crates/vettd-skill-scanner/src/lib.rs) for the entry point and contract |
| `crates/parity-adapter/` | a small binary that reads a file-map JSON envelope on stdin, calls the scanner, and writes findings as JSON on stdout — the cross-language integration point for anything that can spawn a process |
| `parity/` | **temporary.** A Python test harness that diffs this engine's output against a hand-ported TypeScript reimplementation in the `vettd` web app, used only while both versions exist during the TS→Rust migration. Removed once that migration is complete — see [AgenticHighway/vettd#642](https://github.com/AgenticHighway/vettd/issues/642). |

## Build & test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Consumers

- `vettd-cli` depends on this crate directly via a pinned Cargo `git` dependency.
- Scanner suite integration is not yet decided — see AgenticHighway/vettd#642.
