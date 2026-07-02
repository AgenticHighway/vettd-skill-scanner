# AGENTS.md

This file gives coding agents the minimum project context needed to work
safely in this repository.

## Project overview

- `vettd-skill-scanner` is a pure, I/O-free Rust library that scans AI skill
  packages (SKILL.md + bundled files) for structural, security, and
  best-practice findings.
- The scanner performs no filesystem I/O, no network access, and no
  stdout/stderr output. All inputs are pre-loaded by the caller.
- This repo was extracted from `vettd-cli`, which remains its primary
  first-party consumer via a pinned Cargo `git` dependency.

## Repo shape

- `crates/vettd-skill-scanner/` — the scanner engine
- `crates/parity-adapter/` — subprocess entry point for non-Rust callers
  (stdin/stdout JSON protocol, documented in the crate's `main.rs`)
- `parity/` — temporary Rust-vs-TypeScript parity test harness; see
  [AgenticHighway/vettd#642](https://github.com/AgenticHighway/vettd/issues/642)
  for removal criteria. Do not extend this harness — it is not meant to
  become permanent infrastructure.

## Working norms

- Keep changes small and focused.
- Preserve the crate's zero-I/O contract — no filesystem, network, or
  console output from `vettd-skill-scanner` itself.
- Add or update tests when behavior changes.
- Commit messages must be **under 100 characters** (subject line).

## Expected checks

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Notes for agents

- This crate is consumed by other repos at a pinned git revision — a
  breaking change here requires the consumer to bump its pin deliberately,
  it will not happen silently.
