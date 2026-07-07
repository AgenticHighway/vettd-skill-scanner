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
- `crates/http-shim/` — localhost HTTP sidecar (`GET /health` + `POST /scan`)
  through which the scanner suite calls the scanner; the production
  integration path for non-Rust consumers
- `crates/parity-adapter/` — subprocess entry point used by the `parity/`
  test harness only (stdin/stdout JSON protocol, documented in the crate's
  `main.rs`) — see the gotcha under Notes for agents
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

## Issues

- New issues should have 3-4 sections:
  - Description: Describe the issue. Prefer shorter descriptions when appropriate
  - (OPTIONAL) Design Decisions: if the issue is reasonably large or the user explicitly asks, include this section. Focus on large decisions, avoid small details unless instructed otherwise. Generally, lean away from including this section unless prompted
  - Scope: List what is in scope for the issue
  - Acceptance Criteria: Use checkboxes to list what needs to happen before this issue can be marked resolved
- Issue bodies should **always** focus on what the issue/task is, not how to solve it. If there are explicit solution details decided before opening the issue, these should be added as a comment after opening
- Use the Projects API fields correctly when instructed: by default, use status=Todo and leave other fields blank unless instructed

## Required behavior for agents

These rules apply to every task in this project unless explicitly overridden.
Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.

## Rule 1 — Think Before Coding

State assumptions explicitly. If uncertain, ask rather than guess.
Present multiple interpretations when ambiguity exists.
Push back when a simpler approach exists.
Stop when confused. Name what's unclear.

## Rule 2 — Simplicity First

Minimum code that solves the problem. Nothing speculative.
No features beyond what was asked. No abstractions for single-use code.
Test: would a senior engineer say this is overcomplicated? If yes, simplify.

## Rule 3 — Surgical Changes

Touch only what you must. Clean up only your own mess.
Don't "improve" adjacent code, comments, or formatting.
Don't refactor what isn't broken. Match existing style.

## Rule 4 — Goal-Driven Execution

Define success criteria. Loop until verified.
Don't follow steps. Define success and iterate.
Strong success criteria let you loop independently.

## Rule 5 — Use the model only for judgment calls

Use me for: classification, drafting, summarization, extraction.
Do NOT use me for: routing, retries, deterministic transforms.
If code can answer, code answers.

## Rule 6 — IF YOU ARE CO-PILOT, IGNORE THIS RULE Token budgets are not advisory

Per-task: 4,000 tokens. Per-session: 30,000 tokens.
If approaching budget, summarize and start fresh.
Surface the breach. Do not silently overrun.

## Rule 7 — Surface conflicts, don't average them

If two patterns contradict, pick one (more recent / more tested).
Explain why. Flag the other for cleanup.
Don't blend conflicting patterns.

## Rule 8 — Read before you write

Before adding code, read exports, immediate callers, shared utilities.
"Looks orthogonal" is dangerous. If unsure why code is structured a way, ask.

## Rule 9 — Tests verify intent, not just behavior

Tests must encode WHY behavior matters, not just WHAT it does.
A test that can't fail when business logic changes is wrong.

## Rule 10 — Checkpoint after every significant step

Summarize what was done, what's verified, what's left.
Don't continue from a state you can't describe back.
If you lose track, stop and restate.

## Rule 11 — Match the codebase's conventions, even if you disagree

Conformance > taste inside the codebase.
If you genuinely think a convention is harmful, surface it. Don't fork silently.

## Rule 12 — Fail loud

"Completed" is wrong if anything was skipped silently.
"Tests pass" is wrong if any were skipped.
Default to surfacing uncertainty, not hiding it.

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
- **Known gotcha:** `parity-adapter` and `parity/` are a testing tool only
  (cross-language Rust-vs-TS output parity checks, see #642). They are not a
  production integration path — do not treat this subprocess/JSON boundary
  as how any real consumer (vettd-cli, the scanner suite) talks to this
  crate in prod.
