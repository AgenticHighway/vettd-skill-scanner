# EXIT.md — #925 signal emission path, cross-repo status

Created 2026-08-28. One file covering all three repos touched by epic #879 / #925
signal-emission work. This is the hand-off record for smoke testing.

## Branches ready for pickup

| Repo | Branch | Base | Pushed | Content |
|---|---|---|---|---|
| vettd-skill-scanner | `feat/pass-one-signal-emission` | `main` | yes | `Signal` type (`crates/vettd-skill-scanner/src/signal.rs`), `SkillScanResult.signals` (emitted for every scanned asset), `SkillScanResult.coverage` attestations, HTTP shim `signals` + `coverage` fields (`coverage` omitted when empty so zero-coverage runs stay byte-identical) |
| vettd-scanner-suite | `feat/scanner-signal-emission` | `main` | yes | `AssetSignal` contract (`src/contract/asset-signal.ts`), `ScannerOutput.signals?` (`src/contract/scanner.ts`), vettd adapter passthrough (`src/adapters/vettd.ts`) |
| vettd-cli | `feat/cli-scanner-field-gate` | `main` | yes | #243 gate rule **implemented** (D4 ruling: mechanism + recorded additive leaning): `scanner-field-gate.json` manifest, `scripts/check-scanner-field-gate.sh`, CI gate step, pin documentation in `crates/vettd-cli/Cargo.toml`. Commit `4c03245` |

## Per-repo exit readiness

- **vettd-skill-scanner — READY (YES).** CI green (`cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test`). Commits: `e59f952`, `5dcad9e`, `ad4c498`.
- **vettd-scanner-suite — READY (YES).** CI green (`pnpm lint`, `pnpm typecheck`,
  `pnpm test` — 160 pass, `pnpm build`). Commits: `b5a50b9`, `4f11849`.
- **vettd-cli — READY (YES).** #243 gate mechanism implemented and pushed on
  `feat/cli-scanner-field-gate` (commit `4c03245`): D4 ruling recorded on the issue,
  gate enforced in CI. `cargo fmt --all --check`, `cargo clippy -- -D warnings`,
  `cargo test` green. Smoke-testing the signal path does not depend on the CLI branch,
  but the branch is now complete for review.

## Notes for the smoke-test pick-up

- **Signals and coverage shape** is the key AC to verify: every scanned asset now
  carries signals (`signals` always present on a scan), while the `coverage` key
  stays omitted at the shim (`skip_serializing_if = "Vec::is_empty"`) until the
  coverage channel has entries — so zero-coverage runs keep the pre-signals
  response byte-identical.
- **Field mapping** matches the vettd wire contract: 4 required fields `dataCategory`,
  `sourceClass`, `ruleId`, `observedAt`; everything else optional; open strings, no
  closed enums; `observedAt` survives unmodified (never converted to a Date in the
  adapter).
- **Pre-existing duplicate branches:** `feat/signal-emission-path` exists on
  `origin` in vettd-skill-scanner and vettd-scanner-suite with identical trees (the
  earlier naming). Left untouched per no-branch-deletion rule; can be cleaned up by a
  human if desired.
- **Release order:** documented on AgenticHighway/vettd#925 (comment, satisfies the
  remaining AC). The additive optional `signals` shape is forward/backward compatible:
  vettd deploys first or the crate first, neither side breaks; the only constraint is
  a real signal rule must not reach a production consumer before the ingest side that
  persists signals is deployed.
- **vettd-cli#243 gate:** a tag bump of the `vettd-skill-scanner` pin in
  `vettd-cli` now fails CI unless every new `SkillScanResult` field is classified
  (surface|gate) in `scanner-field-gate.json`. D4 ruling + implementation recorded on
  the issue.
- No containers or long-running processes were started by this work; shared dev
  Postgres (`vettd-wt-signals-db`) untouched.