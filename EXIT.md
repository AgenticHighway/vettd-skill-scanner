# EXIT.md — #925 signal emission path, cross-repo status

Created 2026-08-28. One file covering all three repos touched by epic #879 / #925
signal-emission work. This is the hand-off record for smoke testing.

## Branches ready for pickup

| Repo | Branch | Base | Pushed | Content |
|---|---|---|---|---|
| vettd-skill-scanner | `feat/scanner-signal-emission` | `main` | yes | `Signal` type (`crates/vettd-skill-scanner/src/signal.rs`), `SkillScanResult.signals`, HTTP shim `signals` field (omitted when empty → zero-signal runs byte-identical) |
| vettd-scanner-suite | `feat/scanner-signal-emission` | `main` | yes | `AssetSignal` contract (`src/contract/asset-signal.ts`), `ScannerOutput.signals?` (`src/contract/scanner.ts`), vettd adapter passthrough (`src/adapters/vettd.ts`) |
| vettd-cli | `feat/cli-scanner-field-gate` | `main` | yes | `BLOCKED.md` → now a decision record: #243 gate rule = **mechanism + recorded additive leaning**; mechanism NOT yet implemented (deferred) |

## Per-repo exit readiness

- **vettd-skill-scanner — READY (YES).** CI green (`cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test`). Commits: `e59f952`, `5dcad9e`, `ad4c498`.
- **vettd-scanner-suite — READY (YES).** CI green (`pnpm lint`, `pnpm typecheck`,
  `pnpm test` — 160 pass, `pnpm build`). Commits: `b5a50b9`, `4f11849`.
- **vettd-cli — NOT-YET.** #243's gate rule is now DECIDED (mechanism + additive
  leaning) but the mechanism itself is not implemented — deferred per follow-up scope
  ("no new implementation"). The branch carries only the decision record. Smoke-testing
  the signal path does not depend on the CLI branch.

## Notes for the smoke-test pick-up

- **Zero-signal byte-identity** is the key AC to verify: a run with no signals must omit
  the `signals` key at the shim (`skip_serializing_if = "Vec::is_empty"`) and at the
  suite (`signals?: AssetSignal[]`, adapter only copies `body.signals` when present).
- **Field mapping** matches the vettd wire contract: 4 required fields `dataCategory`,
  `sourceClass`, `ruleId`, `observedAt`; everything else optional; open strings, no
  closed enums; `observedAt` survives unmodified (never converted to a Date in the
  adapter).
- **Pre-existing duplicate branches:** `feat/signal-emission-path` exists on
  `origin` in vettd-skill-scanner and vettd-scanner-suite with identical trees (the
  earlier naming). Left untouched per no-branch-deletion rule; can be cleaned up by a
  human if desired.
- **Release order:** not yet documented anywhere (remaining #925 AC). The additive
  optional `signals` shape is forward/backward compatible: vettd deploys first or the
  crate first, neither side breaks — but the AC wants this written down.
- No containers or long-running processes were started by this work; shared dev
  Postgres (`vettd-wt-signals-db`) untouched.