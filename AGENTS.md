# SnipeSpotter contribution conventions

## Scope

Phase 0 established the workspace, stable identity values, policy, and CI scaffolding. Phase 1 behavior is authorized for this branch (`hardening/remaining-jira-findings`): the operator explicitly approved remediating the already-implemented product's security findings (SPOTR-5, -7, -9, -17, -28) and hardening the experimental security boundaries, per the reviewed plan in `docs/plans/remaining-jira-findings.md`. Unrelated feature or phase expansion remains out of scope.

## Rust

- Use Rust 2024 and the workspace MSRV.
- Keep dependency versions exact and declare shared versions in the root `[workspace.dependencies]` table.
- Run `cargo fmt --all --check`, `cargo test -p spotter-core`, and `cargo clippy -p spotter-core --all-targets -- -D warnings` before handoff.
- Keep Windows-only dependencies under `target.'cfg(windows)'.dependencies`.
- Runtime Rust files must declare their FCIS classification with a `// pattern:` comment.
- Keep `spotter-core` platform-neutral; isolate Windows APIs in `spotter-win32`, `spotter-build`, and the Windows service/CLI crates.

## CI and policy

- Keep GitHub Actions references immutable; third-party actions must use full commit SHAs.
- Preserve the reusable checks workflow and its aggregate `ci-success` job.
- Keep `deny.toml` restrictive for advisories, licenses, sources, and dependency duplication.

## Scripts

- PowerShell recon scripts are Phase 0 scaffolds only.
- Scripts should use strict mode, fail on errors, and emit machine-readable output when they gain behavior.
