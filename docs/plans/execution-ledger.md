# Execution Ledger — hardening/remaining-jira-findings

Status: ACTIVE — orchestrator-owned. Update after every contract gate, child creation, integration, and review cycle.

## Anchors

| Item | Value |
| --- | --- |
| Base commit (main HEAD at start) | `237ef56f798a886d33b9b761cd0172184193bbf7` |
| Integration branch | `hardening/remaining-jira-findings` |
| Integration worktree path | `/var/home/displacer/Projects/personal/spotter.hardening-remaining-jira-findings` |
| Plan file | `docs/plans/remaining-jira-findings.md` (integrated branch copy) |
| Plan SHA-256 (source) | `5f1bd50019b3643dcf7955b3992a9bd51249834eae8eeba3f59f88afecd8bb4a` |
| Plan SHA-256 (integration copy) | `5f1bd50019b3643dcf7955b3992a9bd51249834eae8eeba3f59f88afecd8bb4a` |
| Hash comparison | IDENTICAL |
| First integration commit | `2682885523572e46f71dac5b2ee82c7c26e27620` (AGENTS.md scope reconciliation + plan record) |
| Worktrunk | v0.76.0; worktree created with `--no-cd --no-hooks` (no project/user wt config exists; hook approval not required) |
| `.worktrees/` isolation | pre-existing operator worktree `.worktrees/hardware-collector-fix` preserved untouched; nested `.worktrees/.gitignore` (`*`) bootstrapped and verified with `git check-ignore` |

## Baseline results (host = Linux; native Windows evidence tracked separately)

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | PASS |
| `cargo test -p spotter-core` | PASS (47 unit tests) |
| `cargo clippy -p spotter-core --all-targets -- -D warnings` | PASS |
| `cargo check --workspace --all-targets` | PASS |
| `cargo test -p spotter-svc --all-targets --features test-support --locked` | PASS (128 tests: 126 lib + 2 owner_fsm) |
| `cargo test -p spotter-cli --features test-support --locked` | PASS (27 tests: 20 lib + 7 binary_contract) |
| `python3 scripts/test-msi-lifecycle-contract.py` | PASS |
| `python3 scripts/test_docs_contracts.py` | PASS (2 tests) |
| `python3 scripts/test-support-contract.py` | PASS (no output, exit 0) |
| `python3 scripts/test-workflow-contract.py` | PASS (7 tests) |
| `python3 -m unittest discover -s scripts/hardware -p 'test_*.py'` | PASS (34 tests) |
| `python3 scripts/check-product-identity.py` | PASS |

Baseline failures: NONE. No pre-existing failing test blocks any lane.

## Contract gates (Phase 1)

| Lane | Contract file | plan-reviewer verdict | Operator confirmation | Status |
| --- | --- | --- | --- | --- |
| A — pipe identity (SPOTR-5) | pending | pending | pending | NOT STARTED |
| B — journal recovery (SPOTR-7) | pending | pending | pending | NOT STARTED |
| C — hardware host (SPOTR-9/24) | pending | pending | pending | NOT STARTED |
| D — token ownership (SPOTR-17) | pending | pending | pending | NOT STARTED |

Fixture work (lane E) may begin only after the owning lane's contract is recorded here.

## Lane ownership

| Lane | Test registry mapping complete? | Branch | Base (integration SHA) | Exclusive files | Shared requests |
| --- | --- | --- | --- | --- | --- |
| A — IPC identity | REQUIRED BEFORE BRANCH | `hardening/lane-a-ipc-identity` | (record at creation) | `spotter-cli/src/lib.rs` (NamedPipeTransport/exchange), `spotter-win32/src/pipe.rs`, `spotter-svc/src/ipc_server.rs`, `spotter-cli/tests/named_pipe.rs`, `spotter-cli/tests/binary_contract.rs` | core identity constants changes via orchestrator |
| B — journal recovery | REQUIRED BEFORE BRANCH | `hardening/lane-b-journal-recovery` | (record at creation) | `spotter-svc/src/operation_journal.rs`, `spotter-svc/src/sync_engine.rs`, `spotter-svc/src/atomic_file.rs`, `spotter-svc/tests/owner_fsm.rs` | `service.rs` + test-support `lib.rs` via orchestrator after B gate |
| C — hardware host | REQUIRED BEFORE BRANCH | `hardening/lane-c-hardware-host` | (record at creation) | `spotter-hardware-service/**`, `.github/workflows/hardware-experiment.yml`, `scripts/hardware/collect_hardware.ps1`, hardware tests | shared Windows/path modules via orchestrator |
| D — MSI symbols | REQUIRED BEFORE BRANCH | `hardening/lane-d-msi-symbols` | (record at creation) | `installer/Product.wxs`, `scripts/test-msi-lifecycle.ps1` | release.yml/elevated-windows.yml inventories via orchestrator |
| E — token ownership | REQUIRED BEFORE BRANCH | `hardening/lane-e-token-ownership` | (must contain A+B) | `spotter-core/src/ipc.rs`, `spotter-win32/src/dpapi.rs`, CLI token reader/transport, svc line buffering, `owner_ports.rs`, `config_io.rs` | all manifests + Cargo.lock via orchestrator |
| F — docs/evidence | REQUIRED BEFORE BRANCH | `hardening/lane-f-docs` | (after all lanes) | `README.md`, `docs/*.md`, disposition report | docs contract scripts via orchestrator |

## Test registry mapping (required per lane before its branch is created)

Each registered AC test must gain: crate test target path, feature flags, exact command, workflow
job that runs it, expected evidence artifact, and status. Rows below are the registry columns
template; lanes populate their rows before branch creation, and the orchestrator verifies the
mapping is complete as a branch-creation precondition.

| AC | Proposed test | Crate target | Features | Command | Workflow job | Evidence artifact | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AC.2–AC.4 (A) | identity_fixture_actor_boundary, identity_fixture_failure_cleanup, counterfeit_server_receives_no_request_bytes, authentication_precedes_serialization, server_identity_failures_reject_before_write, installed_service_authenticates_and_reconnects, first_instance_claim_and_worker_lifetime, server_exit_during_authentication_fails_closed | `spotter-cli/tests/named_pipe.rs` + native fixture crate tests | `test-support` (windows) | `cargo test -p spotter-cli --features test-support --locked` + native service concurrency suite | `elevated-windows.yml` job `lifecycle` (windows-latest) | test log with byte-count/boolean captures + ledger probe results | pending (blocked on A contract) |
| AC.5–AC.7 (B) | journal_recovery_classification_table, unterminated_complete_record_retains_evidence, journal_truncation_prefix_property, journal_preservation_failure_is_closed, journal_recovery_crash_boundary_table, journal_quarantine_collision_preserves_original, journal_blocked_marker_survives_restart, ambiguous_tail_blocks_all_recovery_callers, ambiguous_tail_never_reissues_mutation, recovery_notice_is_bounded_and_redacted | `spotter-svc/src/operation_journal.rs` (unit) + `spotter-svc/tests/owner_fsm.rs` | default (+`test-support` for atomic faults) | `cargo test -p spotter-svc --all-targets --features test-support --locked` | `checks.yml` job `windows-workspace` | CI test log + manual `journal_operator_recovery_drill` record | pending (blocked on B contract) |
| AC.8–AC.10 (C) | hardware_fixture_unprotected_swap_control, hardware_fixture_actor_boundary, hardware_fixture_cleanup_waits_for_scm, hardware_host_rejects_unsafe_path_table, hardware_host_blocks_validation_launch_swap, hardware_trusted_layout_collection_table, hardware_key_acl_and_cleanup_contract | `spotter-hardware-service` Windows integration tests + `scripts/hardware/test_*.py` | `hardware-experiment` (windows) | `cargo check -p spotter-hardware-service --features hardware-experiment --locked` + native host run; `python3 -m unittest discover -s scripts/hardware -p 'test_*.py'` | `hardware-experiment.yml` job `matrix` (post-approval checkpoint) | workflow run artifacts + redacted evidence links | pending (blocked on C contract) |
| AC.11–AC.12 (E) | set_token_wire_shape_is_unchanged, set_token_debug_is_redacted, token_owner_clone_queue_cancel_cleanup, ipc_secret_buffer_exit_path_table, token_owner_service_failure_table, decrypted_invalid_utf8_is_wiped, dpapi_wipes_output_before_local_free | `spotter-core/src/ipc.rs` (unit), `spotter-svc` unit, `spotter-win32/src/dpapi.rs` (native), `spotter-cli/tests/binary_contract.rs` | `test-support` for CLI/DPAPI | `cargo test -p spotter-core`, `cargo test -p spotter-svc`, `cargo test -p spotter-cli --features test-support --locked`, native DPAPI suite | `checks.yml` jobs `linux-core` (pure) + `windows-workspace` (native DPAPI) | CI test logs | pending (blocked on E base = A+B) |
| AC.13–AC.15 (D) | msi_file_table_excludes_pdbs, test_msi_installed_inventory_excludes_pdbs, symbols_zip_retains_both_pdbs, release_stage_retains_symbol_inputs, direct_scm_stage_retains_executables, test_symbol_distribution_docs_match_inventory | `installer/Product.wxs` (WiX build), `scripts/test-msi-lifecycle-contract.py`, `scripts/test-msi-lifecycle.ps1` | n/a | `python3 scripts/test-msi-lifecycle-contract.py`; PowerShell MSI lifecycle on Windows runner | `checks.yml` job `package-contract` + `release.yml` job `lifecycle` (elevated) | built MSI file-table dump + symbols ZIP listing + CI logs | IN PROGRESS (lane D) |
| AC.16 (F) | hardware_approval_environment_audit (manual) | n/a | n/a | authorized read-only GitHub environment query | manual | redacted metadata snapshot + administrator confirmation or explicit blocked note | IN PROGRESS |
| AC.17 (F) | jira_disposition_audit (manual) | n/a | n/a | evidence report compilation | manual | `docs/plans/jira-evidence-report.md` | pending |
| AC.18 (—) | workspace_handoff_audit (manual) | n/a | n/a | hash comparison + branch/base/path verification | manual | ledger Anchors section | PASS |
| (AC.18 gates) | fmt/test/clippy/workspace checks | workspace | n/a | see Anchors baseline + verification gates in plan | `checks.yml` `ci-success` aggregate | CI run link | PASS (baseline) |

## Shared-edit log

| Requesting lane | Path | Resolution |
| --- | --- | --- |
| D (lane-d-msi) | `.github/workflows/release.yml` `package` job | RESOLVED 2026-09-12: orchestrator took sole release-workflow ownership per the plan's shared-edit rule; applied commit `ae5d00a` — a new "Verify symbols ZIP contains both PDBs" step expands the produced ZIP to a temp dir, asserts `spotter_svc.pdb` and `spotter_cli.pdb` exist, throws before artifact upload on absence, and always cleans the temp dir. Workflow/lifecycle/docs contracts re-run and pass. Integration-controlled edit, not part of the reviewed lane D commit; goes through the normal code-review pass with lane F. |

## Test name registry

Record approved renames here. Proposed names from the acceptance matrix are authoritative unless renamed with justification.

| AC | Proposed test | Lane | Status |
| --- | --- | --- | --- |
| AC.2 | `identity_fixture_actor_boundary` | A | pending |
| AC.2 | `identity_fixture_failure_cleanup` | A | pending |
| AC.3 | `counterfeit_server_receives_no_request_bytes` | A | pending |
| AC.3 | `authentication_precedes_serialization` | A | pending |
| AC.3 | `server_identity_failures_reject_before_write` | A | pending |
| AC.4 | `installed_service_authenticates_and_reconnects` | A | pending |
| AC.4 | `first_instance_claim_and_worker_lifetime` | A | pending |
| AC.4 | `server_exit_during_authentication_fails_closed` | A | pending |
| AC.5 | `journal_recovery_classification_table` | B | pending |
| AC.5 | `unterminated_complete_record_retains_evidence` | B | pending |
| AC.5 | `journal_truncation_prefix_property` | B | pending |
| AC.6 | `journal_preservation_failure_is_closed` | B | pending |
| AC.6 | `journal_recovery_crash_boundary_table` | B | pending |
| AC.6 | `journal_quarantine_collision_preserves_original` | B | pending |
| AC.6 | `journal_blocked_marker_survives_restart` | B | pending |
| AC.7 | `ambiguous_tail_blocks_all_recovery_callers` | B | pending |
| AC.7 | `ambiguous_tail_never_reissues_mutation` | B | pending |
| AC.7 | `recovery_notice_is_bounded_and_redacted` | B | pending |
| AC.7 | `journal_operator_recovery_drill` (manual) | B | pending |
| AC.8 | `hardware_fixture_unprotected_swap_control` | C | pending |
| AC.8 | `hardware_fixture_actor_boundary` | C | pending |
| AC.8 | `hardware_fixture_cleanup_waits_for_scm` | C | pending |
| AC.9 | `hardware_host_rejects_unsafe_path_table` | C | pending |
| AC.9 | `hardware_host_blocks_validation_launch_swap` | C | pending |
| AC.10 | `hardware_trusted_layout_collection_table` | C | pending |
| AC.10 | `hardware_key_acl_and_cleanup_contract` | C | pending |
| AC.11 | `set_token_wire_shape_is_unchanged` | E | pending |
| AC.11 | `set_token_debug_is_redacted` | E | pending |
| AC.11 | `token_owner_clone_queue_cancel_cleanup` | E | pending |
| AC.12 | `ipc_secret_buffer_exit_path_table` | E | pending |
| AC.12 | `token_owner_service_failure_table` | E | pending |
| AC.12 | `decrypted_invalid_utf8_is_wiped` | E | pending |
| AC.12 | `dpapi_wipes_output_before_local_free` | E | pending |
| AC.13 | `msi_file_table_excludes_pdbs` | D | pending |
| AC.13 | `test_msi_installed_inventory_excludes_pdbs` | D | pending |
| AC.14 | `symbols_zip_retains_both_pdbs` | D | pending |
| AC.14 | `release_stage_retains_symbol_inputs` | D | pending |
| AC.14 | `direct_scm_stage_retains_executables` | D | pending |
| AC.15 | `test_symbol_distribution_docs_match_inventory` | D/F | pending |
| AC.16 | `hardware_approval_environment_audit` (manual) | F | pending |
| AC.17 | `jira_disposition_audit` (manual) | F | pending |
| AC.18 | `workspace_handoff_audit` (manual, done Phase 0) | — | PASS (see Anchors) |

## Native Windows evidence log

Fill with command, SHA, pass/fail/skip, CI link. Host is Linux; all native Windows items remain BLOCKED until authorized run available.

| Command | Commit SHA | Result | Evidence link |
| --- | --- | --- | --- |
| (none yet) | | | |

## Post-integration local verification (2026-09-12, HEAD 671204f)

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | PASS |
| `cargo test -p spotter-core` | PASS (47) |
| `cargo clippy -p spotter-core --all-targets -- -D warnings` | PASS |
| `cargo check --workspace --all-targets` | PASS |
| `cargo test -p spotter-svc --all-targets --features test-support --locked` | PASS (126) |
| `cargo test -p spotter-cli --features test-support --locked` | PASS (20 lib + 7 binary_contract) |
| `python3 scripts/test_docs_contracts.py` | PASS (2) |
| `python3 scripts/test-msi-lifecycle-contract.py` | PASS |
| `python3 scripts/test-support-contract.py` | PASS |
| `python3 scripts/test-workflow-contract.py` | PASS (7) |
| `python3 -m unittest discover -s scripts/hardware -p 'test_*.py'` | PASS (34) |
| `python3 scripts/check-product-identity.py` | PASS |

Remaining BLOCKED native/external boundaries (explicitly not passed): actual MSI build/install/
upgrade/uninstall + file-table/installed-tree inspection and direct-SCM lifecycle (Windows runners);
native IPC identity fixtures (lanes A); native hardware fixtures (lane C); `cargo clippy --workspace`
and Windows workspace test runs; SPOTR-23 controlled dispatch; any push/PR/dispatch/Jira write.

## Integration log

| Date | Integrated | Source commit | Base used | Notes |
| --- | --- | --- | --- | --- |
| 2026-09-11 | scope commit | 2682885523572e46f71dac5b2ee82c7c26e27620 | 237ef56f | first commit on integration branch |
| 2026-09-12 | Lane D (SPOTR-28) | lane-D branch `hardening/lane-d-msi-symbols` @ `21938ea` | d8b4afc | 4 review rounds → APPROVED (0 findings); merged `3ae0bf7`; post-merge contracts pass (lifecycle/workflow/docs/identity) |

## Lane D (SPOTR-28) review + integration record

- Round 1 (`c2b7c37`): PDB components removed from `installer/Product.wxs`; negative installed-file checks added to `scripts/test-msi-lifecycle.ps1`; five acceptance-matrix contract functions added to `scripts/test-msi-lifecycle-contract.py`. code-reviewer verdict: REQUEST_CHANGES — mutation test showed symbols-ZIP contents were not statically proven (staging-name checks pass even if PDBs are deleted immediately before `Compress-Archive`).
- Round 2 (`04548d6`): `symbols_zip_retains_both_pdbs` now executes the workflow's real `Compress-Archive` command against synthetic staged PDBs, opens the produced ZIP with `zipfile`, asserts both PDBs present, rejects pre-archive deletion mutations, and binds any future post-archive verifier's coverage to both PDB names. Review finding closed at contract level.
- Shared-edit request for orchestrator: `release.yml` `package` job should add a post-`Compress-Archive` PowerShell verifier (Expand-Archive to temp; assert `spotter_svc.pdb` and `spotter_cli.pdb` exist in the extraction; throw before artifact upload on absence). Deferred to release-workflow ownership — the contract test already binds a future verifier.
- Remaining blocked native evidence: actual MSI build/install/upgrade/uninstall, built-MSI file-table inspection, installed-tree inspection, direct-SCM lifecycle on Windows runners. Tracked in Native Windows evidence log.
- Integration status: MERGED (`3ae0bf7`); post-merge contract checks pass. Worktree retained for cleanup after ledger update.

## Cleanup log

| Worktree | Branch | Disposition |
| --- | --- | --- |
| `spotter.hardening-lane-d-msi-symbols` | `hardening/lane-d-msi-symbols` | Removed 2026-09-12 via `wt remove --foreground --no-delete-branch --no-hooks` (clean, integrated at merge `3ae0bf7`, tip `21938ea` verified ancestor of integration HEAD). Branch RETAINED — not merged to `main`; no force-delete used. |
