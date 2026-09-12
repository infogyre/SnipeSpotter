# Remaining Jira findings: orchestration handoff

## Goal

Address SPOTR-5, SPOTR-7, SPOTR-9, SPOTR-17 and SPOTR-28 through reviewed implementation and native verification; establish an evidence-based disposition for SPOTR-23/24 while leaving SPOTR-10 open until the first stable release. Deliver an isolated integration branch and issue-specific evidence report, not an automatically published release or main-branch merge.

## Implementation Summary

Create the integration worktree first, approve security contracts and build missing Windows fixtures, implement independent lanes, integrate authentication and journal recovery before cross-cutting token ownership changes, then validate packaging, documentation and external evidence. The acceptance matrix below defines completion; the lane prose supplies implementation detail.

## Mandate and first actions

Target facet: `orchestrate`. Read this plan, establish a dependency-aware to-do list, **then make your first execution task creation of a primary Worktrunk worktree and enter it**. Perform implementation and create additional isolated subagent Worktrunk worktrees from that integration worktree. Child worktrees are branches based on the integration branch, not physically nested repositories. Do not start implementation in the source `main` worktree.

The operator requested this multi-phase plan and delegated implementation division to the orchestrator. During planning they explicitly authorized hardening the implemented product despite stale Phase 0 instructions, and selected the policies below. This is not permission to publish releases, push branches, merge to main, alter GitHub administrative settings, or change Jira statuses. Obtain explicit approval for those external actions. Local task-branch commits/integration may be used with reviewed, named-path staging; preserve the source tree.

## Inventory and operator decisions

Source: live Jira `SPOTR` project, queried during this planning session with `project = SPOTR AND statusCategory != Done ORDER BY priority DESC, key ASC`; returned `isLast=true`, ten issues: eight findings plus two umbrellas. Read every finding's subsequent comments; superseding triage takes precedence over original suggested fixes. Repository inspected on `main`; initial untracked `.worktrees/` belongs to the operator. No application changes or test runs were made during planning.

| Issue | Disposition and success boundary |
| --- | --- |
| [SPOTR-5](https://infogyre.atlassian.net/browse/SPOTR-5) | Implement authenticated pipe-server identity and endpoint ownership. Identification SQOS is already implemented and has Windows evidence from run 34194527955; it does not prevent token theft. |
| [SPOTR-7](https://infogyre.atlassian.net/browse/SPOTR-7) | Implement evidence-preserving, operator-visible incomplete-journal-tail recovery. Never silently discard an ambiguous outcome/candidate transition. |
| [SPOTR-9](https://infogyre.atlassian.net/browse/SPOTR-9) | Harden experimental LocalSystem execution paths against standard-user modification and replacement races. |
| [SPOTR-17](https://infogyre.atlassian.net/browse/SPOTR-17) | Best-effort cleanup of application-owned plaintext token buffers, including DPAPI allocation and failure/cancellation paths. |
| [SPOTR-28](https://infogyre.atlassian.net/browse/SPOTR-28) | Operator selected: remove installed MSI PDBs; retain public symbols ZIP. This is packaging policy, not symbol confidentiality remediation. |
| [SPOTR-23](https://infogyre.atlassian.net/browse/SPOTR-23) | Verify external hardware approval configuration; preserve intentional post-observation checkpoint. Infrastructure-dependent, not an assumed code defect. |
| [SPOTR-24](https://infogyre.atlassian.net/browse/SPOTR-24) | Operator selected: retain administrator trust and SYSTEM-read/Administrators-full-control ephemeral-key policy. Document acceptance and test lifecycle within SPOTR-9; do not blindly change F to R. Recommend disposition, not an automatic Jira transition. |
| [SPOTR-10](https://infogyre.atlassian.net/browse/SPOTR-10) | Operator explicitly requires issue remain open. Defer release approval-gate change until first stable release; record that trigger. Preserve publication topology now. |
| SPOTR-4 / SPOTR-29 | Umbrella tracking issues, not two additional implementations. Do not close them en masse, particularly while SPOTR-10 remains open. |

Do not expand into already completed findings, log-size enforcement, physical-hardware qualification, new inventory behavior, or general refactoring.

## Implementation Plan

### Execution ledger and path ownership

After contract approval, record the integration commit SHA used by each child, exclusive paths, shared-edit requests and review result in an execution ledger. A lane's writing branch may be created only after its own design gate is recorded; read-only investigation may proceed earlier. Suggested merge order is foundation/fixtures, A, B, C, D, token lane E, documentation/evidence F. Independent approved lanes may develop concurrently but integration is serial. E branches from a base containing A and B plus all approved manifest prerequisites.

| Owner | Exclusive work | Shared/integration-controlled work | Gate/base |
| --- | --- | --- | --- |
| Foundation/orchestrator | AGENTS scope, reviewed design note, ledger, fixture coordination | Root/crate manifests, Cargo.lock, shared test-support modules | Phase 0 baseline and relevant Phase 1 approvals |
| A: IPC identity | CLI transport/native tests, win32 pipe identity helper, svc IPC instance lifecycle | Core identity changes and new Windows features requested centrally | Approved A contract + identity fixture commit |
| B: journal | Journal parser/repair, sync recovery, journal/owner tests | `service.rs`, service test-support `lib.rs`, atomic helper changes | Approved B state table + foundation |
| C: hardware | Hardware service/path tests, collector, hardware contract tests | Hardware workflow and shared Windows/path modules | Approved C policy + staging fixture commit |
| D: MSI | WiX PDB components, MSI lifecycle inventory/contract tests | Release/elevated workflows and packaging docs | Operator symbols decision + foundation |
| E: token ownership | Core IPC secret field, DPAPI, CLI/service token ownership and all callers/tests | All manifests/lockfile; `service.rs` after B | Approved D ownership contract + A/B integrated |
| F: docs/evidence | README, architecture/operator/CI/hardware docs, disposition report | Documentation contracts and external evidence | Integrated affected implementations |

No two children own the same shared path concurrently. The orchestrator either applies a child's explicit shared-edit patch after its owner finishes, or temporarily grants sole ownership in the ledger. Workflow edits, installer shared expectations and all manifest/lockfile regeneration are serialized. If a child needs another lane's file, stop that edit and request ownership rather than silently expanding scope.

## Phase 0 — isolated workspace and baseline

1. After reading this plan and creating todos, load `worktrunk` and `subagent-git-safety`. Inspect `wt --version`, `wt switch --help`, relevant project/user Worktrunk configuration and hook bodies. Inspect only non-secret configuration; do not source environment files or print credentials. Preserve existing `.worktrees/` contents and operator changes. Use the installed CLI's flags, not assumed flags.
2. Record the source HEAD as explicit base. Create a unique integration branch/worktree, suggested `hardening/remaining-jira-findings`, using `wt switch --create <branch> --base <base>` and supported noninteractive options. If local worktree paths are configured, inspect existing local ignore boundaries before creating anything; use file tools for any local ignore file, preserve conflicting contents, and verify exclusion with `git check-ignore`. Do not rewrite tracked `.gitignore` just for worktree isolation. Stop for operator review if hooks require approval; never auto-approve with `--yes`.
3. Resolve the actual path by exact branch lookup (`wt` supported listing, otherwise read-only `git worktree list --porcelain`), then `pushd` into that path. Verify expected branch and clean baseline. A shell's `wt switch` does not prove the harness directory changed.
4. The reviewed plan is an uncommitted file in the source worktree, not a saved-session active plan, and may not exist in the committed base. Record its SHA-256 before copying, carry its complete contents into the integration worktree with file tools, then compare both hashes. Record the verified hash/base/path in the execution ledger; stop if the copy differs. Leave the source copy and pre-existing files intact. Do not use broad staging.
5. Reconcile `AGENTS.md` scope narrowly in the integration branch: operator-authorized remediation of the already implemented product and experimental security boundaries is in scope; unrelated feature/phase expansion remains out of scope. Preserve Rust, platform-boundary, exact-dependency, CI and script conventions.
6. Establish focused baselines: required core fmt/test/clippy, relevant journal tests, script contracts and Windows compile/runtime availability. Record exact commands/results and existing failures. A baseline failure blocks affected implementation pending diagnosis/operator decision, not unrelated read-only work. Inventory available native Windows/elevated CI execution; Linux cross-compilation is not native security evidence.

## Phase 1 — reviewed contracts before cross-cutting edits

Assign bounded read-only design/research tasks, then consolidate decisions in one short design note. Use current Microsoft/Rust API documentation for Windows identity, handle lifetime, first-instance semantics and ACL/reparse behavior. Use `researcher` with explicit external/local scope. These are design tasks, not permission to invent an authentication protocol.

### A. Pipe identity contract (SPOTR-5)

Prefer OS-backed authentication of the *connected pipe handle* to the expected SCM-managed LocalSystem service, with a retained process handle/identity and stable service identity checks. Evaluate service PID binding, service account, executable trust, process exit/PID reuse and endpoint restart races together; PID-only, image-path-only, DACL-only, or another predictable mutex is insufficient. Explicitly state the boundary against a standard-user counterfeit server; do not claim protection against an administrator who controls SCM/binaries/the machine.

Authenticate before serializing/writing any command bytes to an untrusted endpoint. Preserve `SECURITY_IDENTIFICATION`. Define bounded errors for service stopped, starting, restarting, inaccessible identity, unexpected identity and malicious endpoint. Design first-instance ownership without breaking concurrent accepts/reconnects or creating a gap while workers retain instances. Keep production validation mandatory; test-support identity injection must not become a release bypass.

If OS-backed binding cannot meet the threat model, stop for operator approval of an alternative durable trust/protocol design. Do not reuse the state HMAC key, API token, or add a speculative cryptographic handshake.

### B. Journal recovery contract (SPOTR-7)

Separate pure byte/framing/sequence classification from filesystem repair. Define complete malformed record, corrupt middle record, incomplete unterminated suffix, valid JSON without terminal newline, and semantically invalid phase sequence separately. A missing newline alone is not proof an operation never happened. Preserve usable complete JSON evidence where safe; quarantine ambiguous evidence instead of automatically treating it as absent.

Before repair, preserve the original bytes in a protected, discoverable quarantine artifact with collision-safe naming. Validate the complete prefix and operation phase sequence. Define crash/retry behavior between preservation, replacement and recovery; failed preservation or replacement fails closed without loss of original evidence. Use existing atomic replacement, not append over a fragment. Establish bounded quarantine retention without automatic evidence deletion in this change.

Document how ambiguous prepare/outcome/candidate/commit tails affect existing pending-operation reconciliation: replay must never blindly reissue remote mutations or accept an unverified candidate state. Where safe automatic reconciliation is impossible, expose actionable operator recovery and remain fail-closed. Define operator-visible log/status notice and handling by startup, compaction and identity-change guards. Generic reads should not silently repair files.

#### Required recovery state table

Approve a concrete internal result equivalent to `Clean(records)`, `NeedsOperatorRecovery(reason, evidence_paths, validated_prefix)`, or `Corrupt(reason, original_path)`, plus typed I/O failure. Names are provisional; behavior below is the conservative default requiring operator approval at the design gate. Prefix data in a blocked result is diagnostic evidence, not authorization to replay. This deliberately prefers explicit recovery over an unproven automatic truncation fix.

| Input class | Preservation / active journal | Startup and remote activity | Compaction / identity change |
| --- | --- | --- | --- |
| Empty or valid newline-terminated sequence | No repair | Normal existing verified recovery and owner startup | Existing safeguards |
| Valid complete JSON without newline, valid full sequence | Preserve original before atomic newline normalization; retain the final record as evidence | Continue only after durable normalization and full sequence validation; existing recovery rules still apply | Allowed only after successful normalization/recovery |
| Incomplete unterminated JSON suffix with valid prefix | Preserve original; create discoverable recovery marker before any active replacement; never erase ambiguous suffix evidence | `NeedsOperatorRecovery`; block owner/IPC startup and all remote mutations, emit bounded redacted actionable service log/SCM failure | Both reject until explicit operator recovery clears ambiguity |
| Malformed newline-terminated final record or malformed middle record | Preserve original untouched; corruption diagnostic | Fail closed; no replay or owner exposure | Reject |
| Invalid phase sequence, including otherwise valid unterminated final JSON | Preserve original untouched | Fail closed; no replay | Reject |
| Preservation/marker/normalization I/O failure | Keep original/evidence; fail closed | No replay or owner exposure | Reject |

A blocked marker must survive restarts and dominate a seemingly valid active prefix; compaction, identity-change guards and every startup entry point must check it. Prove repeated restart cannot silently convert blocked recovery into clean state. Because the default blocks IPC startup, do not promise an IPC status endpoint: service logs and SCM failure carry the notice. Define a documented administrator recovery procedure that retains quarantine, validates remote outcomes and signed candidate state, and permits marker removal only after reconciliation. Any proposal to allow read-only degraded IPC or automatic ambiguous-tail reconciliation is a separate reviewed/operator-approved design change. Acceptance may therefore produce safe operator-assisted recovery rather than automatic availability for ambiguous evidence; confirm this tradeoff before implementation.

### C. Protected experiment execution contract (SPOTR-9/24)

Define a dedicated per-cell protected staging root and explicit ownership/rights for config, collector, service executable, key and output directory. Retain the approved key ACL policy. Define allowlisted native Windows/system PowerShell dependencies; legitimate trusted OS ownership such as TrustedInstaller may need a distinct rule rather than blanket SYSTEM/Admin-only rejection.

Validate paths before config read, before SCM registration, and at service consumption—not only after parsing attacker-controlled configuration. Include containment, parent-chain traversal/reparse checks, owner/effective-write control, existing output objects, and identity/race handling. Protected parents or retained validated handles must prevent standard-user swaps between check and use; a second pathname check alone is not a race defense. Keep the current admin trust boundary, and document unavoidable administrator control.

### D. Token ownership contract (SPOTR-17)

Agree on a redacted, drop-zeroizing secret owner that preserves existing SetToken JSON wire shape. Cover queued/cloned/cancelled commands, serialization, CLI input, raw server line, decoded command, DPAPI-owned output and decrypted UTF-8 conversion errors. Minimize copies; do not assume every String/SecretString conversion copies. Coordinate manifests/API ownership centrally; prefer established zeroizing types over custom unsafe wiping.

Use a concrete replacement map in the approved design: DPAPI decrypt and `SecretProtector::decrypt` return an established zeroizing byte owner; `owner_ports` and `config_io` consume that owner into a redacted secret string with explicitly wiped invalid-UTF8 error bytes; CLI TokenReader and SetToken own a redacted zeroizing string; raw/serialized IPC bytes use zeroizing owners. Encryption may continue borrowing plaintext and returning ordinary ciphertext. Preserve the JSON field type/shape through intentional serde conversion, without retaining a parallel plain-String API. Enumerate all `SecretProtector` implementations/fakes, command clones, queue/channel drop paths and conversion callers with LSP references, and migrate them in lane E as one contract replacement. Any unavoidable library-owned temporary is documented rather than falsely counted as wiped.

### E. Missing native test infrastructure (prerequisite to A/C)

These fixtures do not currently exist. Assign explicit fixture-building tasks after the associated design approval and before production security changes; prove each harness observes the insecure baseline with regression tests, then make those tests pass with implementation.

- **IPC fixture:** an isolated installed LocalSystem service with unique SCM/pipe identity, a disposable standard-user actor launching a counterfeit server, an elevated CLI actor, connected-handle identity-query seam for deterministic failure/process-exit/PID-mismatch injection, and capture that reports only byte counts/booleans—not token contents. Verify actor SIDs/elevation and assert zero command bytes received on rejection. Instrument serialization ordering separately from pipe capture. Integrate into existing elevated Windows lifecycle infrastructure; same-account tests remain supplements. Fixture teardown stops/removes services and actors even on failure, with bounded waits.
- **Hardware fixture:** a protected per-cell staging root, administrator setup/cleanup and standard-user mutation actors, controllable config/collector/key/output paths, reparse/ancestor/output-redirection constructors, and synchronization barriers at validation/launch for attempted swaps. Assert actor identity, fixture setup and cleanup after SCM disappearance. Use condition signals rather than sleeps; demonstrate the mutation succeeds in an intentionally unprotected fixture so a passing denial test is meaningful. Keep fixture execution isolated from real service/data paths.
- Store proposed new native tests under the appropriate crate's Windows integration tests and elevated script support. Foundation owns shared support APIs and workflow wiring; A/C own their scenario tests. Record exact test names/commands in the ledger, use the acceptance matrix's proposed names unless review justifies renaming, and wire them into an authorized native/elevated run.

**Gate:** obtain `plan-reviewer`/security-focused review of A–D and operator confirmation of any unresolved durable interface, recovery policy or trust-model change before implementing it. Preserve the reviewed contract in integration so child branches share one base. An unresolved lane can remain blocked while independent approved lanes proceed.

## Phase 2 — first implementation wave

Orchestrator chooses agent count and split based on capacity. Each writing agent gets a separate Worktrunk worktree created from an explicit integration commit, absolute `cwd`, expected branch, file ownership and prerequisites. Suggested lanes:

### Lane A — authenticated IPC (SPOTR-5)

Primary files: `spotter-cli/src/lib.rs` (NamedPipeTransport/exchange), `spotter-svc/src/ipc_server.rs` (instance lifecycle), `spotter-win32/src/pipe.rs`; existing identity constants in `spotter-core/src/identity.rs`; tests `spotter-cli/tests/named_pipe.rs`, `binary_contract.rs`, service native pipe tests and elevated lifecycle support.

Implement reviewed identity and first-instance design, preserving deadlines/concurrency and current DACL/SQOS. Tests must reject a native standard-user counterfeit endpoint before any request/token bytes are sent, reject wrong service/process identity and identity-query failures, and accept genuine installed LocalSystem service, reconnects and concurrent clients. Test service stop/start, competing first-instance claim and instance creation during active workers. Keep existing impersonation-level and ACL tests. Same-account fake tests supplement, not replace, cross-principal installed-service evidence.

### Lane B — evidence-preserving recovery (SPOTR-7)

Primary files: `spotter-svc/src/operation_journal.rs`, `sync_engine.rs`, startup/recovery portions of `service.rs` and test-support `lib.rs`; existing `atomic_file.rs`; `spotter-svc/tests/owner_fsm.rs`.

Implement the reviewed classification/preservation/repair/reconciliation contract. Cover empty/valid journal, each byte-truncation boundary for representative phases, valid final JSON without newline, malformed complete final record, malformed middle record, invalid prefix sequence, quarantine collision/failure, replacement failure, repeated restart, interrupted repair, and pending-operation/candidate-state preservation. Property tests are appropriate for prefix preservation and framing classification. Demonstrate no duplicate remote mutation after an ambiguous tail. Compaction and identity guards must not mistake quarantined ambiguity for clean state. Expose the documented recovery notice and remediation without leaking tokens or upstream raw bodies.

### Lane C — protected experimental host (SPOTR-9, SPOTR-24 policy)

Primary files: `spotter-hardware-service/src/main.rs`, relevant Windows helper/manifests, `.github/workflows/hardware-experiment.yml`, `scripts/hardware/collect_hardware.ps1`, hardware workflow/privacy/collector tests; reuse existing `scripts/TestSupport` concepts where suitable rather than assume product ProgramData ACL helpers fit unchanged.

Stage trusted inputs and support executable, protect the root, verify the reviewed path contract, consume only trusted inputs, and validate output before report parsing/upload. Preserve diagnostic-only status and post-matrix approval ordering. Native negative tests: standard-user-writable config/collector/ancestor, bad owner/effective ACE, reparse at each relevant component, out-of-root path, output-file redirection and attempted replacement during use. Positive tests: supported runner/PowerShell layouts, SYSTEM collection, admin collection, expected reports, normal/failure cleanup with SCM disappearance before file/root deletion. Keep SYSTEM:R/Administrators:F key semantics and verify them rather than claim a new boundary against administrators.

### Lane D — MSI symbols separation (SPOTR-28)

Primary files: `installer/Product.wxs`, `scripts/test-msi-lifecycle.ps1`, MSI/workflow contract tests; consult `.github/workflows/release.yml` and `elevated-windows.yml` for shared stage/symbols/direct-SCM inventories.

Remove PDB components from installed MSI and adjust installed-file assertions. Preserve PDB build/staging inputs required by the public symbols ZIP, the existing release inventory/checksums, and any executable payload needed by direct-SCM tests. Do not remove PDBs from all staging indiscriminately. Inspect the built MSI file table and installed tree for absence; inspect the symbols ZIP for intended PDB presence; run install/upgrade/uninstall and direct-SCM lifecycle tests. Update packaging language to distinguish installed payload from public debugging artifacts; no private channel and no confidentiality claim.

## Phase 3 — integrate first wave, then token cleanup

Review each lane before integration with `code-reviewer`; route findings through `bug-fixer` in isolated worktrees and re-review until zero unresolved findings. Integrate reviewed commits serially into the primary worktree, recording source/base/commit and resolving conflicts there. Re-run affected checks after each integration.

Begin SPOTR-17 implementation on a fresh child worktree **after A and B integrate**, since it touches both transport and service command ownership. Lane C/D may finish independently, but shared manifest/lockfile and documentation edits have a single integration owner.

SPOTR-17 files: `spotter-core/src/ipc.rs`; CLI token reader/transport; service IPC line buffering, `service.rs`, `owner_ports.rs`, `config_io.rs`; `spotter-win32/src/dpapi.rs`; root and affected crate manifests. Check existing pinned `secrecy`/transitive `zeroize`; apply dependency-management research and exact direct dependency declarations where needed, without unrelated upgrades.

Implement drop-based cleanup for application-owned input/serialized/decrypted buffers, including errors, timeouts and dropped queued commands. Wipe valid DPAPI output allocations before LocalFree via safe RAII, respecting pointer/length validity on failed API calls. Zeroize UTF-8 conversion error-owned bytes. Preserve redacted Debug/errors and the wire protocol; no secret-bearing traces. Authentication must still precede sending bytes.

Tests: success and malformed/oversized/unterminated/timeout requests; serialization/write/flush failures; dropped/cloned/queued requests; encryption/client-construction/settings-save failures; invalid decrypted UTF-8 and native DPAPI roundtrip/error cleanup. Use observable safe wipe-before-free seams, not freed-memory reads or process-memory scans. Preserve auth, binary CLI and bearer-auth regressions. Claim best-effort application-owned cleanup only, not complete OS/library/allocator memory erasure.

## Phase 4 — documentation, external evidence and final validation

A single documentation/integration owner updates `README.md`, `docs/architecture.md`, `docs/operator-guide.md`, `docs/ci-guide.md`, and hardware policy where touched. Describe auth trust boundary, journal recovery/operator action, zeroization limits, MSI-versus-public-symbol policy and retained key permissions. Run documentation contracts. Record SPOTR-10 as open/deferred until first stable release; neither add a publish environment nor change tag/publication flow in this plan.

For SPOTR-23, use authorized read-only GitHub administration access or request administrator evidence: environment existence, required reviewers, self-review/bypass behavior and appropriate ref restrictions. Missing tool/permissions or absent evidence means **unverified/blocked**, not absent protection. Preserve `needs: matrix`, exact acknowledgement and diagnostic-only policy. Any change to external settings or controlled workflow dispatch requires operator approval. Verify a controlled run actually pauses at the existing checkpoint before approval; report limitations if unavailable. No automatic promotion or pre-run gate.

## Acceptance Criteria

All test names below are **proposed new tests unless explicitly marked existing**; they are implementation deliverables, not claims that tests exist or passed. Each parameterized case must report separately. Record any approved renamed test and its command against the same AC in the ledger. No AC is complete from prose or compilation alone.

| ID | Independently verifiable criterion | Named regression test / evidence |
| --- | --- | --- |
| AC.1 | Worktree/hash/base/ownership boundary established before writing children | Manual `workspace_handoff_audit`: source/destination SHA-256 equality, exact branch/base/path and clean child status records |
| AC.2 | Fixture actors really span standard user/elevated client/LocalSystem, isolated resources and failure-safe teardown | Native `identity_fixture_actor_boundary` and `identity_fixture_failure_cleanup` |
| AC.3 | Counterfeit/wrong/unqueryable connected server receives no commands; auth precedes serialization/write | Native `counterfeit_server_receives_no_request_bytes`; seam `authentication_precedes_serialization`; parameterized `server_identity_failures_reject_before_write` |
| AC.4 | Genuine service/reconnect/concurrency and first-instance lifetime remain correct | Native `installed_service_authenticates_and_reconnects`, `first_instance_claim_and_worker_lifetime`, `server_exit_during_authentication_fails_closed`; existing `named_pipe_client_limits_impersonation_level` and native concurrency suite |
| AC.5 | Journal classes obey every row in recovery state table, preserving final complete record evidence | `journal_recovery_classification_table`, `unterminated_complete_record_retains_evidence`, `journal_truncation_prefix_property` |
| AC.6 | Original/quarantine/marker survive repair failure, collisions and restart without clean-state misinterpretation | `journal_preservation_failure_is_closed`, `journal_recovery_crash_boundary_table`, `journal_quarantine_collision_preserves_original`, `journal_blocked_marker_survives_restart` |
| AC.7 | Ambiguous recovery never replays remote mutations, compacts or changes identity; operator recovery is actionable | `ambiguous_tail_blocks_all_recovery_callers`, `ambiguous_tail_never_reissues_mutation`, `recovery_notice_is_bounded_and_redacted`; manual `journal_operator_recovery_drill` using retained synthetic evidence and verified remote/candidate state |
| AC.8 | Hardware fixture can exercise mutations and clean isolated SCM/root resources reliably | Native `hardware_fixture_unprotected_swap_control`, `hardware_fixture_actor_boundary`, `hardware_fixture_cleanup_waits_for_scm` |
| AC.9 | Host rejects unsafe objects before use and defeats standard-user path swaps | Native parameterized `hardware_host_rejects_unsafe_path_table` (owner/ACE/ancestor/reparse/containment/output cases) and `hardware_host_blocks_validation_launch_swap` |
| AC.10 | Trusted layouts collect/validate reports with approved key ACL and failure-safe cleanup | Native `hardware_trusted_layout_collection_table`, `hardware_key_acl_and_cleanup_contract`; authorized hosted workflow run evidence including SYSTEM actor |
| AC.11 | All affected secret ports use approved owners without wire/Debug regression | `set_token_wire_shape_is_unchanged`, `set_token_debug_is_redacted`, `token_owner_clone_queue_cancel_cleanup`; workspace compile/tests cover every migrated trait implementation |
| AC.12 | Owned raw/decoded/serialized/DPAPI buffers are wiped on success and failure before release | `ipc_secret_buffer_exit_path_table`, `token_owner_service_failure_table`, `decrypted_invalid_utf8_is_wiped`, native `dpapi_wipes_output_before_local_free`; existing DPAPI/CLI/bearer regression suites |
| AC.13 | Both service and CLI PDBs absent from MSI file table and installed tree | Packaging `msi_file_table_excludes_pdbs`; updated `scripts/test-msi-lifecycle.ps1` negative installed-file checks; static `test_msi_installed_inventory_excludes_pdbs` |
| AC.14 | Both PDBs remain in public symbols ZIP; stages/direct-SCM payload and release inventory preserved | `symbols_zip_retains_both_pdbs`, `release_stage_retains_symbol_inputs`, `direct_scm_stage_retains_executables`; existing direct-SCM lifecycle and release closed-inventory checks |
| AC.15 | Packaging docs/contracts and upgrade/uninstall agree with symbols separation | `test_symbol_distribution_docs_match_inventory`; existing MSI install/upgrade/uninstall flow and `scripts/test-msi-lifecycle-contract.py`, especially installed inventory assertion formerly at lines 190–203 |
| AC.16 | SPOTR-23 external policy genuinely verified or explicitly blocked | Manual `hardware_approval_environment_audit`: redacted read-only metadata, reviewer configuration, self-review/bypass/ref restrictions, expected-policy administrator confirmation; authorized controlled run URL/SHA/checkpoint waiting/approval evidence |
| AC.17 | Approved issue dispositions and external-write boundaries honored | Manual `jira_disposition_audit`: SPOTR-10 open/deferred first stable release, SPOTR-24 retained-policy recommendation, SPOTR-28 public-symbol caveat, SPOTR-23 unverified if evidence absent; explicit approvals recorded before any external mutation |
| AC.18 | Integrated branch passes affected repository gates and zero-finding review | Command log below plus final code-review report; skipped native/infrastructure checks remain blocked and prevent claiming corresponding finding complete |

## Test Strategy

Build missing native fixtures explicitly, then use regression-first tests per AC, including negative controls. Unit tests cover pure policy, deterministic failure injection and ownership; native cross-principal fixtures cover Windows behavior; artifact inspection covers packaging; manual administrative evidence covers external controls. These evidence classes are not interchangeable. The journal state table and secret ownership interfaces remain design-gated; acceptance tests encode the operator-approved final contract.

### Verification gates

Run repository-pinned tools. Minimum required local commands:

- `cargo fmt --all --check`
- `cargo test -p spotter-core`
- `cargo clippy -p spotter-core --all-targets -- -D warnings`
- Targeted service/journal/IPC tests supported on the host.
- Existing script checks selected from `scripts/test-msi-lifecycle-contract.py`, `test-support-contract.py`, `test-workflow-contract.py`, `test_docs_contracts.py`, and `python3 -m unittest discover -s scripts/hardware -p 'test_*.py' -v`; check their current invocation contracts first.
- Product identity, dependency policy and coverage gates from current reusable checks workflow when affected; exact direct dependencies, restrictive `deny.toml`, immutable action SHAs and `ci-success` remain intact.

Required native Windows evidence for affected paths:

- `cargo test --workspace --all-targets`
- `cargo test -p spotter-svc --all-targets --features test-support --locked`
- `cargo test -p spotter-cli --test binary_contract --features test-support --locked`
- Native CLI named-pipe auth/SQOS tests with required test-support feature, plus native service concurrency tests.
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo check -p spotter-hardware-service --features hardware-experiment --locked` plus actual native security tests/host run (compile check alone is insufficient).
- PSScriptAnalyzer and current PowerShell/Python contracts; elevated installed MSI/LocalSystem/standard-user tests; hardware experiment positive/negative path tests and cleanup; built MSI and symbols ZIP inspection.

Record commands, commit SHAs, pass/fail/skip, CI links and native evidence separately. Linux compilation cannot close Windows security/lifecycle acceptance. Do not publish a release to test packaging. If CI access requires a push/PR/dispatch, request approval and report the blocked boundary rather than silently weakening gates. Static/mutation tests cannot substitute for runtime ACL/identity/race evidence.

## Review Strategy

Review Phase 1 contracts and fixture architecture before affected implementation. Review each lane against its AC mapping, then review integrated changes after token ownership and documentation merge. Use `code-reviewer`, isolated `bug-fixer`, and re-review until no unresolved findings. Reviewer must inspect test adequacy and actual native evidence, not merely count named tests. Record any AC blocked by infrastructure separately from code readiness.

## Documentation Strategy

The single documentation owner updates README (installed PDB claim near line 16), operator guide (installed inventory near line 26), CI guide (packaging/staging near lines 138–165), architecture and hardware policy. Update `scripts/test_docs_contracts.py` and packaging assertions in `scripts/test-msi-lifecycle-contract.py` alongside those claims; references are planning anchors, not stable line numbers. Product.wxs service/CLI PDB components and the lifecycle installed-file inventory change together, while release/elevated symbol staging and direct-SCM extraction remain intact. Record security boundaries, recovery procedure and policy dispositions with evidence links, not secret material.

## Risks, Blockers, and Required Decisions

- OS-backed service authentication and journal recovery semantics require a design review and operator approval of final durable contracts; this plan does not pre-authorize an unreviewed protocol or destructive recovery.
- Incomplete journal evidence may require operator-assisted recovery rather than transparent startup; obtain explicit acceptance of the state table before implementing that tradeoff.
- Native elevated/cross-principal Windows fixtures do not yet exist. Their implementation and successful authorized execution are mandatory deliverables for affected findings, not optional follow-ups.
- Hardware path rules must accept legitimate runner/system layouts without granting standard-user write access; protected ancestor and race behavior require real Windows evidence.
- External environment policy values need administrator confirmation. Missing access or evidence blocks SPOTR-23 verification. Any GitHub administration change, dispatch, push, PR creation, Jira post/transition or release publication requires fresh explicit operator approval; this handoff alone grants none.
- SPOTR-10 stays open until the first stable-release approval-policy decision. The operator-approved public symbols ZIP means SPOTR-28 is not a confidentiality fix. Retaining administrator control means SPOTR-24 is not mitigation of a malicious administrator.
- No active saved-session plan is assumed: verify and preserve the reviewed file hash during worktree transfer. This planning artifact is uncommitted; application verification has not been run during planning.

## Orchestrator ownership and completion

- Only the orchestrator integrates branches. Separate writing worktrees even when file sets seem disjoint. Serialize shared `Cargo.toml`/`Cargo.lock`, `service.rs`, workflow and documentation conflicts; children report requested shared edits if outside their ownership.
- Child prompts specify scope, absolute path, expected branch/base, baseline failures and all pre-existing dirty paths. Forbid leaving their worktree, broad staging (`git add .`/`-A`), restore/reset/stash/clean and destructive checkout. Require complete final reports: changed paths, commits, test evidence, failures and remaining risk.
- Use bounded regression-first implementation, applicable coding/testing/security skills, LSP for symbol-aware navigation where exposed, and code-review/review-fix loops. No secret values in prompts/output/artifacts; credential existence checks only and approved secret injection for runtime tests.
- Keep issue-specific implementation and verification todos distinct. Finish a lane only after review and its required evidence; infrastructure-blocked verification remains visibly blocked even if code is ready.
- Prepare a Jira evidence/disposition report for all eight findings; ask before posting/transitions. SPOTR-10 stays open. SPOTR-24 is accepted-policy recommendation, SPOTR-28 is packaging-policy implementation, and SPOTR-23 requires live administrative evidence. Umbrellas are not automatically closed.
- Cleanup only verified clean, integrated child worktrees using inspected Worktrunk removal behavior; never force-delete unmerged work or touch existing operator worktrees. Retain primary integration branch/worktree for review unless removal/main integration is explicitly authorized.

Start by reading this plan and making todos; **then establish and enter the primary Worktrunk worktree before implementation or creating writing subagents**.
