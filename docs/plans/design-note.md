# Design Note — SPOTR-5/7/9/17/28 hardening contracts (lanes A–E)

Status: REV-2 — incorporates plan-reviewer findings (critical + high items resolved). Pending
operator confirmation of the flagged durable decisions before lane implementation starts.

## Reviewer findings incorporated (REV-2 changelog)

1. (Critical, A) Native probe required for `GetNamedPipeServerProcessId` on a `CreateFile` client
   handle: Microsoft's current reference states the handle must come from `CreateNamedPipe`, while
   Chromium and other mature clients call it on client handles. Behavior must be established by a
   native compatibility probe on each supported Windows image before lane A implements the gate;
   probe failure is fail-closed, never a fallback to an unauthenticated path.
2. (High, A) `lpBinaryPathName` from `QueryServiceConfig` is a command line, not a path: a Windows
   quoting-rule argv[0] parser is specified below; reparse-free canonicalization; SCM query failure
   is fail-closed.
3. (High, A) Process/token access rights: `PROCESS_QUERY_LIMITED_INFORMATION` (per current
   Microsoft `OpenProcessToken` documentation) with `TOKEN_QUERY`; cross-account LocalSystem
   inspection from an elevated administrator client may require `SeDebugPrivilege` — enabled
   explicitly, failure is fail-closed. Probe asserts the real behavior.
4. (High, B) Journal classification is the first durable-data gate at startup: it runs before
   config-status branching, DPAPI decryption, remote-client construction, owner creation, or IPC
   accept loop. Only `Clean` reaches `recover_pending`/`apply_recovered_candidate_states`.
5. (High, B) `validated_prefix` is not a public record-bearing API: blocked outcomes expose only a
   redacted summary (reason, evidence paths, validated record count). Typed preservation/marker/
   replacement I/O failure variants replace the lossy `Corrupt{QuarantineUnavailable}` mapping.
6. (High, B) Quarantine/marker artifacts get exclusive-create/no-follow creation, protected-ACL
   application before sensitive content, parent-directory validation, and fsync durability, with
   crash-state tests at every boundary.
7. (High, C) Reparse detection fixed: components are opened with `FILE_FLAG_OPEN_REPARSE_POINT`
   (no-follow) and the reparse tag is read from the handle before traversal; final verification by
   `GetFinalPathNameByHandle` + containment.
8. (High, C) Consumed paths: PowerShell launch must consume only objects bound by retained
   protected handles or content copied into ACL-protected staging objects at launch time; plain
   path-string arguments to `CreateProcess` are not race-safe and are removed from the design.
9. (High, C) Workflow migration is in scope: the key is created directly in the protected root
   (never plaintext-then-`icacls` under `RUNNER_TEMP`), and config/collector/support-executable
   staging moves into the protected root, with acceptance tests asserting the actual workflow paths.
10. (High, D) Exact per-site signature map for both `SecretProtector` traits; server-side request
    line buffer zeroized; `spotter-core` owns the platform-neutral redacted owner type; explicit
    DPAPI wipe-before-free guard over exactly `cbData` bytes with failure handling.
11. (Medium, D) Unavoidable plaintext temporaries inventoried and bounded; tests claim only
    application-owned cleanup; a compile-level check forbids regression to plain String token APIs.
12. (Medium, fixtures) Explicit race-order timeline: counterfeit-claim-then-service-start case
    separately from service-first case; actor privilege assertions; hardware control asserts the
    exact mutation.
13. (Low, registry) Test registry with crate target, feature flags, workflow job, and evidence
    artifact per AC is maintained in the execution ledger before lane branches are created.

Shared decisions across lanes:

- All new code declares its FCIS classification (`// pattern:`) and keeps pure classification/policy
  logic in platform-neutral modules.
- Windows-only APIs stay in `spotter-win32`, `spotter-build`, `spotter-hardware-service`, or
  `#[cfg(windows)]` blocks. `spotter-core` gains no Windows dependencies.
- Exact dependency versions in the root `[workspace.dependencies]` table; `zeroize = "=1.8.2"`
  becomes a direct dependency (already transitive via `secrecy` 0.10).
- No new cryptographic primitives. No reuse of the state HMAC key or the API token for any new
  purpose. Authentication (lane A) precedes serialization (lane E) — asserted by tests in both.

---

## A. Pipe identity contract (SPOTR-5)

Threat: a standard user creates the pipe at the well-known name (or wins a race during service
restart) and receives CLI command bytes, including `SetToken` values. Identification SQOS does not
prevent this.

### A.0 Native compatibility probe (blocks lane A implementation)

Before implementing the identity gate, a probe test (native Windows, in the lane A fixture suite)
establishes:

- `GetNamedPipeServerProcessId` called on the exact client handle produced by `CreateFile` with
  `SECURITY_IDENTIFICATION` SQOS flags against a real `CreateNamedPipeW` server: record success and
  PID correctness, or the specific failure code. Microsoft's reference wording (server-end handle
  requirement) conflicts with observed ecosystem behavior (Chromium's client-side usage); the probe
  resolves this per supported Windows image. If the probe fails on a supported image, lane A stops
  for operator approval of an alternative mechanism — the gate is never silently dropped or
  weakened, and any fallback must be a reviewed design change.
- `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `OpenProcessToken(TOKEN_QUERY)` +
  `GetTokenInformation(TokenUser)` against the genuine LocalSystem service from an elevated
  administrator client: record whether `SeDebugPrivilege` is required. The implementation enables
  `SeDebugPrivilege` explicitly when available and treats any failure as fail-closed
  (authentication failure, zero bytes written).

Probe results are recorded in the execution ledger before the identity gate lands.

### A.1 Identity check

After `CreateFile` on the pipe, before writing any request bytes:

1. Query the connected server's PID from the client-side handle (A.0 probe mechanism).
2. Open the server process with `PROCESS_QUERY_LIMITED_INFORMATION`; retain the process handle for
   all subsequent checks; reject protected/non-queryable processes (fail closed).
3. `OpenProcessToken` with `TOKEN_QUERY`; read `TokenUser` owner SID; require
   `S-1-5-18` (LocalSystem).
4. `QueryFullProcessImageNameW` on the retained handle for diagnostics and path comparison.
5. Re-check process liveness immediately before the write; any post-auth error is fail-closed.

### A.2 Expected service profile and image-path comparison

The expected binary path is read from `QueryServiceConfig` for the configured service name using a
retained SCM/service handle for the duration of the check (current-configuration read; within the
documented administrator boundary an administrator can change registration — that limitation is
stated, not defended).

`lpBinaryPathName` is a command line: it is parsed with Windows command-line quoting rules
(`CommandLineToArgvW` semantics) and only `argv[0]` is used; the rest is never treated as the
executable path. `argv[0]` is canonicalized to a final path without following attacker-controlled
reparse points and compared case-insensitively against `QueryFullProcessImageNameW` output from
the retained server process handle. Test coverage: quoted paths, paths with arguments, case
differences, long paths, and SCM query failure (fail closed). Argument-bearing genuine service
configurations must authenticate.

### A.3 First instance and reconnects

- The service claims the first listening instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`; a competing
  claim fails service startup (the well-known name is never shared while the service runs).
  Per-session instances for reconnects do not pass that flag (only the first).
- Every connection is fully re-authenticated; no identity caching across connections or handles.
- The service side keeps the existing `D:P(A;;GA;;;SY)(A;;GA;;;BA)` DACL.

### A.4 Injection seam (tests, not a release bypass)

A `ServerIdentityQuery` trait in `spotter-win32::pipe`: production `NativeServerIdentityQuery`;
test impls inject deterministic failures (query failure, server exit, PID mismatch). The CLI
transport holds the query as a field with a production `Default`; alternate constructors are
compile-time test-support only. No configuration or environment override exists in production.

### A.5 Bounded errors

`ServiceIdentityError` variants: `PipeUnavailable`, `ServiceStarting`, `ServiceRestarting`,
`IdentityQueryFailed{source}`, `UnexpectedIdentity{observed_account}`, `UnexpectedExecutable{observed_path}`.
All map onto existing `ServiceUnavailable` CLI reporting plus a specific diagnostic. Error text
never includes token material.

### A.6 Boundary statement (must ship in docs)

Prevents a standard user from receiving command bytes via pipe-name ownership or restart races.
Does NOT defend against an administrator controlling SCM, replacing the service binary, or
inspecting the machine. Documented in `docs/architecture.md` and the operator guide.

## B. Journal recovery contract (SPOTR-7)

### B.1 Types (pure classification in `operation_journal.rs`)

```rust
pub enum RecoveryOutcome {
    Clean { records: Vec<JournalRecord> },
    NeedsOperatorRecovery(OperatorRecovery),
    PreservationFailed(PreservationFailure),
    Corrupt { reason: RecoveryReason },
}

pub struct OperatorRecovery {
    reason: RecoveryReason,           // pub getter
    evidence_paths: Vec<PathBuf>,     // pub getter, redacted display
    validated_record_count: usize,    // pub getter
    // No JournalRecord accessor: the prefix is deliberately not replayable through this type.
}
```

- `Corrupt` carries the reason and the original path is known to the caller (it passed it in); no
  record data crosses the boundary.
- Typed I/O failures: `PreservationFailed` distinguishes `QuarantineWrite`, `MarkerWrite`, and
  `Replacement` variants from malformed-evidence corruption. Every non-`Clean` outcome blocks
  startup and remote activity.

### B.2 Classification (pure, property-tested)

Byte-level classification separates: complete newline-terminated records; a final complete JSON
record without a terminal newline; an unterminated incomplete JSON suffix; malformed bytes in a
final record; malformed bytes mid-file; and semantic phase-sequence validity computed on the parsed
prefix via the existing `pending_with_evidence`. A missing newline on an otherwise valid,
phase-valid final record is not proof the operation did not happen; it is retained as evidence and
the file is normalized only after durable preservation.

### B.3 Startup ordering (reviewer finding 4)

Journal/marker classification is the **first durable-data gate** in `service.rs` startup, before:

- the settings-configured branch (the current `recover_operations` call site is moved so an
  unconfigured service with a blocked/corrupt journal still fails closed),
- DPAPI decryption, remote-client construction, owner creation, `recover_pending`, or
  `apply_recovered_candidate_states`,
- the IPC accept loop.

Only `Clean` proceeds to the existing recovery flow. `NeedsOperatorRecovery`, `PreservationFailed`,
and `Corrupt` produce: a bounded redacted service log line, non-zero process exit (SCM reports
failure), and no IPC listener. The blocked marker file dominates every subsequent startup: a
seemingly valid active prefix beside a marker is still blocked, across repeated restarts; the
marker is consulted before any classification result is acted on.

### B.4 Preservation and repair

- Quarantine artifact: `operations.jsonl` → sibling
  `operations.jsonl.quarantine-<unix-millis>-<16 hex of sha256>`; created with `CreateNew`
  (exclusive) semantics, no-follow, after validating the parent directory is not a reparse point;
  if the target name exists, a fresh nonce suffix is used. `sync_all()` before any write to the
  active path; parent-directory flush after creation.
- Blocked-recovery marker `operations.jsonl.recovery-blocked` (reason, evidence path names,
  timestamp; never token material): exclusive-create, no-follow, written and synced before any
  mutation of the active journal when the outcome is `NeedsOperatorRecovery`.
- Active-journal mutation uses the existing `atomic_file::write` replacement path — never append
  over a fragment. `atomic_file::replace` already fails closed with the original untouched;
  preservation/marker/normalization failures keep the original bytes intact and map to
  `PreservationFailed`, blocking startup.
- Startup flow: marker check → classify → if clean, proceed as today; if normalization-eligible
  (valid phase-valid final record without newline), preserve → normalize atomically → re-validate
  full sequence → proceed; otherwise fail closed with an actionable, redacted log line.
- Compaction and `guard_remote_identity_change` refuse operation while any blocked marker or
  ambiguous outcome is present (matching the existing identity-guard fail-closed behavior).

### B.5 No replay of ambiguous evidence

`sync_engine::recover_pending` accepts only `Clean` records; the `OperatorRecovery` type exposes no
record-bearing accessor, so no caller can replay quarantined evidence through it. Candidate state
is never auto-accepted; it is surfaced only through the manual operator procedure.

### B.6 Operator recovery procedure (documented, manual)

1. Stop the service. Locate the quarantine and marker files listed in the service log.
2. With the service stopped, the administrator inspects the full original bytes (quarantined copy)
   and determines the remote outcome by querying Snipe-IT directly.
3. If the remote outcome is confirmed applied, the administrator may either restore a manually
   repaired journal (complete records only, newline-terminated) or remove the journal and marker to
   start clean; both require explicit administrator action.
4. Restart. The marker's absence plus a valid journal is the only accepted clean state.

The recovery notice contains: reason classification, evidence paths, validated record count. Never
record contents, tokens, or upstream bodies.

### B.7 Retention

Quarantine files are retained indefinitely by this change (no automatic deletion). A bounded
retention policy is a separate reviewed change.

## C. Protected experiment execution contract (SPOTR-9, SPOTR-24 policy retained)

### C.1 Staging root and ownership

Per-cell staging root under an administrator-created directory (e.g.
`%ProgramData%\SnipeSpotterHardware\<cell-id>`), created at setup with:

- Root: `Administrators:(F)`, `SYSTEM:(F)`, inheritance disabled, no standard-user ACEs.
- `config.json` and `collector.ps1`: Administrators/SYSTEM full control only.
- Service executable: copied into the root by the administrator setup; same ACLs.
- Key file (`*.key`): retained policy — `SYSTEM:(R)`, `Administrators:(F)` (SPOTR-24 disposition is
  "retain"; verified, not changed).
- `output\` directory: same protection; the collector writes only inside it.

### C.2 Workflow migration (reviewer finding 9 — in scope for lane C)

The current workflow writes the HMAC key under `RUNNER_TEMP` (plaintext-then-`icacls`), stages the
collector from `GITHUB_WORKSPACE`, and stages the service config and support executable under
`RUNNER_TEMP`. Lane C migrates the actual execution path: the key is created **directly inside the
protected root** with restrictive creation ACLs (never plaintext in a user-writable directory first),
and the config, collector, and support executable are staged beneath the protected root before any
secret exists. Acceptance tests assert the real workflow paths (standard-user replacement and
reparse attempts against them must fail), not just an abstract staging-root helper.

### C.3 Path validation

Validation is a pure function run at three times: before reading the config, before SCM
registration, and immediately before consuming each object.

Per path, the handle-based algorithm (reviewer finding 7):

1. Open each path component with `FILE_FLAG_OPEN_REPARSE_POINT` (no-follow) and read
   `FileAttributeTagInfo` from the handle; reject any component carrying a reparse tag **before**
   traversing it. Opening normally would follow the link before the attribute is inspected — that
   ordering is explicitly forbidden.
2. Verify the final path by `GetFinalPathNameByHandle` on the opened handle plus containment inside
   the staging root (no escape via `..`, absolute rewrite, or link traversal).
3. Owner identity: Administrators, SYSTEM, or TrustedInstaller (explicit allowlist for
   system-owned PowerShell layouts) are accepted; any other owner is rejected.
4. Effective ACEs: reject if any principal other than Administrators/SYSTEM holds write access.
5. Standard-user-writable ancestors are rejected even when the leaf object is protected.
6. Output directory: existing objects validated before use; output redirection outside the
   directory prevented via validated paths plus the retained protected directory handle.

### C.4 Race behavior: consumed objects bound at launch (reviewer finding 8)

A retained parent-directory handle does **not** secure paths handed to `CreateProcess` as argument
strings — PowerShell resolves them afresh. Therefore:

- The collector script, key file, and output directory passed to PowerShell are consumed only as
  objects bound by retained protected handles (opened with sharing modes that deny delete/rename/
  write by others), or their **content is copied into a fresh ACL-protected staging object created
  inside the protected root immediately before launch**, and only that immutable staging path is
  passed. Plain pathname arguments referencing the original locations are removed from
  `spawn_collector`.
- Swap attempts at the validation/launch barrier must fail closed or consume the originally
  validated object — never the swapped one. The native `hardware_host_blocks_validation_launch_swap`
  test proves the child cannot consume a replacement.
- An administrator (or the service's own elevated context) can always modify the staging root;
  documented. The defended boundary is standard users, matching SPOTR-9's scope.

## D. Token ownership contract (SPOTR-17)

### D.1 Owner types

`secrecy::SecretString` (existing dependency) and `zeroize::Zeroizing` are the only owner types.
No custom wiping. `zeroize = "=1.8.2"` becomes a direct dependency in `[workspace.dependencies]`.
`spotter-core` owns the platform-neutral redacted wire owner for `SetToken` (depends on
`secrecy`/`zeroize`; both are platform-neutral crates, so `spotter-core` stays neutral).

### D.2 Exact per-site signature map (reviewer finding 10 — replaces the earlier broad table)

| Site | Today | After |
| --- | --- | --- |
| `ports::SecretProtector::decrypt` (`spotter-svc/src/ports.rs`) | `Result<Vec<u8>>` | `Result<Zeroizing<Vec<u8>>>` |
| `owner_ports::SecretProtector::decrypt` (`spotter-svc/src/owner_ports.rs`) | `Result<SecretString>` | `Result<SecretString>` (unchanged redacted type; internally constructed from a `Zeroizing` owner, invalid-UTF-8 error bytes wiped) |
| Every `SecretProtector` implementation and fake (both traits, `DpapiProtector`, test fakes) | as above | migrated to the trait's new signature; LSP references enumerated at lane E entry and recorded in the ledger |
| `spotter-win32::dpapi::decrypt` | `Result<Vec<u8>>` (copy from blob under `LocalFreeGuard`) | returns `Result<Zeroizing<Vec<u8>>>`; a dedicated guard wipes exactly `cbData` bytes **before** `LocalFree`, handling API-failure, null, and invalid-length cases safely (wipe-then-free ordering observable via the existing safe seam; no freed-memory reads in tests) |
| CLI `TokenReader::read_token` (`spotter-cli/src/lib.rs`) | `Result<String>` | `Result<SecretString>`; consumers use `expose_secret()` only at the transport boundary |
| `ServiceCommand::SetToken` (`spotter-core/src/ipc.rs`) | `value: String` (derived serde) | `value: SecretString` with a custom serde impl preserving the exact wire shape `{"cmd":"set_token","value":"..."}`; `Serialize` uses `expose_secret()` at serialization time, `Deserialize` wraps into the owner; Debug redacted; no parallel plain-String API retained |
| CLI request serialization buffer (`exchange_named_pipe`) | `Vec<u8>` | `Zeroizing<Vec<u8>>` |
| Server request line buffer (`ipc_server::serve_one`) | `Vec<u8>` in `BufReader` | `Zeroizing<Vec<u8>>` owner for the consumed line (the token is present server-side before deserialization) |
| Decoded `SetToken` inside `service.rs` | borrows `String` | borrows redacted secret; `set_token(value.as_bytes())` via `expose_secret()` |
| Raw response buffers | plain | unchanged (non-secret status/config data) |
| `owner_ports` consumers of decrypted token | borrow `SecretString` | unchanged |
| `dpapi::encrypt` input | `&[u8]` borrow | unchanged (encryption keeps borrowing plaintext, returns ordinary ciphertext) |

Queue/channel clone and drop paths: `ServiceCommand` derives `Clone`; clones of the redacted owner
are themselves redacted owners (secrecy/zeroize semantics), so queued, cloned, and cancelled
commands zeroize on drop automatically — verified by `token_owner_clone_queue_cancel_cleanup`.

### D.3 Unavoidable plaintext temporaries (reviewer finding 11 — explicit inventory)

| Temporary | Owner | Bound |
| --- | --- | --- |
| `rpassword::prompt_password` return | library-owned `String` | converted to the redacted owner immediately; library internal copy unavoidable, documented |
| `serde_json::to_vec` intermediate | application-owned `Vec<u8>` | produced directly into the `Zeroizing` buffer where the API allows; otherwise wrapped immediately after the call |
| `String::from_utf8` intermediate for valid UTF-8 | application-owned | consumed into the owner immediately; the invalid-UTF-8 error path wipes the error-owned bytes |
| serde deserializer's internal `String` for `SetToken.value` server-side | library-owned | bounded to the deserialization call; documented as library-controlled |

Tests claim only application-owned cleanup. A compile-level check (workspace build + grep gate in
CI contract) forbids any new plain-`String` token API.

### D.4 Wire and Debug regressions

`set_token_wire_shape_is_unchanged` asserts byte-identical JSON; `set_token_debug_is_redacted`
asserts Debug never contains the secret. Deserialize/Serialize/Clone/Drop are all covered.

---

## Fixtures (lane E infrastructure)

### IPC fixture (native, Windows runner)

- Installs a per-test unique service name and pipe name via SCM (existing elevated lifecycle
  infrastructure extended; `elevated-windows.yml` runs the suite).
- **Race-order timeline (reviewer finding 12):**
  - Case 1 (counterfeit-first): the standard-user actor starts first, claims the well-known
    endpoint name, and signals success; only then does the legitimate service attempt its
    first-instance claim, which must fail. The CLI connects to the counterfeit endpoint; the
    counterfeit server records byte counts and must receive zero request bytes.
  - Case 2 (service-first): the genuine LocalSystem service claims the endpoint first and the CLI
    authenticates against it (positive path); reconnect and concurrency covered in the same case.
- The CLI runs elevated as the client actor. Actor SIDs, integrity level, elevation, and
  relevant privilege state (including `SeDebugPrivilege` for the genuine-service identity query)
  are asserted per actor. Captures report only counts/booleans; no token contents are logged.
- Deterministic failure injection via `ServerIdentityQuery` test impls: query failure, server
  process exit, PID mismatch.
- Teardown: stop/delete service, kill actors, bounded waits, fail-safe on test failure.

### Hardware fixture (native, Windows runner)

- Administrator setup creates the protected per-cell root with contract C ACLs; a standard-user
  actor attempts mutations at barrier points.
- The intentionally-unprotected control fixture **performs and verifies the exact mutation**
  (write/replace/reparse observed on disk) that the protected case must deny — process success
  alone is not accepted evidence.
- Synchronization uses named-event condition signals; teardown waits for SCM disappearance before
  deleting files and the root, with bounded waits and failure-safe cleanup.

Both fixtures live in the existing Windows integration test crates with test-support feature gates;
exact test names, crate targets, workflow jobs, and evidence artifacts are registered in the
execution ledger before lane branches are created. AC.16/AC.17/AC.18 are manual/external criteria
with explicit blocked-status semantics.

---

## Operator-decision items requiring confirmation before lane implementation

1. Contract B recovery-state table as revised (operator-assisted recovery for ambiguous tails; no
   automatic reconciliation; no read-only degraded IPC; classification-first startup ordering).
2. Contract A trust-model boundary (documented administrator limitation) plus the PID/image-path
   binding approach, including the A.0 native probe gate.
3. Contract C TrustedInstaller allowlist rule and the workflow migration scope (key created in the
   protected root).
4. SPOTR-23 external verification (Phase 4): requires authorized read-only GitHub admin access;
   missing access keeps it explicitly blocked, not silently passed.
