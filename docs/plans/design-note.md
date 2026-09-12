# Design Note — SPOTR-5/7/9/17/28 hardening contracts (lanes A–E)

Status: DRAFT for plan-reviewer and operator gate. This note consolidates the four implementation
contracts. Each contract states its trust-model boundary explicitly. Nothing here changes a durable
external interface (Jira, GitHub settings, release flow) without separate operator approval.

Shared decisions across lanes:

- All new code declares its FCIS classification (`// pattern:`) and keeps pure classification/policy
  logic in platform-neutral modules (`spotter-core` or crate-local pure modules).
- Windows-only APIs stay in `spotter-win32`, `spotter-build`, `spotter-hardware-service`, or
  `#[cfg(windows)]` blocks. `spotter-core` gains no Windows dependencies.
- Exact dependency versions in the root `[workspace.dependencies]` table; `zeroize = "=1.8.2"` (a
  `secrecy` 0.10 transitively requires `zeroize` 1.x; declaring the direct dep pins that semver
  without unrelated upgrades).
- No new cryptographic primitives. No reuse of the state HMAC key or the API token for any new
  purpose. Authentication (lane A) precedes serialization (lane E) — the ordering invariant is
  asserted by tests in both lanes.

---

## A. Pipe identity contract (SPOTR-5)

Threat: a standard user creates the pipe at the well-known name (or wins a race during service
restart) and receives CLI command bytes, including `SetToken` values. Identification SQOS does not
prevent this.

### Design

CLI-side authentication of the *connected* server handle, before writing any request bytes:

1. After `CreateFile` on the pipe, the CLI queries the connected server's identity from the client
   side of the pipe handle: `GetNamedPipeServerProcessId` for the server PID, then
   `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ...)` and `OpenProcessToken` +
   `GetTokenInformation(TokenUser)` to read the server process's owner SID, plus
   `QueryFullProcessImageNameW` for diagnostics.
2. The CLI checks identity against the expected service profile, all evaluated together:
   - the server PID is alive and its token owner is `LocalSystem` (well-known SID `S-1-5-18`);
   - the image path matches the installed service executable recorded at SCM registration time
     (the service binary path as reported by `QueryServiceConfig` under the service name recorded
     in the CLI's service configuration), canonicalized and compared case-insensitively;
   - the check happens against the currently connected handle, and is repeated on every
     reconnect (each new connection is fully re-authenticated; no identity caching across
     connections).
3. Any failure — PID unavailable, process exited mid-check, token query failure, unexpected
   account, unexpected path, or pipe reset between check and write — aborts with a typed error and
   **zero request bytes are written**. The exchange function serializes the request only after the
   authentication gate returns `Ok` (serialization ordering is observable through a test seam that
   counts bytes written and auth calls).
4. The service side keeps the existing `D:P(A;;GA;;;SY)(A;;GA;;;BA)` DACL and
   `first_pipe_instance` semantics; lane A additionally enables `first_pipe_instance` for the
   first listening instance so only one server can hold the well-known endpoint name while the
   service runs, and retains per-session instances for reconnects. The first-instance claim uses
   the existing pipe creation path with `FILE_FLAG_FIRST_PIPE_INSTANCE`; a competing claim fails
   service startup rather than silently sharing the name.
5. `SECURITY_IDENTIFICATION` is preserved. The client does not impersonate; the server identity
   query uses only the connected handle's peer PID, which does not require impersonation.

### Injection seam (tests, not a release bypass)

A `ServerIdentityQuery` trait lives in `spotter-win32::pipe` with a production implementation
(`NativeServerIdentityQuery`) and test implementations that can deterministically fail, exit the
server process, or report a mismatched PID. The CLI transport accepts the query as a field with a
`Default` production constructor; test-support feature gates alternate constructors. Production
code paths never read an override from configuration or environment — the seam is compile-time
test-only, satisfying "test-support identity injection must not become a release bypass".

### Bounded errors

`ServiceIdentityError` variants: `PipeUnavailable` (service stopped), `ServiceStarting`,
`ServiceRestarting`, `IdentityQueryFailed{source}`, `UnexpectedIdentity{observed_account}`,
`UnexpectedExecutable{observed_path}`. All map onto existing `ServiceUnavailable` CLI reporting
plus a specific diagnostic. Nothing in the error text includes token material.

### Boundary statement (must ship in docs)

This design prevents a standard user from receiving command bytes by owning the pipe name or
winning a restart race. It does NOT defend against an administrator who controls SCM, replaces the
service binary, or inspects the machine. That boundary is documented in `docs/architecture.md` and
the operator guide.

### Residual risk

PID reuse between query and write is bounded by re-checking liveness immediately before the write
and treating any post-auth error as fail-closed. A truly race-free design would require the server
to authenticate itself cryptographically; that is a protocol change outside this plan's scope and
is called out as a documented limitation rather than claimed as solved.

## B. Journal recovery contract (SPOTR-7)

### Types (platform-neutral, pure classification in `operation_journal.rs`)

```rust
pub enum RecoveryOutcome {
    Clean { records: Vec<JournalRecord> },
    NeedsOperatorRecovery {
        reason: RecoveryReason,
        evidence_paths: Vec<PathBuf>,
        validated_prefix: Vec<JournalRecord>,
    },
    Corrupt { reason: RecoveryReason, original_path: PathBuf },
}

pub enum RecoveryReason {
    UnterminatedFinalRecord,        // ambiguous completeness
    MalformedFinalRecord,
    MalformedMiddleRecord,
    InvalidPhaseSequence,
    QuarantineUnavailable,          // preservation I/O failure
    ReplacementFailed,              // active-journal replacement I/O failure
    BlockedMarkerPresent,           // sticky recovery marker dominates
}
```

`validated_prefix` inside a blocked outcome is diagnostic evidence only; no caller may replay it.
Type is deliberately opaque to callers outside the journal module: `service.rs` can format
`reason`/paths for logs but cannot obtain records to replay.

### Classification (pure, property-tested)

Byte-level classification separates: complete newline-terminated records; a final complete JSON
record without a terminal newline; an unterminated incomplete JSON suffix; malformed bytes in a
final record; malformed bytes mid-file; and semantic phase-sequence validity computed on the
parsed prefix via the existing `pending_with_evidence`. A missing newline on an otherwise valid,
phase-valid final record is *not* proof the operation did not happen; it is retained as evidence
and the file is normalized only after durable preservation.

### Preservation and repair

- Quarantine artifact: `operations.jsonl` → sibling `operations.jsonl.quarantine-<unix-millis>-<16 hex of sha256>`
  (collision-safe; if the target exists, a fresh nonce suffix is appended). Created with
  `sync_all()` before any write to the active path; directory sync after creation.
- A blocked-recovery marker file `operations.jsonl.recovery-blocked` (containing reason, evidence
  path names, and a timestamp; never token material) is created *before* any mutation of the
  active journal when the outcome is `NeedsOperatorRecovery`.
- Every mutation of the active journal uses the existing `atomic_file::write` replacement path —
  never an append over a fragment. `atomic_file::replace` already fails closed on replacement
  errors (original untouched); the journal layer propagates preservation failures as
  `Corrupt{QuarantineUnavailable}` and blocks startup.
- Startup flow: classify → if clean, proceed as today; if normalization-eligible (case 2), preserve
  → normalize atomically → re-validate full sequence → proceed; if blocked or corrupt, create/keep
  the marker and fail closed with an actionable, redacted service log line and non-zero SCM exit.
- The blocked marker dominates: every startup path, compaction, and the identity-change guard
  check for it first; a seemingly valid active prefix next to a marker is still blocked. Repeated
  restarts cannot silently clear it — removal requires the explicit documented administrator
  procedure below. Marker presence is checked with the same durability (read + sync) as the journal.
- Compaction and `guard_remote_identity_change` refuse operation while any blocked marker or
  ambiguous outcome is present (fail closed, matching the existing identity-guard behavior for
  invalid journals).

### No replay of ambiguous evidence

`sync_engine` recovery continues to accept only `Clean` records. `RemoteOutcomeObserved` evidence
inside a blocked outcome is never fed to remote mutation code paths. The candidate state is not
auto-accepted; it is surfaced only through the operator procedure.

### Operator recovery procedure (documented, manual)

1. Stop the service. Locate the quarantine and marker files listed in the service log.
2. With the service stopped, the administrator inspects the full original bytes (quarantined copy)
   and the validated prefix, and determines remote outcome by querying Snipe-IT directly.
3. If the remote outcome is confirmed applied, the administrator may either restore a manually
   repaired journal (complete records only, newline-terminated) or remove the journal and marker to
   start clean; both paths require explicit administrator action.
4. Restart the service. The marker's absence plus a valid journal is the only accepted clean state.

The recovery notice in service logs contains: reason classification, evidence paths, and the
validated-prefix record count. It never contains record contents, tokens, or upstream bodies.

### Retention

Quarantine files are retained indefinitely by this change (no automatic deletion). A bounded
retention policy is a separate reviewed change.

## C. Protected experiment execution contract (SPOTR-9, SPOTR-24 policy retained)

### Staging root and ownership

Per-cell staging root under an administrator-created directory (e.g.
`%ProgramData%\SnipeSpotterHardware\<cell-id>`), created at setup with:

- Root: `Administrators:(F)`, `SYSTEM:(F)`, inheritance disabled, no standard-user ACEs.
- `config.json` and `collector.ps1`: Administrators/SYSTEM full control only.
- Service executable: copied into the root by the administrator setup; same ACLs.
- Key file (`*.key`): retained policy — `SYSTEM:(R)`, `Administrators:(F)` (documented acceptance;
  SPOTR-24 disposition is "retain", so this is verified, not changed).
- `output\` directory: same protect semantics; the collector writes only inside it.

TrustedInstaller-owned system objects (e.g. Windows PowerShell under `System32\WindowsPowerShell`)
are accepted by ownership checks via an explicit allowlist rule: object owner may be
TrustedInstaller or Administrators/SYSTEM; any other owner (including any authenticated-user
writable owner) is rejected. Standard-user-writable *ancestors* are rejected even when the leaf
object is protected.

### Path validation points

Validation is a pure function `spotter-hardware-service` (and mirrored pure helpers for tests)
run at three times: before reading the config, before SCM registration of the per-cell service,
and immediately before consuming each path (collector launch, key read, output creation). Between
check and use, the code opens the object with the desired access and retains the handle for the
consumption step, so an attacker cannot swap the object after validation; where a retained handle
is impossible (e.g. argument-passed paths to PowerShell), the parent directory handle is retained
open with write-access denial semantics.

Checks per path: containment inside the staging root (no escape via `..` or absolute rewrite);
parent-chain traversal with reparse-point rejection at every component; owner identity; effective
ACEs granting write to any principal other than Administrators/SYSTEM (deny-if-writable-by-others);
for the output directory: existing objects are validated before use, and output redirection
outside the directory is prevented by passing only validated paths plus the retained directory
handle.

Reparse handling: `FILE_FLAG_OPEN_REPARSE_POINT`-free traversal (open each component normally and
reject if `FILE_ATTRIBUTE_REPARSE_POINT` is set), so junctions/symlinks anywhere in the chain fail
validation.

### Race behavior

The standard-user mutation window is closed by retained handles, not by repeated pathname checks.
Tests inject swap attempts at a barrier between validation and launch; the launch must fail closed
(or consume the originally validated object), never the swapped one.

### Explicit limitation

An administrator (or the service's own elevated context) can always modify the staging root. This
is documented; the boundary defended is *standard users*, matching SPOTR-9's scope.

## D. Token ownership contract (SPOTR-17)

### Owner types

Adopt `secrecy::SecretString` (already a dependency) and `zeroize::Zeroizing` as the only owner
types. No custom wiping. `zeroize = "=1.8.2"` becomes a direct dependency in
`[workspace.dependencies]` (already transitively present via `secrecy`; declared explicitly for
the crates that own raw buffers).

### Replacement map (contract, lane E must migrate all listed sites)

| Site | Today | After |
| --- | --- | --- |
| `spotter-win32::dpapi::decrypt` output | `Vec<u8>` copy from DPAPI blob, LocalFree guard | `Zeroizing<Vec<u8>>` (wiped before LocalFree) |
| `SecretProtector::decrypt` (both ports modules and fakes) | `SecretString` | `SecretString` (already redacted) but constructed from a `Zeroizing` owner; invalid-UTF-8 error bytes wiped via `Zeroizing` on the error path |
| `owner_ports` consumers of decrypted token | borrows `SecretString` | unchanged (borrows redacted secret) |
| CLI `TokenReader::read_token` | `String` | `Zeroizing<String>` handed to transport; redacted Debug |
| `ServiceCommand::SetToken` wire field | `String` (serde) | unchanged wire shape: serde serializes from a scoped plain borrow at the serialization boundary; the stored field type becomes a redacted owner (`SecretString` with explicit serde impl or scoped `expose_secret`), preserving `{"cmd":"set_token","value":"..."}` exactly |
| Raw IPC request/response line buffers in CLI transport | `Vec<u8>`/`String` | `Zeroizing<Vec<u8>>` for request bytes containing the token; response bytes are non-secret (status/config) and stay plain |
| Serialized request bytes in `exchange_named_pipe` | `Vec<u8>` | `Zeroizing<Vec<u8>>` |
| DPAPI `encrypt` input | `&[u8]` borrow | unchanged (borrow; encryption may keep borrowing plaintext, returning ordinary ciphertext per plan) |

The `SetToken` JSON shape is preserved through an intentional serde conversion: the enum keeps
`value: String` on the wire via a custom `Serialize`/`Deserialize` pair (or `#[serde(with)]`)
backed by the redacted owner, so `test_set_token` wire assertions remain byte-identical. A
parallel plain-`String` API is not retained.

### Coverage of all owners

LSP reference enumeration (lane E entry task, recorded in the ledger) covers: both
`SecretProtector` traits and every implementation/fake; `ServiceCommand` clones through the queue
and channel; drop paths for queued/cancelled commands; every `String`→owner conversion site.
Library-owned temporaries that cannot be wiped (if any surface) are documented as best-effort
limits, not claimed as wiped.

### Error paths

Serialization failure, write failure, flush failure, response timeout, dropped queued commands,
cloned commands, and invalid UTF-8 from DPAPI decryption all wipe owned buffers before returning
or dropping. DPAPI output is zeroized before `LocalFree` through the existing RAII guard extended
to hold a `Zeroizing` view of the blob (wipe-then-free ordering is observable via the existing
safe seam; no freed-memory reads in tests).

---

## Fixtures (lane E infrastructure)

### IPC fixture (native, Windows runner)

- Installs a per-test unique service name and pipe name via SCM (existing elevated lifecycle
  infrastructure in `spotter-svc` tests is extended; `elevated-windows.yml` runs the suite).
- A standard-user actor (runas with a random per-run password, existing helper pattern) launches
  `counterfeit-server.exe` (a tiny test binary that creates the pipe name and records byte counts).
- The CLI runs elevated as the client actor. Captures report only counts/booleans (bytes received,
  connected true/false); no token contents are ever logged.
- Deterministic failure injection through `ServerIdentityQuery` test impls: query failure, server
  process exit, PID mismatch.
- Teardown: stop/delete service, kill actors, bounded waits, fail-safe on test failure.

### Hardware fixture (native, Windows runner)

- Administrator setup creates the protected per-cell root with the ACLs from contract C; a
  standard-user actor attempts mutations at barrier points.
- An intentionally-unprotected control fixture proves the mutation actor actually succeeds when
  protection is absent (`hardware_fixture_unprotected_swap_control`), making the denial tests
  meaningful.
- Synchronization uses named-event condition signals; teardown waits for SCM disappearance before
  deleting files and the root, with bounded waits and failure-safe cleanup.

Both fixtures live in the existing Windows integration test crates with test-support feature gates;
exact test names are in the ledger's registry and match the acceptance matrix.

---

## Blocked / operator-decision items

1. Contract B recovery-state table: implemented as written (operator-assisted recovery for
   ambiguous tails; no automatic reconciliation, no read-only degraded IPC). The plan requires
   explicit operator acceptance of this tradeoff before lane B implements it.
2. Contract A trust-model boundary (documented administrator limitation) and the PID/image-path
   binding approach: confirm this meets the operator's threat model, or stop for an alternative
   protocol design.
3. Contract C allowlist rule for TrustedInstaller-owned paths: confirm acceptance.
4. SPOTR-23 external verification (Phase 4): requires authorized read-only GitHub admin access;
   missing access keeps it explicitly blocked, not silently passed.
