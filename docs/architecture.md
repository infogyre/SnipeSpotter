# SnipeSpotter architecture

SnipeSpotter separates deterministic decisions from operating-system and network I/O using the Functional Core / Imperative Shell (FCIS) pattern.

## Crate dependency graph

```mermaid
graph TD
    Core[spotter-core: Functional Core] --> SVC[spotter-svc: Imperative Shell]
    Core --> CLI[spotter-cli: Imperative Shell]
    Win32[spotter-win32: Windows FFI] --> SVC
    Win32 --> CLI
    Build[spotter-build: build-time resources] --> SVC
    Build --> CLI
    Core -.-> Build
```

Dependency rules:

- `spotter-core` has zero I/O, no async, no platform-specific FFI. `cfg(windows)` is permitted only for path constants that select a directory root without performing I/O.
- `spotter-svc` and `spotter-cli` never import from each other.
- `spotter-win32` and `spotter-build` are Windows-only and never compile on non-Windows targets.
- `spotter-build` reads `spotter-core` source at build time (file parse, not crate dependency).

## Crate responsibilities

### spotter-core (Functional Core)

Owns all domain logic with no side effects:

- **Configuration schema** (`config.rs`): `Settings` with nested `SnipeItSettings`, `PollingSettings`, `LoggingSettings`, `MonitorSettings`. TOML round-trip, `serde(default)`, `config_status()` for missing-field detection.
- **Identity constants** (`identity.rs`): `PRODUCT_NAME`, `COMPANY_NAME`, derived `SERVICE_NAME`, `PIPE_NAME`, `MUTEX_NAME`, and `data_dir()`.
- **SMBIOS parser** (`smbios.rs`): `parse_smbios_tables(raw: &[u8]) -> Result<SystemInfo, SmbiosParseError>`. Parses Type 1/2/3 tables and string tables. `ChassisType` with `is_portable()` for types 8-12, 14, 30-32.
- **Monitor data** (`monitors.rs`): `MonitorInfo`, `MonitorSyncState`, `MonitorSyncEntry`. `diff_monitors()` computes new/removed/unchanged monitors with typed UTC timestamps.
- **Snipe-IT models** (`snipeit/`): `Asset`, `AssetModel`, `Manufacturer`, `Category` response types. Request builders for PATCH, checkout, and check-in. Endpoint-specific classifiers that consume HTTP status + wire body and return structured `SnipeItError` variants.
- **Sync planning** (`sync.rs`): `plan_sync()` is the pure planner. Takes resolved taxonomy, monitor state, policy, and a supplied `now` timestamp. Returns `SyncPlan` with asset updates, checkouts, checkins, next monitor state, and warnings. Missing taxonomy suppresses mutations and emits warnings.
- **IPC protocol** (`ipc.rs`): `ServiceCommand` and `IpcResponse` enums with serde tagging. `SettingsUpdate` for typed config field updates. `validate_config_field()` for client-side validation. 64 KiB line limit.
- **Service state** (`state.rs`): `ServiceState` with HMAC-SHA256 signing. `canonical_bytes()` excludes the HMAC field. Constant-time verification via `subtle`.

### spotter-win32 (Windows FFI)

Narrowly scoped unsafe wrappers with RAII ownership:

- **DPAPI** (`dpapi.rs`): `encrypt()` / `decrypt()` using `CryptProtectData` / `CryptUnprotectData` with `CRYPTPROTECT_LOCAL_MACHINE` and `CRYPTPROTECT_UI_FORBIDDEN`. Output buffers are copied to Rust-owned vectors and freed with `LocalFree` via RAII guard.
- **Named mutex** (`mutex.rs`): `try_acquire_global_mutex()` using `CreateMutexW` with `ERROR_ALREADY_EXISTS` detection. Mutex name: `Global\SnipeSpotter`.
- **Pipe DACL** (`pipe.rs`): `create_admin_pipe_security_attributes()` builds an SDDL descriptor granting generic-all to SYSTEM (`SY`) and built-in Administrators (`BA`), with no handle inheritance.
- **Elevation** (`elevation.rs`): `is_elevated()` checks whether the current process has administrator rights.

### spotter-build (Build helper)

Parses `PRODUCT_NAME` and `COMPANY_NAME` from `spotter-core/src/identity.rs` at build time and passes them as preprocessor defines to the RC compiler. Embeds `VERSIONINFO` and STRINGTABLE resources. The CLI exe gets a `requireAdministrator` manifest; the service exe gets `asInvoker`.

### spotter-svc (Service shell)

Implements the Gather -- Process -- Persist cycle:

- **FSM** (`fsm.rs`): Enum + match loop. All states visible in one function. The FSM is the single owner of active config, Snipe-IT client, sync execution, and in-memory state. Commands are serialized: one sync/check-in at a time, duplicate triggers coalesce, config updates commit atomically.
- **Hardware discovery** (`discovery.rs`): `discover_hardware()` calls `GetSystemFirmwareTable` for SMBIOS and WMI `WmiMonitorID` for monitors. Abstracted behind a `HardwareDiscovery` trait with real and mock implementations.
- **Snipe-IT client** (`snipeit_client.rs`): `reqwest`-based HTTP client with bearer token auth, rate limit handling (`X-RateLimit-Remaining`, `Retry-After`), pagination, and `Option<String>` base URL override for wiremock testing.
- **Sync engine** (`sync_engine.rs`): Orchestrates gather (discover hardware, find assets by serial, resolve taxonomy, load prior state) -- process (`plan_sync()`) -- persist (journal each operation, reconcile before execution, mark confirmed, persist state delta).
- **IPC server** (`ipc_server.rs`): Named-pipe server with JSON-over-newline protocol. Transport handlers validate framing and enqueue `FsmCommand` values to the FSM. Each request carries a one-shot response sender for committed results.
- **Config I/O** (`config_io.rs`): Crash-safe Windows replacement via `ReplaceFileW` / `MoveFileExW`. DPAPI decryption wraps the token in `SecretString`.
- **State I/O** (`state_io.rs`): HMAC-signed state with crash-safe replacement. HMAC key generated with `getrandom` on first run.
- **Operation journal** (`operation_journal.rs`): Append-only, fsynced journal of prepared/confirmed operations with deterministic IDs. Recovery loads signed state plus pending records, reconciles, retries only operations still not in desired state, then compacts atomically.
- **Logging** (`logging.rs`): `tracing-subscriber` with `tracing-appender` rolling file appender. Daily rotation, configurable level and retention.
- **Service registration** (`service.rs`): `windows-service` crate for SCM integration. Service name: `SnipeSpotter`, account: `LocalSystem`, start type: automatic.

### spotter-cli (CLI)

`clap` derive with nested subcommands. Depends on injectable `IpcTransport`, `ServiceRegistrar`, `ElevationChecker`, and `TokenReader` ports. Unit tests use fakes; production adapters perform named-pipe, SCM, console, and elevation I/O.

## Service lifecycle (FSM)

```mermaid
stateDiagram-v2
    [*] --> Bootstrap
    Bootstrap --> LoadConfig
    LoadConfig --> Unconfigured: required values missing
    LoadConfig --> Decrypt: complete
    Unconfigured --> LoadConfig: configuration changed via IPC
    Decrypt --> ValidateConfig: DPAPI success
    Decrypt --> Error: DPAPI failure
    ValidateConfig --> Idle: connectivity OK
    ValidateConfig --> Unconfigured: auth or permission failure
    Idle --> Syncing: timer or manual trigger
    Syncing --> Idle: success
    Syncing --> Error: transient failure
    Error --> Idle: retry interval
    Error --> Unconfigured: auth or permission error
```

Key FSM properties:

- The FSM is the single owner of active config, Snipe-IT client, sync/check-in execution, and in-memory service state.
- IPC transport accepts connections in all states, but handlers enqueue typed `FsmCommand` values to the FSM over a bounded channel. The FSM serializes all mutations.
- Duplicate `TriggerSync` requests coalesce with an already queued or running sync.
- `CheckinAll` and `CheckinSerial` are serialized after any active sync and operate on the latest committed monitor state.
- State transitions write to `state.toml` before sending notifications (commit-before-notify).

## Synchronization flow

```mermaid
sequenceDiagram
    participant HW as Windows discovery
    participant API as Snipe-IT
    participant Core as spotter-core
    participant Store as state/journal
    HW->>Core: SystemInfo and monitors
    API->>Core: assets and resolved taxonomy
    Store->>Core: previous signed state
    Core-->>Store: SyncPlan
    Store->>Store: append prepared operation to journal
    Store->>API: apply or reconcile mutation
    API-->>Store: confirmed outcome
    Store->>Store: mark confirmed and replace signed state
    Store->>Store: compact journal
```

Operation recovery:

- Before each external mutation, the engine durably appends a journal entry keyed by a deterministic `operation_id` (operation kind + source asset + target/status + sync generation).
- Before execution, the engine reconciles the current server assignment/status. If the desired state is already applied, it treats that as success.
- After each confirmed response, the engine durably marks the operation complete and persists the monitor-state delta.
- On restart, recovery loads signed state plus pending journal records, queries Snipe-IT, records confirmed outcomes, retries only operations still not in desired state, then compacts atomically.

## Security boundaries

- **API tokens**: Encrypted by the LocalSystem service with machine-scope DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`). Plaintext never persists. The elevated CLI submits plaintext over the SYSTEM/admin-only pipe; the service performs encryption.
- **Named-pipe access**: Restricted to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` via an SDDL DACL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`). No handle inheritance.
- **ProgramData ACLs**: Settings, state, HMAC key, journal, and logs under `%ProgramData%\infogyre\SnipeSpotter\` with inheritable full control only to SYSTEM and Administrators.
- **Signed state**: HMAC-SHA256 over canonical JSON that excludes the HMAC field. Constant-time verification via `subtle`. Tampered state is rejected; the operator preserves files for diagnosis rather than deleting them.
- **IPC line limit**: 64 KiB maximum per request or response line to prevent DoS.
- **Elevation**: CLI manifest requires `requireAdministrator`. Runtime `is_elevated()` check as belt-and-suspenders backup.

## Monitor check-in policy

| Policy | Behavior |
|---|---|
| `Manual` | Never automatically checks in monitors. Operator must use `spotter-cli checkin`. |
| `AutoNonPortable` | Checks in an absent monitor only when: (1) SMBIOS chassis type is non-portable, (2) the monitor was previously checked out, (3) `now - absent_since >= checkin_threshold_hours`. |

Portable chassis types (suppressed auto check-in): 8 (Portable), 9 (Laptop), 10 (Notebook), 11 (Hand Held), 12 (Docking Station), 14 (Sub Notebook), 30 (Tablet), 31 (Convertible), 32 (Detachable).

A present monitor clears its `absent_since` timestamp. A newly absent monitor sets it to the current `now`. Continued absence preserves the original timestamp. The CLI `checkin --all` and `checkin <serial>` commands force check-in regardless of policy.
