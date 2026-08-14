# SnipeSpotter architecture

SnipeSpotter separates deterministic decisions from operating-system and network I/O.

```mermaid
graph TD
  Core[spotter-core: Functional Core] --> Service[spotter-svc: Imperative Shell]
  Core --> CLI[spotter-cli: Imperative Shell]
  Win32[spotter-win32: Windows FFI] --> Service
  Win32 --> CLI
  Build[spotter-build: build-time resources] --> Service
  Build --> CLI
```

`spotter-core` owns configuration, SMBIOS parsing, monitor state, Snipe-IT wire classification, sync planning, IPC types, and signed state. It receives timestamps and keys as inputs and performs no file, network, async, or Windows I/O.

`spotter-win32` owns DPAPI, the process mutex, named-pipe security attributes, and elevation checks. Each Windows allocation or handle has an RAII owner.

`spotter-svc` gathers hardware and remote state, calls the core planner, and persists confirmed outcomes. `spotter-cli` converts operator commands into IPC requests. Neither shell imports from the other.

## Service lifecycle

```mermaid
stateDiagram-v2
  [*] --> Bootstrap
  Bootstrap --> LoadConfig
  LoadConfig --> Unconfigured: required values missing
  LoadConfig --> Decrypt: complete
  Unconfigured --> LoadConfig: configuration changed
  Decrypt --> ValidateConfig
  ValidateConfig --> Idle: valid
  ValidateConfig --> Unconfigured: authentication or permission failure
  Idle --> Syncing: timer or trigger
  Syncing --> Idle: success
  Syncing --> Error: transient failure
  Error --> Idle: retry interval
```

The service controller is the single owner of active settings and synchronization state. Duplicate triggers coalesce. State is committed before success is returned to IPC clients.

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
  Store->>Store: append prepared operation
  Store->>API: apply or reconcile mutation
  API-->>Store: confirmed outcome
  Store->>Store: mark confirmed and replace signed state
```

Prepared operations use deterministic identifiers. Recovery reconciles remote state before retrying an uncertain mutation.

## Security boundaries

- API tokens are encrypted by the LocalSystem service with machine-scope DPAPI.
- Named-pipe access is restricted to SYSTEM and built-in Administrators.
- Settings, state, key, journal, and logs belong under `%ProgramData%\infogyre\SnipeSpotter` with equivalent ACLs.
- Signed state uses HMAC-SHA256 over canonical JSON that excludes the HMAC field.
- IPC lines are bounded to 64 KiB.
