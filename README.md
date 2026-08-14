# SnipeSpotter

SnipeSpotter synchronizes Windows system and monitor inventory with an existing [Snipe-IT](https://snipeitapp.com/) asset management instance. It discovers local hardware via SMBIOS and WMI, matches computer and monitor assets by serial number, applies field updates through PATCH, checks out monitors to their host computer, and automatically checks in absent monitors on non-portable machines -- all through a Windows service that polls on a configurable interval.

## Key features

- **Serial-primary matching**: Finds Snipe-IT assets by exact serial number via `GET /api/v1/hardware/byserial/{serial}`.
- **Strict taxonomy**: Resolves manufacturer, category, and model IDs through paginated lookup. No taxonomy or asset records are auto-created.
- **SMBIOS discovery**: Reads Type 1 (System Information), Type 2 (Baseboard), and Type 3 (System Enclosure) tables via `GetSystemFirmwareTable`.
- **WMI monitor discovery**: Queries `WmiMonitorID` in `root\wmi` for connected monitor manufacturer codes, product codes, serials, and manufacture dates.
- **DPAPI token protection**: API tokens are encrypted with machine-scope DPAPI by the LocalSystem service. Plaintext never persists to disk.
- **Named-pipe IPC**: The CLI communicates with the service over a named pipe restricted to SYSTEM and built-in Administrators via a DACL.
- **Operation journaling**: Prepared operations are durably journaled before remote execution. Recovery reconciles server state before retrying uncertain mutations.
- **Signed state**: Service state is HMAC-SHA256 signed with constant-time verification to detect tampering.
- **WiX 6 MSI installer**: Installs binaries, PDBs, and CycloneDX SBOMs; registers the service as automatic LocalSystem; adds `bin\` to system PATH; creates ProgramData with restricted ACLs.
- **Configurable monitor check-in**: `Manual` policy never auto-checks in; `AutoNonPortable` checks in absent monitors on non-portable chassis after a configurable threshold.

## Workspace

| Crate | Role | Pattern |
|---|---|---|
| `spotter-core` | Domain types, validation, IPC protocol, Snipe-IT models, SMBIOS parser, config schema, sync planning, signed state | Functional Core |
| `spotter-win32` | DPAPI encrypt/decrypt, named mutex, pipe DACL, elevation check | Imperative Shell (FFI) |
| `spotter-build` | RC resource embedding, manifest propagation | Build-time |
| `spotter-svc` | Windows service: FSM loop, WMI/SMBIOS discovery, HTTP client, IPC server, config/state I/O, operation journal, logging | Imperative Shell |
| `spotter-cli` | Operator CLI: clap commands, IPC client, output formatting, SCM registrar | Imperative Shell |

The service and CLI never import from each other. The core crate has zero I/O, zero async, and zero platform-specific FFI.

## Quick start

```powershell
# Install the MSI from an elevated terminal
msiexec /i SnipeSpotter-<version>-x64.msi /qn

# Configure the Snipe-IT connection
spotter-cli config set snipeit.url https://snipe.example.test
spotter-cli config set snipeit.checkout_status_id 5
spotter-cli config set snipeit.checkin_status_id 6
spotter-cli config set-token

# Trigger the first synchronization
spotter-cli sync

# Verify status
spotter-cli status --full
```

SnipeSpotter does not create Snipe-IT assets, manufacturers, categories, or models. The computer and monitor assets must already exist in Snipe-IT and be findable by serial number.

## Documentation

- [Architecture](docs/architecture.md) -- crate layout, FCIS boundaries, FSM states, sync flow, security model
- [Operator guide](docs/operator-guide.md) -- installation, configuration, CLI reference, troubleshooting, recovery
- [CI and release guide](docs/ci-guide.md) -- CI topology, release process, manual MSI build, lifecycle validation

## Requirements

- Windows x64
- Administrator access for installation and CLI operation
- Snipe-IT v8.2 or a version with compatible hardware lookup, PATCH, checkout, and check-in endpoints
- Existing Snipe-IT computer and monitor assets matched by serial number

## License

MIT
