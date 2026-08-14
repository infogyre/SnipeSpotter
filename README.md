# SnipeSpotter

SnipeSpotter synchronizes Windows system and monitor inventory with an existing Snipe-IT instance. It uses serial-number matching, strict taxonomy lookup, interval polling, administrator-only IPC, and machine-scope DPAPI token protection.

## Workspace

- `spotter-core` — pure configuration, parsing, planning, IPC, and signed-state logic
- `spotter-win32` — DPAPI, mutex, pipe security, and elevation FFI
- `spotter-svc` — Windows service shell
- `spotter-cli` — operator CLI
- `spotter-build` — Windows resource build support
- `installer` — WiX 6 MSI authoring

## Quick start

```powershell
msiexec /i SnipeSpotter-<version>-x64.msi
spotter-cli config set snipeit.url https://snipe.example.test
spotter-cli config set snipeit.checkout_status_id 5
spotter-cli config set snipeit.checkin_status_id 6
spotter-cli config set-token
spotter-cli sync
```

SnipeSpotter does not create Snipe-IT assets, manufacturers, categories, or models.

See:

- [Architecture](docs/architecture.md)
- [Operator guide](docs/operator-guide.md)
- [CI and release guide](docs/ci-guide.md)
