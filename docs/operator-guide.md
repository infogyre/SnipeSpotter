# SnipeSpotter operator guide

## Requirements

- Windows x64
- Administrator access for installation and CLI operation
- Snipe-IT 8.2 or a version with compatible hardware lookup, PATCH, checkout, and check-in endpoints
- Existing Snipe-IT computer and monitor assets; SnipeSpotter does not create assets or taxonomy records

## Installation

Install the MSI from an elevated terminal:

```powershell
msiexec /i SnipeSpotter-<version>-x64.msi /qn /l*v install.log
```

The MSI installs binaries and PDBs under `%ProgramFiles%\infogyre\SnipeSpotter\bin`, installs CycloneDX SBOMs under the adjacent `sbom` directory, registers `SnipeSpotter` as an automatic LocalSystem service, adds the binary directory to system PATH, and creates `%ProgramData%\infogyre\SnipeSpotter`. The ProgramData tree grants inheritable full control only to LocalSystem and the built-in Administrators group through installer-authored ACL entries.

## Initial configuration

```powershell
spotter-cli config set snipeit.url https://snipe.example.test
spotter-cli config set snipeit.checkout_status_id 5
spotter-cli config set snipeit.checkin_status_id 6
spotter-cli config set-token
spotter-cli sync
```

The service encrypts the token with machine-scope DPAPI. Re-enter it after an OS reinstall or when moving configuration to another computer.

## Configuration reference

| Field | Default | Notes |
|---|---:|---|
| `snipeit.url` | empty | Required HTTP(S) instance URL |
| `snipeit.checkout_status_id` | 0 | Required administrator-selected status |
| `snipeit.checkin_status_id` | 0 | Required administrator-selected status |
| `polling.interval_hours` | 4 | 1–168 |
| `logging.level` | `info` | trace/debug/info/warn/error |
| `logging.max_size_mb` | 10 | Rotation target |
| `logging.max_files` | 5 | Retained files |
| `monitors.checkin_policy` | `manual` | `manual` or `auto_non_portable` |
| `monitors.checkin_threshold_hours` | 24 | Absence threshold |

`auto_non_portable` checks in an absent monitor only when SMBIOS identifies the computer as non-portable and the full threshold has elapsed. A present monitor clears its absence timestamp.

## CLI commands

```text
spotter-cli config set <field> <value>
spotter-cli config get [field]
spotter-cli config set-token
spotter-cli status [--full] [--json]
spotter-cli sync
spotter-cli checkin --all -y
spotter-cli checkin <serial> -y
spotter-cli service install
spotter-cli service uninstall
```

Use `--json` for automation. Exit code 0 means success, 1 means an operational error, and 2 is reserved for a service-not-running condition.

## Troubleshooting and recovery

1. Run `spotter-cli status --full` and inspect the configured Snipe-IT instance.
2. Check logs under `%ProgramData%\infogyre\SnipeSpotter\logs`.
3. Confirm the API token can read and update hardware and perform checkout/check-in.
4. Confirm manufacturer, category, and model taxonomy records exist uniquely.
5. If state HMAC verification fails, stop the service and preserve `state.toml`, the journal, and logs for diagnosis. Do not delete a pending journal blindly; recovery reconciles remote assignment before retrying.
6. After machine reinstallation, run `config set-token` again.

To uninstall silently:

```powershell
msiexec /x SnipeSpotter-<version>-x64.msi /qn /l*v uninstall.log
```
