# SnipeSpotter operator guide

## Requirements

- Windows x64
- Administrator access for installation and CLI operation
- Snipe-IT v8.2 or a version with compatible hardware lookup, PATCH, checkout, and check-in endpoints
- Existing Snipe-IT computer and monitor assets; SnipeSpotter does not create assets or taxonomy records

## Installation

### Silent install

Install the MSI from an elevated terminal:

```powershell
msiexec /i SnipeSpotter-<version>-x64.msi /qn /norestart /l*v install.log
```

### Interactive install

Double-click the MSI in Explorer and follow the wizard. Administrator elevation is required.

### What the installer does

1. Installs `spotter-svc.exe`, `spotter-cli.exe`, and their PDBs to `%ProgramFiles%\infogyre\SnipeSpotter\bin\`.
2. Installs CycloneDX SBOM JSONs to `%ProgramFiles%\infogyre\SnipeSpotter\sbom\`.
3. Registers `SnipeSpotter` as a Windows service with:
   - Executable path: `%ProgramFiles%\infogyre\SnipeSpotter\bin\spotter-svc.exe`
   - Start type: automatic
   - Logon account: `LocalSystem` (runtime principal: `NT AUTHORITY\SYSTEM`)
4. Adds `%ProgramFiles%\infogyre\SnipeSpotter\bin\` to the system `PATH` environment variable.
5. Creates `%ProgramData%\infogyre\SnipeSpotter\` with a blank `settings.toml` template.
6. Applies a protected ACL contract to the ProgramData tree. Directories receive explicit self FullControl plus inherit-only ContainerInherit/ObjectInherit GenericAll rules for `SYSTEM` and built-in `Administrators`; files receive only explicit self FullControl rules for those SIDs. Inherited or unauthorized Allow ACEs are rejected, while Deny ACEs remain preserved.

The service is registered but not started during installation. When started, it remains `Running` while unconfigured and serves the administrator-only named pipe so the CLI can complete configuration; an unconfigured state is not a service-health failure. It will start on the next boot, or you can start it manually after installation.

### Major upgrade

The MSI uses a fixed `UpgradeCode` with `<MajorUpgrade>` for version-to-version upgrades. Install the new MSI over the previous one:

```powershell
msiexec /i SnipeSpotter-<new-version>-x64.msi /qn /norestart
```

Configuration in `%ProgramData%` is preserved across upgrades (the settings component uses `NeverOverwrite="yes"`).

## Initial configuration

After installation, configure the Snipe-IT connection from an elevated terminal:

```powershell
# Set the Snipe-IT instance URL
spotter-cli config set snipeit.url https://snipe.example.test

# Set the status IDs for monitor checkout and check-in
# These are administrator-selected Snipe-IT status label IDs
spotter-cli config set snipeit.checkout_status_id 5
spotter-cli config set snipeit.checkin_status_id 6

# Set the API token (encrypted with machine-scope DPAPI)
spotter-cli config set-token

# Trigger the first synchronization
spotter-cli sync

# Verify the service is running and synced
spotter-cli status --full
```

The `config set-token` command prompts for the token with no echo. For automation, pipe the token via stdin:

```powershell
$token | spotter-cli config set-token
```

The service encrypts the token with machine-scope DPAPI. Re-enter it after an OS reinstall or when moving configuration to another computer.

### Post-configuration

After setting the URL, status IDs, and token, the service transitions from `Unconfigured` to `Idle` and begins polling on the configured interval. The first `spotter-cli sync` triggers an immediate synchronization.

## Configuration reference

All configuration is stored in `%ProgramData%\infogyre\SnipeSpotter\settings.toml`. Use `spotter-cli config set` to modify fields; do not edit the file directly while the service is running.

### Snipe-IT settings

| Field | Default | Valid range | Notes |
|---|---|---|---|
| `snipeit.url` | empty | HTTP(S) URL | Required. Base URL of the Snipe-IT instance. |
| `snipeit.checkout_status_id` | 0 | positive integer | Required. Snipe-IT status label ID for monitor checkout. |
| `snipeit.checkin_status_id` | 0 | positive integer | Required. Snipe-IT status label ID for monitor check-in. |
| `snipeit.api_token_encrypted` | empty | -- | Set via `config set-token`, not `config set`. DPAPI-encrypted. |

### Polling settings

| Field | Default | Valid range | Notes |
|---|---|---|---|
| `polling.interval_hours` | 4 | 1--168 | Hours between automatic sync cycles. |

### Logging settings

| Field | Default | Valid range | Notes |
|---|---|---|---|
| `logging.level` | `info` | `trace`, `debug`, `info`, `warn`, `error` | Log verbosity. |
| `logging.max_size_mb` | 10 | 1--10240 | Rotation target size per log file. |
| `logging.max_files` | 5 | 1--1000 | Number of rotated log files to retain. |

### Monitor settings

| Field | Default | Valid range | Notes |
|---|---|---|---|
| `monitors.checkin_policy` | `manual` | `manual`, `auto_non_portable` | Whether absent monitors are automatically checked in. |
| `monitors.checkin_threshold_hours` | 24 | 1--8760 | Hours of absence before auto check-in (only with `auto_non_portable`). |

#### Check-in policy details

- **`manual`**: Monitors are never automatically checked in. Use `spotter-cli checkin --all` or `spotter-cli checkin <serial>` to force check-in.
- **`auto_non_portable`**: Checks in an absent monitor only when all of the following are true:
  1. The SMBIOS chassis type is non-portable (desktop, tower, server, etc.)
  2. The monitor was previously checked out to this computer
  3. The monitor has been absent for at least `checkin_threshold_hours`

Portable chassis types (laptop, notebook, tablet, convertible, detachable, etc.) never trigger auto check-in, even with this policy. This prevents checking in monitors that may be docked/undocked frequently.

A present monitor clears its `absent_since` timestamp. A newly absent monitor sets it to the current time. Continued absence preserves the original timestamp (the threshold is measured from first absence, not last sync).

## CLI commands

All commands require an elevated terminal (administrator).

### config set

```powershell
spotter-cli config set <dotted.path> <value>
```

Sets a configuration field by dotted path. Validates the value before sending to the service. Use `config set-token` for the API token, not `config set snipeit.api_token_encrypted`.

Examples:

```powershell
spotter-cli config set snipeit.url https://snipe.example.test
spotter-cli config set polling.interval_hours 2
spotter-cli config set monitors.checkin_policy auto_non_portable
spotter-cli config set logging.level debug
```

### config get

```powershell
spotter-cli config get [dotted.path]
```

Without a path, displays all configuration with secrets redacted. With a path, displays a single field.

### config set-token

```powershell
spotter-cli config set-token
```

Prompts for the Snipe-IT API token with no echo. The service encrypts it with machine-scope DPAPI before storing. For automation, pipe the token via stdin.

### status

```powershell
spotter-cli status [--full] [--json]
```

Displays the current service state. Without `--full`, shows the FSM state, last sync time, next sync time, and Snipe-IT URL. With `--full`, also shows the matched computer asset and known monitor inventory.

Use `--json` for machine-readable output.

### sync

```powershell
spotter-cli sync
```

Triggers an immediate synchronization. If a sync is already running, the request coalesces with the existing operation. Returns when the sync completes or fails.

### checkin

```powershell
spotter-cli checkin --all [-y]
spotter-cli checkin <serial> [-y]
```

Forces check-in of monitors regardless of check-in policy. `--all` checks in all absent monitors. `<serial>` checks in a specific monitor by serial number. The `-y` flag skips the confirmation prompt.

### service install / uninstall

Direct CLI SCM registration is intentionally separate from MSI registration. `service install` creates the sibling service with AutoStart, own-process type, the production service executable, the `LocalSystem` account, and the documented description. If the service is already installed, the command returns an actionable operational error without mutating it. `service uninstall` stops a running service, waits for `Stopped`, requests deletion, and waits for SCM disappearance; uninstalling a missing service returns an actionable operational error. A pending stop or delete timeout is a failure, not an accepted early result.

```powershell
spotter-cli service install
spotter-cli service uninstall
```

Installs or removes the Windows service via the SCM. The MSI installer handles this automatically; these commands are for manual registration without the MSI.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Operational error |
| 2 | Service not running |

## Troubleshooting

### Service will not start

1. Check the Windows event log for service start failures.
2. Check logs under `%ProgramData%\infogyre\SnipeSpotter\logs\`.
3. Run `spotter-cli status` to see the current FSM state. If `Unconfigured`, complete the initial configuration above.
4. Verify the service account is `LocalSystem`:
   ```powershell
   Get-CimInstance Win32_Service -Filter "Name='SnipeSpotter'" | Select-Object Name, StartName, StartMode, State
   ```

### Sync fails with authentication error

1. Verify the Snipe-IT URL is correct: `spotter-cli config get snipeit.url`.
2. Re-enter the API token: `spotter-cli config set-token`.
3. Verify the token has permissions to read hardware, update assets, and perform checkout/check-in.
4. Check that the Snipe-IT API version is compatible (v8.2 or later).

### Sync fails with "taxonomy unresolved"

1. Run `spotter-cli status --full` to see which assets and monitors are matched.
2. Confirm that the manufacturer, category, and model records exist in Snipe-IT for the local system and each monitor.
3. Confirm the records are unique (not duplicated). SnipeSpotter uses strict lookup and will not guess.

### Monitor not checking in automatically

1. Verify `monitors.checkin_policy` is set to `auto_non_portable`.
2. Verify the computer's chassis type is non-portable. Laptops, tablets, and convertibles are excluded from auto check-in.
3. Verify the monitor has been absent for at least `monitors.checkin_threshold_hours`.
4. Check the service state for warnings via `spotter-cli status --full`.

### State HMAC verification failure

If the service logs an HMAC verification failure:

1. Stop the service: `sc stop SnipeSpotter`.
2. Preserve `state.toml`, the journal directory, and logs for diagnosis.
3. Do not delete a pending journal blindly. Recovery reconciles remote assignment before retrying uncertain operations.
4. If the state is unrecoverable, you may delete `state.toml` and `state-hmac-key.bin` to reset state. The next sync will rebuild monitor state from Snipe-IT.

### After machine reinstallation

DPAPI ciphertext is bound to the machine. After an OS reinstall:

1. Reinstall the SnipeSpotter MSI.
2. Re-enter all configuration: URL, status IDs, and token.
3. The service will rebuild monitor state on the next sync.

## Hosted hardware experiment

This Phase 0 diagnostic scaffold is separate from SnipeSpotter installation, synchronization, and MSI lifecycle validation. Its contract and validator can be checked on non-Windows systems, but collection, LocalSystem execution, protected approval, and artifact upload run only on GitHub-hosted Windows runners. It does not need a Snipe-IT URL, API token, administrator credential, or physical device.

An authorized operator may dispatch `.github/workflows/hardware-experiment.yml` with the exact `operator_acknowledgement=APPROVE` input. The workflow then runs the bounded matrix and pauses at the protected environment job named `awaiting_operator_hardware_approval` before any observation can be promoted; that protected environment is a post-observation evidence checkpoint, not pre-run authorization:

1. Set `operator_acknowledgement` to the exact value `APPROVE` when dispatching.
2. Use the default `images=windows-2022,windows-latest`; add `windows-2025` only when that optional hosted label is explicitly approved.
3. Keep `repetitions=3`; the preparation job rejects other values and reports optional images that were not selected.
4. Review both direct-admin and LocalSystem reports for each of the three repetitions per selected image.
5. Download reports only for the approved diagnostic question; artifacts expire after seven days.
6. Do not promote runner-specific gates, persistent fixtures, or a physical matrix from the observations without a separate explicit operator approval after reviewing the checkpoint report.

The collector records the requested image label and alias, exact bounded runner/build metadata, process bitness, caller class, the numeric Windows process session ID captured in each context, classified API outcomes/durations, bounded SMBIOS lengths/type histograms, WMI counts/array lengths/placeholder classes, chassis class counts, and short HMAC fragments. It never records raw serials, asset tags, monitor strings, firmware/EDID, environment values, tokens, or exception text. One protected per-image/repetition HMAC key is shared by the direct and LocalSystem contexts, never uploaded, and removed by failure-safe cleanup. The validator runs before upload and emits only generic pass/fail output.

Treat a report as hosted-runner diagnostics only. It is not a hardware inventory record, physical hardware result, release approval, promotion signal, deployment, or Snipe-IT mutation. Do not use the existing raw recon scripts for this workflow; they serve a different fixture-generation purpose.

## Uninstallation

### Silent uninstall

```powershell
msiexec /x SnipeSpotter-<version>-x64.msi /qn /norestart /l*v uninstall.log
```

### What uninstall removes

- Stops and removes the Windows service registration.
- Removes `%ProgramFiles%\infogyre\SnipeSpotter\` (binaries, PDBs, SBOMs).
- Removes the `bin\` entry from system PATH.
- Removes `%ProgramData%\infogyre\SnipeSpotter\` (settings, state, key, journal, logs).

Configuration is not preserved across uninstall. To preserve configuration, back up `%ProgramData%\infogyre\SnipeSpotter\settings.toml` before uninstalling.
