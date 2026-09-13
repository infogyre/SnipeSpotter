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

1. Installs `spotter-svc.exe` and `spotter-cli.exe` to `%ProgramFiles%\infogyre\SnipeSpotter\bin\`. The PDB debug symbols for both executables are not installed; they are published separately in the release symbols ZIP.
2. Installs CycloneDX SBOM JSONs to `%ProgramFiles%\infogyre\SnipeSpotter\sbom\`.
3. Registers `SnipeSpotter` as a Windows service with:
   - Executable path: `%ProgramFiles%\infogyre\SnipeSpotter\bin\spotter-svc.exe`
   - Start type: automatic
   - Logon account: `LocalSystem` (runtime principal: `NT AUTHORITY\SYSTEM`)
4. Adds `%ProgramFiles%\infogyre\SnipeSpotter\bin\` to the system `PATH` environment variable.
5. Creates `%ProgramData%\infogyre\SnipeSpotter\` with a blank `settings.toml` template.
6. Applies the initial protected ACL contract to the ProgramData tree. Directories receive explicit self FullControl plus inherit-only ContainerInherit/ObjectInherit GenericAll rules for `SYSTEM` and built-in `Administrators`; files receive only explicit self FullControl rules for those SIDs. Inherited or unauthorized Allow ACEs are rejected, while Deny ACEs remain preserved.

The installer creates the initial tree, but runtime startup is the security boundary: the service reapplies the protected contract to the root and existing runtime artifacts, and the atomic writer applies it to temporary files and reapplies it to each replaced destination. A standard user is not an allowed principal for the root, settings, state, HMAC key, journal, or logs.

The service is registered but not started during installation. When started, it remains `Running` while unconfigured and serves the administrator-only named pipe so the CLI can complete configuration; `Unconfigured` is an operating state, not a service-health failure. The CLI authenticates the connected pipe server before sending any request bytes by checking its server PID, LocalSystem owner SID, and SCM-registered executable image. This prevents a standard user from supplying a counterfeit endpoint during startup or a restart race. It does not protect against an administrator controlling SCM, replacing the service binary, or inspecting the machine. The service will start on the next boot, or you can start it manually after installation.

### Major upgrade

The MSI uses a fixed `UpgradeCode` with `<MajorUpgrade>` for version-to-version upgrades. Install the new MSI over the previous one:

```powershell
msiexec /i SnipeSpotter-<new-version>-x64.msi /qn /norestart
```

Configuration in `%ProgramData%` is preserved across upgrades (the settings component uses `NeverOverwrite="yes"`).

## Initial configuration

After installation, start the service and wait for bounded readiness from an elevated terminal before configuring it. The MSI adds the installed `bin\` directory to the system `PATH`, but an already-open shell may require a new shell, an explicit `$env:Path` refresh, or the full `%ProgramFiles%\infogyre\SnipeSpotter\bin\spotter-cli.exe` path. The README quick start gives the exact Start-Service, service-state, named-pipe, and `Unconfigured` status sequence exercised by the MSI lifecycle harness.

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

The service encrypts the token with machine-scope DPAPI. Application-owned token buffers use best-effort zeroizing owners; DPAPI output is wiped over its reported `cbData` bytes before `LocalFree`. This does not claim that library-owned input/deserialization or allocator copies can be erased. Re-enter the token after an OS reinstall or when moving configuration to another computer.

### Post-configuration

After setting the URL, status IDs, and token, the service transitions from `Unconfigured` to `Idle` and begins polling on the configured interval. The first `spotter-cli sync` triggers an immediate synchronization.

## Configuration reference

All configuration is stored in `%ProgramData%\infogyre\SnipeSpotter\settings.toml`. Use `spotter-cli config set` to modify fields; do not edit the file directly while the service is running.

Configuration loading is deliberately strict. Unknown keys are rejected both at the root and inside every nested table, so remove obsolete or misspelled keys before upgrading. The installer’s blank template remains valid and configurable. Snipe-IT identity is blank-or-complete: URL, checkout status ID, and check-in status ID must either all remain at their blank defaults or all be supplied with valid values. A token-only refresh remains allowed when recovery needs new credentials, but identity changes are refused while pending journal evidence exists.

### Snipe-IT settings

| Field | Default | Valid range | Notes |
|---|---|---|---|
| `snipeit.url` | empty | HTTPS URL | Required. Base URL of the Snipe-IT instance. Nonblank HTTP URLs are rejected; blank stays valid while configuration is staged. |
| `snipeit.checkout_status_id` | 0 | positive integer | Required. Snipe-IT status label ID for monitor checkout. |
| `snipeit.checkin_status_id` | 0 | positive integer | Required. Snipe-IT status label ID for monitor check-in. |
| `snipeit.api_token_encrypted` | empty | -- | Set via `config set-token`, not `config set`. DPAPI-encrypted. |

### Polling settings

| Field | Default | Valid range | Notes |
|---|---|---|---|
| `polling.interval_hours` | 4 | 1--168 | Hours between automatic sync cycles. |

**Automatic scheduling semantics.** The service reports `next_sync` in status output as the next *automatic enqueue attempt*, not a guaranteed remote execution time. Activation (first valid configuration) arms one full interval from activation. Saving an actual interval change re-arms from the accepted change; saving unrelated settings or the same value again never resets the deadline. A manual `sync` does not reset the automatic schedule. After each automatic sync completes (success or failure), the next interval arms from that completion, so a slow sync shifts the next attempt rather than causing catch-up bursts. While an automatic sync is in flight, `next_sync` is absent; it reappears after completion. If the endpoint becomes unconfigured, `next_sync` disappears until configuration is reactivated.

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

Without a path, displays all nine nonsecret settable fields in a fixed order plus any missing-configuration names, with secrets redacted. With a path, displays one `field: value` line. Selectable fields are the exact dotted names documented in the configuration reference (for example `snipeit.url`, `polling.interval_hours`); selection is validated locally before any transport call.

With `--json`, selector-free output preserves the complete redacted configuration envelope exactly as the service returns it; a selected field returns a typed scalar (string or number). The encrypted token is not selectable: use `config set-token` to change it, and unknown fields are rejected locally without echoing input.

### config set-token

```powershell
spotter-cli config set-token
```

Prompts for the Snipe-IT API token with no echo. The service encrypts it with machine-scope DPAPI before storing. For automation, pipe the token via stdin.

### status

```powershell
spotter-cli status [--full] [--json]
```

Displays the current service state. Without `--full`, shows the transient state, configured endpoint, and last/next sync times. With `--full`, additionally shows the matched asset and every tracked monitor with assignment, check-out, and absence details. Status reads return committed data only — a sync currently in flight appears as the transient `Syncing` state, while all inventory fields keep their last committed values — and they never touch disk, the journal, or the network. `next_sync` is the next automatic enqueue attempt (see [Polling settings](#polling-settings)); it is suppressed while unconfigured or while an automatic sync is in flight.

Use `--json` for machine-readable output. Named-pipe request reads and response writes/flushes each have a fixed five-second deadline. These transport deadlines do not cancel a command once the FSM has queued it: if the client times out, a mutation may still complete and be durably committed, so check status/recovery evidence before retrying.

### sync

```powershell
spotter-cli sync
```

Triggers an immediate synchronization. If a sync is already running, the request coalesces with the existing operation. Returns when the sync completes or fails. Before accepting new synchronization or forced check-in work, the owner first recovers pending journal evidence; recovery failure prevents new remote mutations. A recovered candidate becomes the active in-memory state immediately after its durable signed-state save, even if the later terminal journal append or compaction fails.

The HTTP client applies fixed safety limits to its HTTPS requests: 30 seconds per request; no redirects followed; at most 1 MiB per success response and 16 KiB retained for error classification; page size 100; and at most 100 requests, 10,000 rows, or 60 seconds for one pagination operation. Exceeding a limit fails the operation rather than returning partial results.

## HTTPS-only production endpoints

Production requires HTTPS. Every entry point that accepts a Snipe-IT URL — loaded settings, dotted IPC updates, and both production client constructors — rejects any nonblank `http://` URL, URLs with embedded credentials, query strings, fragments, control characters, malformed authorities, or out-of-range ports before any network I/O. Blank URLs remain valid while configuration is staged. There is no opt-out.

Existing HTTP installations fail closed with a bounded, actionable message; the service never rewrites persisted URLs or contacts the old HTTP endpoint automatically. If the service still holds unresolved mutation evidence (pending journal records), endpoint changes stay blocked by the pending-journal identity guard; operator-assisted recovery resolves the evidence first, then reconfigures the endpoint manually.

The client uses the OS certificate trust store (Windows machine trust). Install your CA chain through normal machine administration; no insecure bypass exists.

The named-pipe DACL still grants access only to SYSTEM and built-in Administrators. Authentication is per connection, uses the connected server process identity and SCM image path, and fails closed before serialization or writing when the service is unavailable, restarting, unqueryable, not LocalSystem, or running an unexpected executable.

### checkin

```powershell
spotter-cli checkin --all [-y]
spotter-cli checkin <serial> [-y]
```

Forces check-in of monitors regardless of check-in policy. `--all` checks in all absent monitors. `<serial>` checks in a specific monitor by serial number. The `-y` flag skips the confirmation prompt.

### service install / uninstall

Ordinary production `spotter-cli service install` and `service uninstall` use the fixed `SnipeSpotter` SCM and runtime identity, so they can target the same service registered by the MSI. `service install` creates an AutoStart, own-process service using the production executable, the `LocalSystem` account, and the documented description. It does not start the service.

The command contracts are:

| Situation | Result |
|---|---|
| `install`, service absent | Registers the service and returns success. |
| `install`, service already registered | Returns exit code 1 with `service ... is already installed`; it does not mutate the existing registration. |
| `install`, SCM reports marked for deletion | Returns exit code 1 with a marked-for-deletion error; it does not proceed. |
| `uninstall`, service absent | Returns exit code 1 with `service ... is not installed`. |
| `uninstall`, service running | Requests stop, waits up to 90 seconds for `Stopped`, requests deletion, then waits up to another 90 seconds for SCM disappearance. |
| `uninstall`, service already stopped | Requests deletion, then waits up to 90 seconds for SCM disappearance. |
| stop/delete wait times out or remains pending | Returns an error; an early return is not success. |

Only the elevated feature-gated test-support lane supplies hidden identity overrides. It generates `SnipeSpotterDirect-$RunIdentity` with matching unique pipe, mutex, data root, and test executable values, so lifecycle tests do not collide with the MSI’s `SnipeSpotter` service. The same duplicate, missing, stop, delete, and wait contracts apply to that generated test identity when the lane invokes the real CLI.

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

### Sync fails with HTTPS or certificate error

The service requires HTTPS and validates the endpoint against the OS certificate trust store.

1. Confirm the URL starts with `https://`: `spotter-cli config get snipeit.url`.
2. Confirm the Snipe-IT server presents a certificate chain that is trusted on this machine (corporate CA: install the chain through normal machine administration).
3. Confirm the certificate matches the hostname exactly; IP-address or mismatched-name endpoints fail verification.
4. A rejected certificate never falls back to HTTP; there is no bypass.

### Changing the endpoint while mutation evidence is pending

If recovery still holds unresolved mutation evidence, endpoint changes are blocked by the pending-journal identity guard, and the service will not rewrite URLs automatically. Resolve the evidence first (see recovery below), then update the endpoint with `config set`.

### Sync fails with "taxonomy unresolved"

1. Run `spotter-cli status --full` to see which assets and monitors are matched.
2. Confirm that the manufacturer, category, and model records exist in Snipe-IT for the local system and each monitor.
3. Confirm the records are unique (not duplicated). SnipeSpotter uses strict lookup and will not guess.

### Duplicate monitor serial warning

When more than one local monitor reports the same serial, SnipeSpotter treats that serial as present but ambiguous. It preserves existing assignment/absence state, plans no checkout, check-in, or asset update for that serial, and emits a bounded deterministic warning rather than guessing. Correct the local identity collision before expecting synchronization for those monitors.

### Monitor not checking in automatically

1. Verify `monitors.checkin_policy` is set to `auto_non_portable`.
2. Verify the computer's chassis type is non-portable. Laptops, tablets, and convertibles are excluded from auto check-in.
3. Verify the monitor has been absent for at least `monitors.checkin_threshold_hours`.
4. Check the service state for warnings via `spotter-cli status --full`.

### State HMAC verification failure

If the service logs an HMAC verification failure:

1. Stop the service: `sc stop SnipeSpotter`.
2. Preserve `state.toml`, the journal directory, and logs for diagnosis.
3. Do not delete a pending journal blindly. Recovery processes pending prepared and observed operations in durable prepared order, reconciles remote assignment, and keeps evidence until signed state is saved and the operation is committed.
4. If the state is unrecoverable, you may delete `state.toml` and `state-hmac-key.bin` to reset state. The next sync will rebuild monitor state from Snipe-IT.

### Blocked operation journal recovery

Journal admission runs before configuration branching, DPAPI decryption, remote-client construction, owner recovery, and IPC startup. A `NeedsOperatorRecovery`, `PreservationFailed`, or `Corrupt` result stops the service, leaves remote activity disabled, and writes a bounded log notice containing only the classification, evidence paths, and validated record count. The original journal bytes are not silently discarded. When preservation succeeds, the service retains a sibling quarantine file such as `operations.jsonl.quarantine-<unix-millis>-<hash>` and a sticky `operations.jsonl.recovery-blocked` marker. Quarantines are retained indefinitely.

Use this administrator procedure:

1. Stop the service: `sc stop SnipeSpotter`.
2. Read the service log and locate the exact quarantine and marker paths named by the recovery notice. Preserve both files and the original `operations.jsonl` while investigating.
3. Inspect the quarantined bytes with the service stopped. Validate the remote outcome directly in Snipe-IT; do not infer it from a partial local record and do not retry a mutation blindly.
4. If the remote outcome is confirmed applied, either restore a manually repaired journal containing only complete, newline-terminated records or remove the journal and marker to start clean. Removing the marker without reconciling the remote outcome is not recovery.
5. Restart the service and confirm it reaches `Running`. Marker absence plus a valid journal is the only accepted clean state; a valid-looking journal beside the marker remains blocked.

The blocked recovery result exposes no journal records, so ambiguous evidence cannot be replayed automatically. If quarantine or marker creation failed, leave the original bytes untouched and escalate with the service log; do not treat that outcome as clean.

Settings, state, keys, and journal compaction use same-directory replacement. The writer guarantees complete old-or-new destination content across the tested process-interruption points; it does not guarantee survival across physical power loss. It is a single-writer design. A failed write cleans up only its own temporary file, while startup cleanup removes stale temporary files only when the PID/nonce sidecar matches, the owner is dead, and the age threshold has elapsed. Leave files with missing or malformed metadata, a live/current owner, or insufficient age in place for diagnosis.

### After machine reinstallation

DPAPI ciphertext is bound to the machine. After an OS reinstall:

1. Reinstall the SnipeSpotter MSI.
2. Re-enter all configuration: URL, status IDs, and token.
3. The service will rebuild monitor state on the next sync.

## Hosted hardware experiment

This privacy-safe diagnostic experiment is separate from SnipeSpotter installation, synchronization, and MSI lifecycle validation. Its schema and validator can be checked on non-Windows systems, but collection, LocalSystem execution, protected approval, and artifact upload run only on GitHub-hosted Windows runners. It does not need a Snipe-IT URL, API token, administrator credential, or physical device.

An authorized operator may dispatch `.github/workflows/hardware-experiment.yml` with the exact `operator_acknowledgement=APPROVE` input. The workflow then runs the bounded matrix and pauses at the protected environment job named `awaiting_operator_hardware_approval`. Approving that environment only lets the post-observation checkpoint job complete; the workflow promotes nothing:

1. Set `operator_acknowledgement` to the exact value `APPROVE` when dispatching.
2. Use the default `images=windows-2022,windows-latest`; add `windows-2025` only when that optional hosted label is explicitly approved.
3. Keep `repetitions=3`; the preparation job rejects other values and reports optional images that were not selected.
4. Review both direct-admin and LocalSystem reports for each of the three repetitions per selected image.
5. Download reports only for the approved diagnostic question; artifacts expire after seven days.
6. Any runner-specific gate, persistent fixture, or physical matrix requires a separate operator-approved and reviewed repository change after the checkpoint report is reviewed.

The collector records the requested image label and alias, exact bounded runner/build metadata, process bitness, caller class, the numeric Windows process session ID captured in each context, classified API outcomes/durations, bounded SMBIOS lengths/type histograms, WMI counts/array lengths/placeholder classes, chassis class counts, and short HMAC fragments. It never records raw serials, asset tags, monitor strings, firmware/EDID, environment values, tokens, or exception text. One protected per-image/repetition HMAC key is shared by the direct and LocalSystem contexts, never uploaded, and removed by failure-safe cleanup. The validator runs before upload and emits only generic pass/fail output.

Treat a report as hosted-runner diagnostics only. It is not a hardware inventory record, physical hardware result, release approval, promotion signal, deployment, or Snipe-IT mutation. Do not use the existing raw recon scripts for this workflow; they serve a different fixture-generation purpose.

## Uninstallation

### Silent uninstall

```powershell
msiexec /x SnipeSpotter-<version>-x64.msi /qn /norestart /l*v uninstall.log
```

### What uninstall removes

- Stops and removes the Windows service registration.
- Removes `%ProgramFiles%\infogyre\SnipeSpotter\` (binaries, SBOMs).
- Removes the `bin\` entry from system PATH.
- Removes `%ProgramData%\infogyre\SnipeSpotter\` (settings, state, key, journal, logs).

Configuration is not preserved across uninstall. To preserve configuration, back up `%ProgramData%\infogyre\SnipeSpotter\settings.toml` before uninstalling.
