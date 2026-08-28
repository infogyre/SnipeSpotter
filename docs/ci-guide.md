# CI and release guide

## CI topology

SnipeSpotter uses a reusable-workflow pattern with path gating to keep CI fast.

### Workflows

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | Push to `main`, PRs | Path-gated caller that dispatches to `checks.yml` |
| `checks.yml` | `workflow_call` | Reusable workflow with all required gates |
| `release.yml` | Tag push `vX.Y.Z`, `workflow_dispatch` | Build, package, validate, and publish releases |
| `elevated-windows.yml` | Reusable `workflow_call` | Elevated MSI/service lifecycle and cleanup lane |
| `hardware-experiment.yml` | Protected `workflow_dispatch` | Privacy-safe hosted hardware observations; stops at operator approval |
| `bump.yml` | `workflow_dispatch` | Bump workspace version and open a PR |
| `mutants.yml` | Weekly schedule | Mutation testing with `cargo-mutants` |

### Path gating

`ci.yml` uses `dorny/paths-filter` to detect changes in the `run_checks` and `run_elevated` path sets. Only relevant paths trigger each reusable workflow. When elevated paths are not relevant, `elevated-skip` emits an explicit successful result and `ci-success` consumes it; relevant paths require the reusable elevated workflow result. A `force_all` input bypasses gating for manual runs.

### Jobs

#### Linux core checks (`ubuntu-latest`)

| Step | Command | Gate |
|---|---|---|
| Workspace formatting | `cargo fmt --all --check` | Format |
| Product identity consistency | `python3 scripts/check-product-identity.py` | Identity |
| Core clippy | `cargo clippy -p spotter-core --all-targets -- -D warnings` | Lint |
| Core tests | `cargo test -p spotter-core` | Tests |
| Dependency policy | `cargo install cargo-deny --locked && cargo deny check` | Supply chain |
| Core coverage | `cargo install cargo-llvm-cov --locked && cargo llvm-cov --package spotter-core --all-features --fail-under-lines 80` | Coverage |

Linux only builds and tests `spotter-core` (the cross-platform crate). Windows-only crates are excluded via `default-members = ["spotter-core"]`.

#### Windows workspace checks (`windows-latest`)

| Step | Command | Gate |
|---|---|---|
| Workspace tests | `cargo test --workspace --all-targets` | Tests |
| Workspace clippy | `cargo clippy --workspace --all-targets -- -D warnings` | Lint |
| PowerShell script lint | `Invoke-ScriptAnalyzer` on all `.ps1` and `.psm1` files | Script quality |

#### Package contract (`ubuntu-latest`)

Verifies the workspace has exactly 5 packages with the expected names: `spotter-core`, `spotter-win32`, `spotter-build`, `spotter-svc`, `spotter-cli`.

#### CI success (aggregate gate)

A single required status check that depends on all three jobs above. All must pass for the gate to succeed.

### Action pinning policy

All third-party GitHub Actions are pinned to full commit SHAs with version comments. Never replace a SHA with a floating tag. The `paths-filter` action is pinned to `v3.0.4` and the `attest-build-provenance` action to `v2`.

### Workflow security

- `persist-credentials: false` on all read-only checkouts.
- All shell-consumed GitHub expressions are passed through environment variables to prevent template injection.
- `actionlint` and `zizmor` validate workflow security locally and in CI.

## Release process

### Automated path (recommended)

1. **Bump version**: Use the bump workflow with `patch`, `minor`, or `major`.
   ```bash
   gh workflow run bump.yml -f level=patch
   ```
2. **Merge the version PR**: Review and merge the PR that updates `Cargo.toml` and `Cargo.lock`.
3. **Tag the release**: Tag the main-branch commit as `vX.Y.Z`.
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
4. **Release workflow runs automatically**: The tag push triggers `release.yml`, which:
   - **Verify job** (Ubuntu): Confirms the tag points to `main`, validates the tag version matches `Cargo.toml`, and runs the full test suite.
   - **Build job** (Windows): Builds `spotter-svc.exe` and `spotter-cli.exe` with `cargo build --release --locked --target x86_64-pc-windows-msvc`, asserts exact `.exe` and underscore-named `.pdb` files exist, and uploads a closed artifact inventory.
   - **Package job** (Windows): Installs WiX 6, verifies `wix --version`, generates CycloneDX SBOMs, builds the MSI with explicit version/platform properties, renames it deterministically, validates the MSI lifecycle (install, service registration, start/stop, ACLs, PATH, uninstall), and uploads packaged artifacts.
   - **Aggregate job** (Ubuntu): Downloads all artifacts, creates `SHA256SUMS`, generates SLSA provenance attestation, creates a draft GitHub Release, and uploads all assets (MSI, supplemental ZIP with exes + PDBs + SBOMs, checksums).
   - **Publish job**: Flips the draft release to published only after all preceding jobs pass.

### Dry run path (validation without publishing)

Trigger the release workflow manually without a tag:

```bash
gh workflow run release.yml --ref main
```

This runs every step except attestation and publish. Use it to validate the full artifact pipeline before cutting a real release.

### Release-candidate path

Before the first production release, create a release-candidate tag (`v0.1.0-rc1`) to exercise the end-to-end draft/publish path. Verify the GitHub Release is created as a draft, then published, with all expected assets.

## Manual MSI build

From a Windows developer shell with Rust MSVC, .NET, and WiX 6:

```powershell
# Build release binaries
cargo build -p spotter-svc -p spotter-cli --release --locked --target x86_64-pc-windows-msvc

# Determine the version
$version = (cargo metadata --no-deps --format-version 1 | ConvertFrom-Json).packages[0].version

# Stage binaries (must contain exactly: spotter-svc.exe, spotter-cli.exe, spotter_svc.pdb, spotter_cli.pdb)
$stage = "release-stage"
New-Item -ItemType Directory -Force $stage
Copy-Item target/x86_64-pc-windows-msvc/release/spotter-svc.exe $stage
Copy-Item target/x86_64-pc-windows-msvc/release/spotter-cli.exe $stage
Copy-Item target/x86_64-pc-windows-msvc/release/spotter_svc.pdb $stage
Copy-Item target/x86_64-pc-windows-msvc/release/spotter_cli.pdb $stage

# Install WiX 6
dotnet tool install --global wix --version 6.0.0
wix --version

# Build the MSI
dotnet build installer/Product.wixproj -c Release -p:Platform=x64 -p:ProductVersion=$version -p:StageDir="$stage"

# The MSI is at installer/bin/x64/Release/en-US/SnipeSpotter.msi
```

The staging directory must contain exactly the expected executables and PDBs. Do not rebuild binaries from inside the packaging step. The CI workflow enforces this by downloading a pre-built artifact and verifying the inventory before packaging.

## MSI lifecycle validation

The lifecycle test is `scripts/test-msi-lifecycle.ps1`. On an elevated Windows runner, it:

1. **Install**: Silently installs the MSI and verifies:
   - Service `SnipeSpotter` is registered with automatic start type and `LocalSystem` account
   - Service executable path matches `%ProgramFiles%\infogyre\SnipeSpotter\bin\spotter-svc.exe`
   - All expected files exist: `bin\spotter-svc.exe`, `bin\spotter-cli.exe`, `bin\spotter_svc.pdb`, `bin\spotter_cli.pdb`, `sbom\*.cdx.json`, `settings.toml`
2. **ACLs**: Verifies the protected Windows semantic contract for every runtime artifact. The data directory must have exactly one explicit self FullControl Allow and one explicit inherit-only ContainerInherit/ObjectInherit GenericAll Allow for each `SYSTEM` and built-in `Administrators` SID; each file must have exactly one explicit self FullControl Allow for each SID. Inherited and unauthorized Allow ACEs, duplicates, and mask/flag mismatches fail validation. Deny ACEs are preserved and are not counted as Allows.
3. **PATH**: Verifies the `bin\` directory was added to the machine PATH.
4. **Service health**: Starts the service, requires it to remain `Running` for the configured stability window, verifies the running process owner is `NT AUTHORITY\\SYSTEM`, verifies the fixed named pipe is present, invokes the installed CLI for JSON status, and requires an `Unconfigured` response before stopping it.
5. **Uninstall**: Silently uninstalls and verifies:
   - Service is no longer registered
   - `Program Files\infogyre\SnipeSpotter\` is removed
   - `bin\` entry is removed from machine PATH

### Major-upgrade test

Pass `-PreviousMsiPath` to exercise major-upgrade configuration preservation:

```powershell
./scripts/test-msi-lifecycle.ps1 -MsiPath "packaged/SnipeSpotter-0.1.0-x64.msi" -PreviousMsiPath "packaged/SnipeSpotter-0.0.9-x64.msi"
```

This installs the previous MSI, adds a marker to `settings.toml`, installs the new MSI over it, and verifies the marker survives the upgrade.

### Elevated coverage and cleanup

The reusable `elevated-windows.yml` lane is invoked for relevant PR paths and by the release workflow after the MSI is built. It uses unique run identities, bounded condition-based waits, sustained service/pipe checks where available, and failure-safe cleanup. A cleanup failure is a failed lifecycle result; it is never silently accepted. The PR caller emits an explicit successful skip when no elevated path is relevant so the aggregate `ci-success` check remains deterministic.

### Hosted hardware experiment

`hardware-experiment.yml` is protected and manually dispatched. Its `images` input drives the generated matrix; `windows-2022` and `windows-latest` are always required, while the optional `windows-2025` label is scheduled only when explicitly requested. The fixed `repetitions=3` input creates three repetitions per selected image. Each image/repetition cell runs both direct-admin and LocalSystem collection with one protected per-cell HMAC key, validates both reports before upload, records the requested image label/alias and exact runner metadata plus the numeric session ID from each process context, and removes keys and temporary reports during failure-safe cleanup. Unsupported optional images are reported in the preparation job's machine-readable `skipped_images` output. The workflow stops at `awaiting_operator_hardware_approval`; hosted observations are evidence only and do not implement release promotion or physical-hardware qualification.

### Runner policy

If GitHub-hosted runner policy prevents a required SCM or MSI operation, treat that as a blocking CI infrastructure defect. First adapt the test to supported administrative mechanisms. If impossible, stop before release and require an operator decision about a dedicated Windows test runner. Do not silently downgrade lifecycle coverage to manual-only.

## Recon scripts

Three PowerShell scripts capture hardware data for test fixture generation:

| Script | Data source | Output |
|---|---|---|
| `scripts/recon-smbios.ps1` | `GetSystemFirmwareTable` (SMBIOS raw bytes) | `smbios-fixture.json` (hex + base64) |
| `scripts/recon-wmi-monitors.ps1` | `WmiMonitorID` in `root\wmi` | `wmi-monitors-fixture.json` (manufacturer, product, serial, week/year) |
| `scripts/recon-chassis.ps1` | `Win32_SystemEnclosure.ChassisTypes` | `chassis-fixture.json` (chassis type, portability flag, enclosure metadata) |

Run these on target hardware to generate realistic test fixtures for the SMBIOS parser and monitor discovery code. The scripts accept a `-OutputPath` parameter to control where the JSON fixture is written.

## Hosted hardware experiment

The hosted experiment is intentionally separate from the raw fixture scripts above. Run `.github/workflows/hardware-experiment.yml` only through `workflow_dispatch`; it is not called by `ci.yml`, `checks.yml`, or `release.yml`.

### Approval and dispatch

1. Create a protected GitHub environment named `hardware-experiment-approval` and require an operator reviewer. Do not put secrets in this environment; the experiment does not need credentials.
2. Dispatch the workflow with `operator_acknowledgement=APPROVE`, the default `images=windows-2022,windows-latest` (or include the explicitly approved optional `windows-2025` label), and `repetitions=3`.
3. The job named `awaiting_operator_hardware_approval` runs after the Windows matrix and pauses at the protected environment before any observation can be promoted. Its gate rejects acknowledgements other than the exact word `APPROVE`; it is a post-observation evidence checkpoint, not a pre-allocation authorization gate.
4. `windows-2022` and `windows-latest` are required. The preparation job reports optional `windows-2025` as skipped when it is not requested; an unknown image label is rejected rather than replacing either required image.

The generated matrix runs three repetitions per selected image. Each image/repetition cell collects both direct-admin and LocalSystem reports with one shared protected HMAC key, derives the session ID inside each process context, validates both locally, and uploads only the redacted JSON reports with seven-day retention. The matrix has no package, release, publish, promotion, deployment, Snipe-IT, or physical-hardware step. A failing validator prevents upload; cleanup removes the key, service host files, and reports and fails if cleanup cannot complete.

### Privacy gates

The collector is `scripts/hardware/collect_hardware.ps1`; do not substitute the existing `scripts/recon-*.ps1` scripts because those intentionally write raw fixture data. The upload-side command is:

```powershell
python scripts/hardware/validate_report.py --input artifacts/hardware-report.json
```

The validator enforces the closed schema in `scripts/hardware/report-schema.json` and the stricter pure policy in `scripts/hardware/privacy_policy.py`. It rejects raw identifiers, tokens, firmware/EDID payloads, environment dumps, exception text, unbounded collections/strings, and reports over 32 KiB. The collector uses an ephemeral random HMAC key only to generate short fragments; the key is never uploaded. Validation output is generic and does not echo report contents.

This experiment provides observations about GitHub-hosted runner images only. It is not evidence about physical hardware and must not be used as a release promotion or lifecycle sign-off.
