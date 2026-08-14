# CI and release guide

## CI topology

SnipeSpotter uses a reusable-workflow pattern with path gating to keep CI fast.

### Workflows

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | Push to `main`, PRs | Path-gated caller that dispatches to `checks.yml` |
| `checks.yml` | `workflow_call` | Reusable workflow with all required gates |
| `release.yml` | Tag push `vX.Y.Z`, `workflow_dispatch` | Build, package, validate, and publish releases |
| `bump.yml` | `workflow_dispatch` | Bump workspace version and open a PR |
| `mutants.yml` | Weekly schedule | Mutation testing with `cargo-mutants` |

### Path gating

`ci.yml` uses `dorny/paths-filter` to detect changes in:
- `code` -- Rust source files
- `windows` -- code + installer + workflows

Only relevant paths trigger the reusable checks workflow. A `force_all` input bypasses gating for manual runs.

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
| PowerShell script lint | `Invoke-ScriptAnalyzer` on all `.ps1` files | Script quality |

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
2. **ACLs**: Verifies `ProgramData\infogyre\SnipeSpotter\` grants full control to `SYSTEM` and `Administrators`.
3. **PATH**: Verifies the `bin\` directory was added to the machine PATH.
4. **Service start/stop**: Starts the service, waits 3 seconds, checks state (Running or Stopped -- the unconfigured service may stop on its own), stops if running.
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
