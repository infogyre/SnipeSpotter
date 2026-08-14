# CI and release guide

## Checks

The reusable `.github/workflows/checks.yml` owns the required `ci-success` gate.

Linux runs formatting, strict Clippy and tests for `spotter-core`, dependency policy, and line coverage. Windows runs workspace tests and strict Clippy so DPAPI, SCM, named-pipe, and resource code compile on the supported platform. Workflow changes should also pass `actionlint` and `zizmor`.

All third-party actions must be pinned to verified full commit SHAs. Never replace a SHA with a floating tag.

## Release process

1. Use the bump workflow with `patch`, `minor`, or `major`.
2. Review and merge the generated version PR.
3. Tag the main-branch commit as `vX.Y.Z`.
4. The release workflow verifies the tag/version, runs tests, builds `spotter-svc.exe` and `spotter-cli.exe` plus underscore-named PDBs, packages WiX 6 MSI and CycloneDX SBOMs, generates checksums/provenance, creates a draft release, and publishes only after all gates pass.

A workflow-dispatch dry run builds and validates the closed artifact inventory without publishing. The packaging job also silently installs the generated MSI, verifies SCM registration, LocalSystem identity, automatic startup, installed binaries/PDBs/SBOMs, ProgramData ACLs, machine PATH integration, service start/stop, uninstall cleanup, and uploads MSI logs even on failure.

## Manual MSI build

From a Windows developer shell with Rust MSVC, .NET, and WiX 6:

```powershell
cargo build -p spotter-svc -p spotter-cli --release --locked --target x86_64-pc-windows-msvc
$version = (cargo metadata --no-deps --format-version 1 | ConvertFrom-Json).packages[0].version
dotnet tool install --global wix --version 6.0.0
wix --version
dotnet build installer/Product.wixproj -c Release -p:Platform=x64 -p:ProductVersion=$version -p:StageDir=<staging-directory>
```

The staging directory must contain exactly the expected executables and PDBs. Do not rebuild binaries from inside the packaging step.

## MSI lifecycle validation

On an elevated Windows runner:

1. Install silently and query SCM path, automatic start type, and LocalSystem account.
2. Start and stop the unconfigured service.
3. Verify SYSTEM/Administrators ACLs on ProgramData files and logs.
4. Verify PATH installation and CLI-to-service token setup.
5. Install the previous MSI, configure it, then major-upgrade and confirm configuration survives.
6. Uninstall and confirm install-owned resources are removed.

The lifecycle implementation is `scripts/test-msi-lifecycle.ps1`. Pass `-PreviousMsiPath` to exercise major-upgrade configuration preservation when a previous test MSI is available.

If GitHub-hosted runner policy prevents these operations, treat that as a blocking CI infrastructure defect rather than silently downgrading the test.
