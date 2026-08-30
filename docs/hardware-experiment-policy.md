# Hosted hardware experiment policy

## Status and scope

This is a privacy-safe diagnostic experiment for GitHub-hosted Windows runners. Its workflow and privacy contracts are implemented, but native Windows collection and the protected dispatch checkpoint execute only in GitHub Actions. It is not a product feature, release gate, hardware certification, device inventory process, or physical-device test matrix. It does not promote an artifact, publish a release, mutate Snipe-IT, or replace the existing lifecycle workflow.

The only supported entry point is the protected `workflow_dispatch` workflow:

- workflow: `.github/workflows/hardware-experiment.yml`
- approval environment: `hardware-experiment-approval`
- checkpoint job: `awaiting_operator_hardware_approval`
- collector: `scripts/hardware/collect_hardware.ps1`
- validator: `scripts/hardware/validate_report.py`
- report schema: `scripts/hardware/report-schema.json`

## Collection contract

The generated matrix contains one cell per selected image and repetition. The required images are `windows-2022` and `windows-latest`; `windows-2025` is optional and is skipped unless the operator explicitly includes it in `images`. The `images` input drives the matrix, unknown labels are rejected, and the workflow requires three repetitions. Each image/repetition cell emits two reports: one from `interactive-admin` and one from `LocalSystem`.

A report may contain only:

- exact runner image/build metadata: selected image, image OS/version labels, OS build, PowerShell version, runner architecture;
- process bitness (`32` or `64`);
- caller class, bounded context, and the numeric Windows process session ID captured in that context;
- classified API result and bounded duration for the Windows queries;
- bounded SMBIOS byte length, structure count, type histogram, and capped marker;
- WMI object count, fixed array lengths, placeholder class names, and capped marker;
- chassis class counts (`portable`, `desktop`, `server`, `enclosure`, `unknown`) and capped marker;
- at most 16-character lowercase HMAC-SHA256 fragments.

The collector may briefly hold raw values in process memory solely to classify lengths or compute HMAC fragments. It does not write, print, upload, or include those values in an exception. The workflow generates one random 32-byte key per image/repetition cell, protects the temporary key for SYSTEM and Administrators, and passes that same key to both direct and LocalSystem collectors in the cell so equal fragments are comparable. The key is never uploaded, is removed in failure-safe cleanup, and is not a stable cross-run identifier.

## Explicitly prohibited data

The validator rejects unknown fields and values that resemble or contain:

- serial numbers, asset tags, instance names, UUIDs/GUIDs, MAC addresses, hostnames, usernames, paths, or command lines;
- API tokens, bearer/basic credentials, secrets, passwords, private keys, certificates, or key material;
- raw SMBIOS/firmware bytes, hex/base64 payloads, raw EDID, or monitor identity strings;
- environment dumps or environment-derived maps;
- stack traces, exception text, or unbounded diagnostic strings;
- unbounded arrays/maps/strings or reports larger than 32 KiB.

Validator failures print only a generic count. They never echo report contents or the rejected key/value. Upload is allowed only after local validation succeeds.

## Artifact and retention rules

Each image/repetition cell uploads one artifact containing both context reports, with a seven-day maximum retention. Do not download, merge, or publish reports outside the repository's approved experiment review. Delete artifacts early when the experiment is cancelled or the diagnostic question is answered.

No workflow step may:

- build or promote a release;
- publish a release, package, attestation, or deployment;
- call Snipe-IT or mutate an external inventory;
- access a physical runner or claim physical hardware coverage;
- use `scripts/recon-smbios.ps1`, `scripts/recon-wmi-monitors.ps1`, or `scripts/recon-chassis.ps1` (those existing scripts intentionally emit raw fixture data and are out of scope).
