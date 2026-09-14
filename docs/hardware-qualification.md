# Hosted Windows hardware-visibility experiment

This experiment is a privacy-safe hosted-runner observation, not a hardware qualification gate. When dispatched on GitHub-hosted Windows, its generated matrix compares bounded capability and shape information from the required `windows-2022` and `windows-latest` labels (and explicitly selected optional labels) in direct-admin and temporary LocalSystem contexts, with three repetitions per selected image. Hosted virtual evidence is not proof of physical hardware behavior. Approval of the named checkpoint only lets that post-observation job complete; it promotes nothing.

## Data policy

The diagnostic emits only:

- runner image and build metadata;
- process bitness, caller class, and the numeric Windows process session ID captured in that process context;
- classified API outcomes and bounded durations;
- RSMB length and a bounded SMBIOS type histogram;
- WMI row counts, array lengths, and placeholder classes;
- normalized chassis classes/counts;
- optional within-run keyed HMAC fragments.

It never uploads raw SMBIOS bytes, serials, UUIDs, asset tags, monitor names, EDID, environment dumps, tokens, HMAC keys, or unbounded exception text. The validator rejects unknown fields, oversized values, token-like content, and key/firmware payloads before an artifact can be retained.

The workflow creates one random 32-byte HMAC key per image/repetition cell directly in a protected per-cell root under `%ProgramData%\SnipeSpotterHardware\<cell-id>`, shares it with both contexts in that cell, and never uploads it. The key retains `SYSTEM:(R)` / `Administrators:(F)` under the accepted SPOTR-24 policy. Config, collector, support executable, key, and output are staged in that root; `RUNNER_TEMP` is not used as a plaintext staging area. The same protected key is used by that cell's direct and LocalSystem collectors, making equal fragments comparable between those contexts. It is removed during failure-safe cleanup after service deletion is confirmed and is not a stable cross-run identifier or fixture.

## Protected staging and path policy

The per-cell staging root is protected with inheritance disabled and explicit `SYSTEM`/`Administrators` control. The host opens path components without following reparse points, checks final-path containment, rejects unauthorized write access and writable ancestors, and validates the config before SCM registration and again immediately before launch. TrustedInstaller is accepted only for an allowlisted system PowerShell executable layout; ordinary experiment inputs must remain administrator- or SYSTEM-owned. The workflow consumes validated bound objects from the protected root, so a standard-user replacement attempt cannot substitute a collector, key, config, or output path. Administrators and the service's elevated context remain outside this boundary.

## Approval checkpoint

The workflow records the named `awaiting_operator_hardware_approval` checkpoint after the matrix completes. Approving the protected environment only lets this checkpoint job complete; the workflow contains no promotion step. Permanent PR assertions, long-lived sanitized fixtures, or a physical/self-hosted hardware matrix require a separate operator-approved and reviewed change.

Even after review, hosted virtual observations cannot prove physical serial fidelity, EDID behavior, hotplug behavior, vendor fidelity, or direct/service equality on physical machines. Those remain separate qualification questions.
