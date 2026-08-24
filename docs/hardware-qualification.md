# Hosted Windows hardware-visibility experiment

This experiment is a Phase 0 privacy-safe observation scaffold, not a hardware qualification gate. When dispatched on GitHub-hosted Windows, its generated matrix compares bounded capability and shape information from the required `windows-2022` and `windows-latest` labels (and explicitly selected optional labels) in direct-admin and temporary LocalSystem contexts, with three repetitions per selected image.

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

The workflow generates one random 32-byte HMAC key per image/repetition cell, holds it only in the runner temp directory, shares it with both contexts in that cell, and never uploads it. The same protected key is used by that cell's direct and LocalSystem collectors, making equal fragments comparable between those contexts. It is removed during failure-safe cleanup and is not a stable cross-run identifier or fixture.

## Approval checkpoint

The workflow records the named `awaiting_operator_hardware_approval` checkpoint after the matrix completes. Until an operator explicitly approves a follow-up, observations must not be promoted into permanent PR assertions, long-lived sanitized fixtures, or a physical/self-hosted hardware matrix.

Even after review, hosted virtual observations cannot prove physical serial fidelity, EDID behavior, hotplug behavior, vendor fidelity, or direct/service equality on physical machines. Those remain separate qualification questions.
