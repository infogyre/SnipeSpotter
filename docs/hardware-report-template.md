# Hosted Windows Hardware Experiment — Report

## Run metadata

- **Workflow run:** 32694136588
- **Commit:** 3c0a7d1
- **Images:** windows-2022, windows-latest
- **Repetitions:** 3 per image × 2 contexts (direct-admin, LocalSystem) = 12 cells
- **All cells:** success
- **Checkpoint:** awaiting_operator_hardware_approval — passed

## Exact image versions

| Label | ImageOS | OS build | Image version | PowerShell |
|-------|---------|----------|---------------|------------|
| windows-2022 | win22 | 20348 | 20260818.277.1 | 7.6.5 |
| windows-latest | win25-vs2026 | 26100 | 20260818.207.1 | 7.6.5 |

## Observations

### SMBIOS

Both images produce identical structural shapes across all repetitions and contexts:

- **Status:** ok (all 12 cells)
- **Raw length:** 1280 bytes
- **Structure count:** 15
- **Type histogram:** `{0:1, 1:1, 2:1, 3:1, 4:1, 11:1, 16:1, 17:2, 19:2, 20:2, 32:1, 127:1}`
- **Capped:** false

### WMI monitors

Both images produce identical monitor shapes:

- **Status:** ok (all 12 cells)
- **Count:** 1
- **Array lengths:** manufacturer_name [16], product_code_id [16], serial_number_id [16], week_of_manufacture [1], year_of_manufacture [1]
- **Placeholder classes:** empty, zero_terminated
- **Capped:** false

### Chassis

Both images produce identical chassis classification:

- **Status:** ok (all 12 cells)
- **Count:** 1
- **Class counts:** portable 0, desktop 1, server 0, enclosure 0, unknown 0

### API results

All 4 hardware APIs succeeded in all 12 cells:

| API | Result | Typical duration |
|-----|--------|-----------------|
| process_identity | ok | 0 ms |
| smbios | ok | 3–6 s |
| wmi_monitors | ok | 60–75 ms |
| chassis | ok | 10–25 ms |

### Privacy validation

All 12 reports passed the privacy validator:

- `hmac_key_uploaded`: false
- `raw_identifiers_emitted`: false
- `raw_payloads_emitted`: false
- `max_report_bytes`: 32768 (all reports under 3 KB)

### HMAC fragments

Machine HMAC fragments differ across images (expected — different VMs). Within-run fragments are identical across direct-admin and LocalSystem contexts, confirming identifier consistency within a single VM.

## Evidence summary

Record observations here; do not turn them into release, PR, or hardware gates in this template. The regular Windows workspace checks and the release build job run the required `spotter-svc/tests/hosted_hardware.rs` integration tests. The manually dispatched hardware experiment is separate: it collects redacted, bounded observations in three repetitions per selected hosted image, in both direct-admin and LocalSystem contexts. It does not run those integration tests or replace the regular checks.

For each observation, record the image label and alias, exact runner metadata, repetition, execution context, result, and relevant bounded measurement. Keep the report limited to the privacy schema. The observations in this document describe GitHub-hosted virtual machines, not physical hardware.

### Observation categories

Use the categories below when summarizing a run. They describe evidence to review, not proposed gates:

- SMBIOS acquisition result, bounded byte length, structure count, and type histogram.
- WMI monitor query result, bounded monitor count, array lengths, and placeholder classes.
- Chassis classification and bounded class counts.
- Process identity result and the numeric Windows process session ID captured in each context.
- API result classifications and durations for direct-admin and LocalSystem contexts.
- Privacy-validator result, report size, and whether raw identifiers or payloads were emitted.
- HMAC fragment comparison within a VM and across distinct hosted VMs, without recording the key.

### Limitations and follow-up

Hosted observations cannot verify the following physical or vendor-specific behaviors:

- Physical serial-number fidelity and real vendor/model strings.
- EDID byte-level correctness.
- Monitor hotplug detection.
- Multi-monitor scenarios.
- Vendor-specific SMBIOS extensions.
- Physical chassis-type variety, including laptops, servers, and tablets.

The `awaiting_operator_hardware_approval` job is a post-observation evidence checkpoint. It does not authorize the run before allocation and does not automatically promote an observation, fixture, release gate, or physical-hardware qualification. Any future gate or policy change requires a separate explicit decision and documented policy; this report alone is not that decision.
