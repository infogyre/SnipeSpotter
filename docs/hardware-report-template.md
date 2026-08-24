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

## Promotion assessment

### Stable assertions supported by evidence

The following assertions are stable across all 12 cells and both images. They are safe to promote as PR-level CI gates:

1. **SMBIOS acquisition succeeds** on both windows-2022 and windows-latest.
2. **SMBIOS structure count is 15** with the exact type histogram.
3. **WMI monitor query succeeds** and returns exactly 1 monitor.
4. **Monitor array lengths are bounded** (manufacturer/product/serial = 16, week/year = 1).
5. **Chassis is desktop (non-portable)** — chassis type 3, no portable/server/enclosure.
6. **All 4 hardware APIs succeed in both direct-admin and LocalSystem contexts.**

### Behaviors requiring physical hardware

The following cannot be verified on hosted runners and require physical/self-hosted hardware:

- Physical serial number fidelity (real vendor/model strings)
- EDID byte-level correctness
- Monitor hotplug detection
- Multi-monitor scenarios (>1 active monitor)
- Vendor-specific SMBIOS extensions
- Physical chassis type variety (laptop, server, tablet)

### Recommendation

Promote the 6 stable assertions above as hosted-runner CI gates. These verify that the production hardware acquisition pipeline works correctly on GitHub-hosted Windows runners without claiming physical hardware fidelity. Physical hardware qualification remains a separate, operator-defined follow-up.
