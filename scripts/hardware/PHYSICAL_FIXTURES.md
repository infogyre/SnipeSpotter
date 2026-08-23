# Physical Hardware Fixture Capture

These scripts capture real SMBIOS and WMI monitor data from a Windows machine
and convert it into CI-ready test fixtures.

## When to use

Run `Capture-PhysicalFixtures.ps1` on a physical Windows laptop (not a VM)
with real monitors connected. The captured data provides structural shapes
that synthetic fixtures cannot: multi-string SMBIOS tables, real chassis
type encodings, actual WMI array lengths, and zero-terminated string edge
cases.

## Privacy

The capture script replaces all identifiers (serials, asset tags, UUIDs,
manufacturer names, product codes) with deterministic placeholders that
preserve byte length and encoding. No real identifiers are emitted. The
converter script validates this before writing fixtures.

**Do not commit capture output from a machine you do not own.** The
placeholders are deterministic, but the structural metadata (chassis type,
SMBIOS structure counts, monitor count) still reveals hardware class
information.

## Steps

### 1. Capture on the laptop

```powershell
pwsh -File scripts/hardware/Capture-PhysicalFixtures.ps1 `
    -OutputPath .\capture.json `
    -Label 'laptop-model-xyz'
```

This produces `capture.json` with:
- `smbios.raw_hex` — hex-encoded SMBIOS buffer with identifiers redacted
- `smbios.summary` — structure type histogram, version, counts
- `wmi_monitors` — per-monitor shapes with placeholder identifiers
- `chassis.types` — numeric chassis type values
- `metadata` — OS build, PowerShell version, capture timestamp

### 2. Convert to CI fixtures

```powershell
pwsh -File scripts/hardware/Convert-PhysicalFixtures.ps1 `
    -InputPath .\capture.json `
    -OutputDir tests\fixtures\physical
```

This produces:
- `smbios_fixture.bin` — raw bytes for `parse_smbios_tables` tests
- `wmi_monitors.json` — normalized monitor shapes for `convert_monitor` tests
- `chassis.json` — chassis type values for `ChassisType::is_portable` tests
- `fixture_summary.json` — human-readable index

### 3. Validate privacy

```bash
python scripts/hardware/validate_physical_fixture.py --input tests/fixtures/physical/
```

This checks that no real identifiers, raw firmware bytes, or unredacted
strings remain in the fixture files.

### 4. Commit fixtures

Commit the `tests/fixtures/physical/` directory to the repository. CI tests
can then `include_bytes!("../tests/fixtures/physical/smbios_fixture.bin")`
and `include_str!("../tests/fixtures/physical/wmi_monitors.json")` to
exercise the real hardware shapes.

## What the fixtures prove

- SMBIOS parser handles real multi-structure tables with correct string
  indexing, not just minimal synthetic fixtures.
- WMI monitor conversion handles real array shapes (variable-length
  zero-terminated arrays, empty arrays, multi-byte characters).
- Chassis type classification matches real hardware encodings.
- The sync planner receives realistic `SystemInfo` and `Vec<MonitorInfo>`
  shapes from physical hardware.
