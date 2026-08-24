# Hardware experiment report template

This template documents the shape of a privacy-safe report. It is not a fixture and must not be populated with real identifiers. The collector creates the actual JSON and the validator enforces `scripts/hardware/report-schema.json` plus additional token/payload checks.

```json
{
  "schema_version": 1,
  "experiment": {
    "image": "windows-2022",
    "context": "interactive-admin",
    "repetition": 1,
    "caller_class": "interactive-admin",
    "session_id": 1
  },
  "build": {
    "image": "windows-2022",
    "image_alias": "windows-2022",
    "image_os": "<bounded runner label>",
    "image_version": "<bounded runner label>",
    "os_build": 20348,
    "powershell_version": "<bounded version>",
    "runner_architecture": "X64"
  },
  "process": {"bitness": 64},
  "privacy": {
    "hmac_algorithm": "HMAC-SHA256",
    "hmac_key_uploaded": false,
    "raw_identifiers_emitted": false,
    "raw_payloads_emitted": false,
    "max_report_bytes": 32768
  },
  "api_results": [
    {"api": "<classified API name>", "result": "ok", "duration_ms": 12}
  ],
  "smbios": {
    "status": "ok",
    "length": 256,
    "structure_count": 7,
    "type_histogram": {"1": 1, "2": 1, "3": 1},
    "capped": false
  },
  "wmi": {
    "status": "ok",
    "count": 2,
    "array_lengths": {
      "manufacturer_name": [4, 4],
      "product_code_id": [8, 8],
      "serial_number_id": [12, 12],
      "week_of_manufacture": [1, 1],
      "year_of_manufacture": [1, 1]
    },
    "placeholder_classes": ["monitor_identifier"],
    "capped": false
  },
  "chassis": {
    "status": "ok",
    "count": 1,
    "class_counts": {
      "portable": 0,
      "desktop": 1,
      "server": 0,
      "enclosure": 0,
      "unknown": 0
    },
    "capped": false
  },
  "hmac_fragments": [
    {"kind": "machine", "fragment": "<16 lowercase hex characters>"}
  ]
}
```

The angle-bracket values above are documentation placeholders only. Do not replace them with serials, EDID, firmware, environment, token, or exception data. `image_alias` must equal `image`. The workflow artifact is bounded to 32 KiB and retained for at most seven days; the per-cell HMAC key is never part of the report or artifact.
