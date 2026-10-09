# Asset-tag authority (SPOTR-48)

Snipe-IT is authoritative for a computer's managed asset tag. SnipeSpotter does
not populate or replace that field from SMBIOS firmware. This applies to every
firmware value: empty strings, whitespace, vendor placeholders, valid-looking
tags, and tags equal to the current managed value. A missing or empty Snipe-IT
tag does not grant firmware update authority. Manage asset tags in Snipe-IT.

The synchronization planner omits `asset_tag` entirely from computer PATCH
bodies. Supported serial-number and resolved-model updates still proceed. No
configuration switch enables firmware-tag synchronization.

## Upgrading with pending operations

Older versions may have written pending computer PATCH operations containing
`asset_tag` into the operation journal. New planning behavior alone cannot make
those persisted operations safe. Execution and recovery reject tag-bearing
PATCH operations before sending them and retain their journal evidence for
operator reconciliation. This also applies to valid-looking or unchanged tag
values; the journal does not establish authority to manage Snipe-IT tags.

If recovery is blocked for this reason, stop the service and preserve the
journal and signed state before investigation. Reconcile the pending operation
with the authoritative Snipe-IT asset through the
[policy-blocked legacy recovery procedure](operator-guide.md#policy-blocked-legacy-operations-and-ownerless-monitor-state). Do not delete journal evidence or manually strip a field: operation
identifiers and recovery evidence can be bound to the original payload, and a
previous attempt may already have reached Snipe-IT. Confirm the managed tag in
Snipe-IT before resuming synchronization.

## Regression coverage

The planner tests cover empty, whitespace, placeholder, legitimate differing,
and equal firmware tags against missing, empty, whitespace, and managed remote
tags. They verify that tag differences alone produce no PATCH, and serialize
real planned requests to verify that serial/model updates include no
`asset_tag` key, including no explicit JSON `null` or empty tag.
