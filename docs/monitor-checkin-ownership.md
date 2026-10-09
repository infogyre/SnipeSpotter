# Monitor check-in ownership (SPOTR-47)

Automatic and forced check-in require the computer asset ID recorded when
SnipeSpotter checked out the monitor. This expected owner travels in signed
monitor state and in each prepared journal operation. It is not inferred from
the latest remote assignment or a newly matched computer.

Immediately before a check-in POST, the production adapter reads the monitor
again. It permits the write only when the returned asset identity matches and
`assigned_to.type` is exactly `asset`, with the expected asset ID. A user or
location with the same numeric ID is not the expected owner. Unknown/missing
assignment types, a different owner, and invalid expected owners suppress the
write with a visible error. Forced check-in uses the same executor and cannot
bypass this check.

An unassigned monitor already in the requested check-in status is an idempotent
success with no POST. An unassigned monitor in another status is suppressed
rather than issuing a check-in to change its status. Every retry and recovery
replay obtains fresh remote state, including after an ambiguous prior response.
Conflicts preserve pending evidence and block recovery for operator review;
SnipeSpotter does not rewrite the recorded owner to make a retry succeed.

## Upgrade behavior

Older signed monitor entries without a recorded checkout owner remain readable
but cannot authorize automatic or forced check-in. The optional field is omitted
when absent to preserve the prior canonical state representation. An existing
checked-out flag alone does not establish ownership.

Old pending check-in journal payloads without `expected_asset_id` fail closed.
Do not blindly delete pending evidence or add an owner to make it replay. Follow
the [policy-blocked legacy recovery procedure](operator-guide.md#policy-blocked-legacy-operations-and-ownerless-monitor-state), verify actual assignment/outcome, and reconcile
state using reviewed evidence before resuming. New successful checkouts record
the owner for future check-ins. Reconnection alone does not restore owner
evidence on an already checked-out legacy entry. Rollback requires the matching
binary and a consistent stopped-service data snapshot: old binaries cannot
authenticate new owner-bearing signed state. See the linked procedure.

## Residual concurrency and qualification

There is still a time-of-check/time-of-use interval between GET and POST. The
client has no verified server-side compare-and-set, conditional ownership, or
idempotency capability for check-in; the standard request carries only the
status ID. The guard prevents stale-owner replay but does not make the operation
atomic. A reassignment after the GET can still race with POST. Supervised beta
must document this restriction and qualify the exact supported server version
and operational coordination; stronger guarantees require a verified backend
conditional-write contract and corresponding client support.

Regression tests exercise mocked HTTP responses, typed owner collisions,
reassignment across prepare/restart/retry, and already-applied outcomes. These
are not evidence of live Snipe-IT behavior. Qualification must capture the exact
candidate/server versions, before/after assignments, forced and automatic paths,
and recovery behavior on approved non-production assets. No live asset was
mutated as part of these code changes. Merge and runtime qualification remain
separate readiness gates; this change alone does not close the Jira blocker.
