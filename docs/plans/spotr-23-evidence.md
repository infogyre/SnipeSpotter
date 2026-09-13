# SPOTR-23 evidence: hardware approval environment audit (read-only, 2026-09-12)

Method: authorized read-only GitHub administration queries via `gh api` (authenticated as
jakewimmer, admin: true) against `infogyre/SnipeSpotter`. No external setting was changed; no
workflow was dispatched; no Jira transition performed. Record text contains no secret material.

## Environment metadata

Query: `GET /repos/infogyre/SnipeSpotter/environments`

| Property | Observed value | Assessment vs expected policy |
| --- | --- | --- |
| Environment name | `hardware-experiment-approval` (id 20366366277) | EXISTS — matches the `environment:` referenced by the `checkpoint` job in `.github/workflows/hardware-experiment.yml` |
| Created | 2026-08-22T00:58:03Z | — |
| `can_admins_bypass` | `true` | ADMINISTRATOR BYPASS IS POSSIBLE — the post-observation checkpoint can be bypassed by repository admins. Plan expected-policy: review of whether this is acceptable must be recorded; this weakens "required reviewer" enforcement for admins. |
| `protection_rules` | `[]` (EMPTY) | **NO required reviewers configured.** The environment does not name any required reviewer. |
| `deployment_branch_policy` | `null` | NO branch restriction — any ref the workflow runs from can gate on this environment. |

## Branch/ref protections

Query: `GET /repos/infogyre/SnipeSpotter/branches/main/protection` → 404 "Branch not protected".
`main` has NO branch protection rules. Combined with `can_admins_bypass: true` and empty
protection rules, there is no enforced reviewer gate on `main` ref changes.

## Observed checkpoint behavior (historical runs; no dispatch performed)

The most recent authorized controlled run (workflow_dispatch run 32694136588, head `3c0a7d16`,
2026-08-24) shows the `awaiting_operator_hardware_approval` job completing in ~3 seconds
(05:38:26 → 05:38:29Z, all steps success) with NO waiting interval — the checkpoint passed
immediately. Deployment status timeline for deployment 6057184829 (same run):
`in_progress` at 05:38:27Z → `success` at 05:38:30Z, created by jakewimmer.

Every historical run of the checkpoint job (runs 32554140342, 32552056434) also completed in
2–4 seconds. There is NO evidence of any run actually pausing to await operator approval, and no
deployment `failure`/`waiting` status that would indicate a pending-approval gate ever engaged.

## Disposition

**SPOTR-23: UNVERIFIED / POLICY NOT ENFORCED AS DESCRIBED.**

The workflow YAML preserves `needs: matrix`, the exact acknowledgement input, and diagnostic-only
policy text (verified in-repo). However, the external GitHub environment provides NO actual
approval enforcement: no required reviewers, admin bypass enabled, no branch policy, and
historical checkpoint jobs that complete instantly rather than pausing. The plan's expectation of
an "intentional post-observation checkpoint" exists as workflow mechanics only — it does not
require a human approval through the environment.

Missing/absent evidence per the plan: expected-policy administrator confirmation of intended
configuration, and any controlled run demonstrating an actual pause. Both remain outstanding;
this audit makes no change to any external setting (adding reviewers or branch policy requires
fresh explicit operator approval).
