# Jira evidence and disposition report — SPOTR hardening branch

Branch: `hardening/remaining-jira-findings`. Live Jira read 2026-09-12 (cloud
`29b4ec9f-a4b7-4a3c-ac17-bd2295b93557`, infogyre.atlassian.net). NO Jira write was performed:
no comments posted, no transitions, no assignments. Posting this report or transitioning any
issue requires fresh explicit operator approval per the plan.

## Dispositions per finding (live data + implemented evidence)

### SPOTR-5 — Unverified pipe server / unrestricted impersonation (High, To Do)
- Jira history: PR #7 partially mitigated with `SECURITY_IDENTIFICATION` SQOS; Windows CI run
  34194527955 proves the impersonation-level limit. Triage explicitly keeps the ticket open —
  SQOS does not authenticate the server or prevent token theft.
- This branch: Lane A (authenticated pipe identity) is designed and review-approved (design note
  REV-2) but implementation is **blocked pending operator confirmation of the identity-binding
  contract** (server PID + LocalSystem owner + SCM argv[0] image-path, per-connection
  re-check, native probe gate first, documented administrator limitation). Native fixture work
  (AC.2–AC.4) follows contract approval.
- Recommended disposition: remain open until lane A lands with native counterfeit-server evidence.

### SPOTR-7 — Truncated operation journal causes persistent startup failure (Medium, To Do)
- Superseding triage (comment 10012): never silently discard the final record; preserve/quarantine,
  validate prefix and phase sequence, distinguish unterminated tails from corruption, operator-
  visible recovery.
- This branch: Lane B contract fully designed (recovery state table REV-2: quarantine with
  exclusive-create/no-follow, sticky blocked marker, classification-first startup ordering, typed
  preservation failures, redacted operator notice) and review-approved; implementation **blocked
  pending operator acceptance of the recovery tradeoff** (operator-assisted recovery for ambiguous
  tails; no automatic reconciliation; no read-only degraded IPC).
- Recommended disposition: remain open until lane B lands with the full state-table test suite.

### SPOTR-9 — Hardware service trusts config paths without ACL verification (Medium, To Do)
- Superseding triage (comment 10002): conditional hardening; verify protected files/directories and
  handle path replacement races.
- This branch: Lane C contract designed (protected per-cell root, no-follow component traversal
  with handle-based reparse rejection, TrustedInstaller allowlist, handle-bound/copy-to-protected-
  staging consumption to close check-to-use races, workflow key/config/collector migration into
  the protected root) and review-approved; implementation **blocked pending operator confirmation**
  (TrustedInstaller rule + workflow-migration scope).
- Recommended disposition: remain open until lane C lands with native swap/race evidence.

### SPOTR-10 — Release publication lacks approval gate (Medium, To Do)
- Superseding triage (comment 10003): governance improvement, not compromise; existing tag/version/
  tests/lifecycle/attestation gates already exist; add approval only if release policy calls for it.
- Operator decision (plan): issue stays OPEN; approval-gate change deferred until the first stable
  release; publication topology preserved; no environment added in this branch.
- Recommended disposition: remain open with the recorded first-stable-release trigger.

### SPOTR-17 — Plaintext API token buffers not zeroized (Low, To Do)
- Superseding triage (comment 10019): wipe DPAPI plaintext before LocalFree, minimize copies with
  zeroizing owners including error paths; do not assume every String/SecretString conversion copies.
- This branch: Lane E contract designed (exact per-site owner map for both `SecretProtector` traits,
  `SetToken` wire-shape-preserving redacted owner, DPAPI wipe-before-LocalFree guard, server-side
  line buffer ownership, unavoidable-temporaries inventory) and review-approved. Implementation is
  sequenced after lanes A+B integrate (per plan); **currently blocked upstream** by the A/B
  contract confirmations.
- Recommended disposition: remain open until lane E lands with wipe-path test evidence.

### SPOTR-23 — Hardware-experiment approval depends on external environment config (Low, To Do)
- Superseding triage (comment 10006): verify environment settings; do not infer absent reviewers
  from YAML.
- This branch: authorized read-only audit performed (`docs/plans/spotr-23-evidence.md`). Result:
  environment `hardware-experiment-approval` exists but has **no required reviewers**
  (`protection_rules: []`), `can_admins_bypass: true`, no deployment branch policy, `main` is not
  branch-protected, and every historical checkpoint job completed in 2–4 s with no pause. Verdict
  recorded as **UNVERIFIED / policy not enforced as described** — not "protection absent" beyond
  the observed configuration. No external setting changed; a controlled dispatch was NOT performed.
- Recommended disposition: remain open; enforcement decision (add reviewers/branch policy) requires
  explicit operator approval as an external change.

### SPOTR-24 — HMAC key grants Administrators Full Control (Low, To Do)
- Superseding triage (comment 10007): not a demonstrated vulnerability under the trust model;
  administrators already control the job; do not apply the `:R`-only suggestion blindly.
- Operator decision (plan): retain `SYSTEM:(R)`/`Administrators:(F)` policy; acceptance documented
  within lane C (key ACL contract test), lifecycle verified rather than claimed.
- Recommended disposition: accepted-policy recommendation recorded here and in lane C's contract;
  no automatic transition.

### SPOTR-28 — PDBs shipped in MSI (Low, To Do)
- Superseding triage (comment 10011): optional distribution-policy decision, not a vulnerability.
- This branch: **IMPLEMENTED AND REVIEW-APPROVED** (lane D, 4 review rounds, final APPROVED, merged
  at `3ae0bf7`). Installed PDB components removed from `installer/Product.wxs`; installed-tree
  negative checks added; the public symbols ZIP retains both PDBs (contract now executes the
  workflow's real Compress-Archive and asserts both PDBs inside the produced ZIP, rejects
  pre-archive deletion, and binds future post-archive verifiers). Remaining native evidence
  (MSI build/install/lifecycle inspection on Windows runners) is explicitly blocked, not passed.
- Recommended disposition: implementation complete on the integration branch; transition after
  native MSI evidence lands and with operator approval to post.

## Umbrellas (context only — not closed)

- SPOTR-4 (Security review 2026-09-02, umbrella, To Do): tracks the security findings above.
- SPOTR-29 (Walkthrough 2026-09-06, To Do): separate functional/ops backlog.
- Neither should be closed; SPOTR-10 remains open by operator decision, and several child findings
  remain open on this branch.

## External-write boundaries honored

This report is read-only. Before any Jira post/transition, GitHub administration change, dispatch,
push, PR creation, or release publication, fresh explicit operator approval is required (plan:
"this handoff alone grants none").
