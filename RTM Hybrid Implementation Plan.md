# RTM Hybrid AD / Entra Support — Implementation Plan

Maps `hybrid-ad-entra-sync-framework.md` (the requirement) onto the current
codebase (the reality) and sequences the work. Scope is the doc's **v1 MVP**:
cloud-side hybrid awareness only — no domain-controller access, no LDAP
credentials, no on-prem connector (that is explicit Later Scope, §88-106/§160).

## Guiding principle (product intent)

When a tenant is Hybrid AD, RTM must make that **impossible to miss** — a very
direct, always-visible notice on the tenant (and on affected user/group views),
not a subtle badge. The intent behind the notice:

- **You can still do everything cloud.** SharePoint, Exchange Online, and the
  Entra/Azure AD *cloud* pieces (licensing, session revocation, MFA/auth
  methods, cloud-only group membership, app assignments, and all EXO/SharePoint
  actions) remain fully usable in RTM against a hybrid tenant.
- **You cannot touch on-prem AD pieces.** Identity core mastered by on-prem AD
  (display name/profile, UPN, synced group membership, account enable/disable)
  is not editable from RTM — those changes belong in Active Directory.
- **Do not break anything.** RTM must never fire a cloud write that on-prem AD
  will reject or silently revert at the next sync. Blocked actions fail closed
  with a clear explanation; nothing is attempted that could leave the tenant in
  an inconsistent state.

The notice is informational, not a lockout: it tells the technician *which*
surface they are on, so cloud work proceeds confidently and on-prem work is
routed to AD.

## Implementation status (shipped)

The three guiding-principle items below are **implemented and verified** (backend
`go test ./...` green, frontend `tsc + vite build` green, browser-verified in
mock mode):

- **Detection** — `onPremisesSyncEnabled` is read for users and groups
  (`internal/graph/client.go`); `model.User.SourceOfAuthority` and
  `Group.Source` carry it; the tenant detail endpoint computes
  `identityMode` + synced/cloud counts (`internal/server/hybrid.go`,
  `getTenant`).
- **Impossible-to-miss notice** — `HybridNotice` banner on the tenant detail
  page (with counts) and, compact, on the Users and Groups inventories; a source
  badge on every user/group row; an Identity card on the tenant page
  (`frontend/src/components/common/HybridNotice.tsx`, `status.ts`).
- **Cloud stays usable / on-prem fails closed** — the What-If gate classifies
  each target: it blocks only `block_signin`/`unblock_signin` on synced users
  and membership changes on synced groups, returning `WhatIfPreview.Blocked[]`
  with a resolution; execute filters blocked targets (never queued) and audits
  the attempt as Denied. Licensing, session revocation, cloud-group membership,
  and all Exchange/SharePoint actions remain allowed on synced users
  (`internal/server/handlers.go` `planTargets`/`executeChange`,
  `server_hybrid_test.go`).

## Deferred architecture

Hybrid reporting, a group-membership source report, further `onPremises*`
metadata, and the future on-prem connector remain intentionally deferred. They
are separate architecture projects, not incomplete worktree changes; each
needs its own design, provider contract, tests, and live acceptance environment.

## Top risks / flagged items

Three things to be aware of before any code is written (detailed in the sections
below):

1. **`hybrid.go` is a naming trap.** It is the live-vs-sample provider router,
   **not** hybrid AD. Overloading it will confuse the two concepts. See
   *Naming warning*. (Still true — the router was left as-is; new hybrid code
   lives in `server/hybrid.go`.)
2. ~~**Active correctness bug:** the live Graph client hardcodes `Source:
   "Cloud"` on every group and never selects `onPremisesSyncEnabled`.~~
   **FIXED** — the client now selects `onPremisesSyncEnabled` and derives
   `Source` for users and groups.
3. ~~**Safety gap:** none of the 16 write actions are source-aware, so a write
   against an on-prem-mastered object is queued and fails with an opaque Graph
   error.~~ **FIXED** — the What-If gate blocks on-prem-mastered writes and
   fails closed before the job queue.

## Naming warning

`backend/internal/graph/hybrid.go` already exists but is **unrelated** — it is
the live-vs-sample provider router (`hybridProvider`). Do not overload it. New
hybrid-identity code should use `source of authority` / `identity mode`
terminology to avoid confusion. Consider renaming the existing type to
`routingProvider` as a cleanup (optional, separate change).

## Current gaps (verified against code)

- `model.User` has **no** on-prem fields; live query
  `internal/graph/client.go:394` never `$select`s `onPremisesSyncEnabled`.
- `model.Group.Source` exists but the **live** client hardcodes `Source:
  "Cloud"` (`client.go:477`); only sample data shows `"On-prem sync"`. Live
  synced groups are therefore mislabeled.
- `model.Tenant` has no `identityMode`.
- None of the 16 write actions are source-aware — a Graph write against an
  on-prem-mastered object is queued and fails with an opaque Graph error.
- Frontend has zero hybrid awareness.
- No hybrid reporting; no audit for blocked/skipped hybrid actions.

## Design

### Source of authority (per object)

Derive, don't trust a single field. From Graph:

- `onPremisesSyncEnabled == true` → `on_prem`
- `onPremisesSyncEnabled == false/null` **and** object present in cloud →
  `cloud`
- field absent / provider error → `unknown`

Also capture (nullable, for UI + reports): `onPremisesImmutableId`,
`onPremisesSecurityIdentifier`, `onPremisesDomainName`,
`onPremisesSamAccountName`, `onPremisesDistinguishedName`, `lastCloudSyncSeenAt`
(from `onPremisesLastSyncDateTime`).

### Identity mode (per tenant)

Computed from object inventory, cached on the tenant:

- any synced objects + any cloud-only objects → `mixed`
- all synced → `hybrid`
- none synced → `cloud`
- inventory never run / provider error → `unknown`

### Action classification

A static table keyed by action, returning one of:
`cloud_supported | hybrid_supported | hybrid_limited | on_prem_required |
unsupported`. Consulted by the What-If step **per object**. Initial mapping
(from framework §55-78) for the 16 existing actions:

| Action | cloud object | synced (on_prem) object |
|---|---|---|
| add/remove group membership (security grp) | cloud_supported | **on_prem_required** |
| add/remove group membership (M365 grp) | cloud_supported | hybrid_supported |
| block/unblock sign-in | cloud_supported | **on_prem_required** |
| assign/remove license | cloud_supported | hybrid_supported (licensing is cloud-side) |
| revoke sessions | cloud_supported | cloud_supported |
| mailbox forwarding/auto-reply/permission (EXO) | cloud_supported | hybrid_supported* |
| site access / sharing (SharePoint) | cloud_supported | cloud_supported |

\* mailbox settings live in Exchange Online (cloud) even for synced users; the
distribution/mail-enabled **group** membership case is `hybrid_limited` and
noted for the EXO integration.

## Work breakdown

### Backend

1. **Model** (`internal/model/model.go`): add to `User` a
   `SourceOfAuthority string` + `OnPremisesSyncEnabled *bool` + the nullable
   `onPremises*` fields; add `SourceOfAuthority`/on-prem fields to `Group`
   (keep `Source` as the display string, derive it from the new field); add
   `IdentityMode string` + `SyncedUsers`/`CloudUsers`/`SyncedGroups`/
   `CloudGroups` counts to `Tenant`.
2. **Graph live client** (`internal/graph/client.go`): extend the users
   `$select` (line 394) and groups `$select` (line 454) with
   `onPremisesSyncEnabled,onPremisesImmutableId,onPremisesSecurityIdentifier,
   onPremisesDomainName,onPremisesSamAccountName,onPremisesDistinguishedName,
   onPremisesLastSyncDateTime`; populate the new fields; replace hardcoded
   `Source: "Cloud"` with derived value.
3. **Sample provider** (`internal/graph/sample.go`): give a couple of sample
   users/groups `on_prem` authority so hybrid UI/tests have data offline.
4. **Classification** (new `internal/graph/authority.go` or
   `internal/actions`): the table above + a `Classify(action, obj) verdict`
   helper.
5. **Write gate**: in the What-If/execute path, classify each target; objects
   that resolve to `on_prem_required`/`unsupported` are returned as **blocked**
   (not queued), with the standard message: *"This object is synced from
   on-prem AD. Make this change in on-prem Active Directory, then allow Entra
   sync to update Microsoft 365."* Blocked objects are audited (§9) and appear
   in the What-If preview response.
6. **Reports** (`internal/reports`): add synced/cloud user & group counts,
   unknown/stale-metadata rows, and a group-membership source-of-authority
   report (framework §123-132).
7. **Tenant inventory**: compute + cache `identityMode` and counts on refresh.
8. **Tests**: fake-Graph tenant returning `onPremisesSyncEnabled=true` →
   source classified `on_prem`; write action against it is blocked + audited,
   not executed; cloud object still executes; identity-mode computation;
   report fan-out counts.

### Frontend

9. **Types** (`src/types`): mirror the new fields (keep mock + real shapes
   identical, per CLAUDE.md).
10. **Badges/filters**: source-of-authority badge on user & group rows/detail;
    "synced only / cloud only" filter in the DataTable; use design tokens, no
    hardcoded colors.
11. **Tenant detail**: an Identity card — mode, last inventory sync, synced vs
    cloud counts, detected on-prem domains.
12. **What-If modal**: separate **successful / skipped / blocked / failed**
    groups; show the on-prem reason per blocked object (framework §120-122).
13. **Mock API**: extend mock data so `VITE_USE_MOCK=true` demonstrates hybrid.

### Docs

14. Update `RTM API Specification.md` (new fields + What-If blocked shape),
    `RTM Database Design.md` (§133-140: `identity_mode`, `source_of_authority`,
    `on_premises_*`, `hybrid_action_support`, future `connector_id`),
    `RTM System Architecture.md` / ADRs (record the cloud-side-only hybrid
    decision), and a cloud-writable-vs-on-prem-required action matrix.

## Suggested sequencing

1. Backend safety core: steps 1,2,4,5,8 — makes RTM **safe** against hybrid
   tenants (no confusing failed writes) as fast as possible.
2. Inventory + reporting: steps 3,6,7.
3. Frontend surfacing: steps 9-13.
4. Docs: step 14 (alongside each phase per ADR-019 Definition of Done).

## Explicitly out of scope (Later, per framework §160-168)

On-prem connector agent, direct AD reads/writes, OU-aware lifecycle, password
reset/unlock, hybrid deprovisioning, Entra Connect health. The MVP must
**detect, display, report, and safely block** — not manage on-prem AD.
