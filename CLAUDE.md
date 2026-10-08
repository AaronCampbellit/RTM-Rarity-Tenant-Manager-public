# RTM — Rarity Tenant Manager (agent notes)

MSP platform for managing Microsoft 365 tenants. Security-first: tenant
isolation, audit-first, What-If preview + approval before every write, revert
support, global reporting is read-only.

## Repo shape

- `frontend/` — React + Vite + TS + Tailwind. All 16 v1 screens + modals + login, feature-based. Runs standalone on a mock API (`VITE_USE_MOCK=true`) or against the Go API (`false`).
- `backend/` — Go API + worker on chi + pgx + River. `internal/store` has a `Store` interface with `mem` (offline) and `pg` (Postgres) impls; `internal/graph` is the Microsoft provider (sample or live client-credentials); `internal/auth` is JWT+RBAC; `internal/jobs` is River. Falls back to in-memory when `RTM_DATABASE_URL` is unset so `make run` works offline.
- Root `*.md` files are the authoritative specs (vision, API, security, DB, Graph, ADRs, coding standards, roadmap, UI/UX). Read them before changing behavior.

## Conventions

- **Stack is fixed (ADR-018).** Don't introduce other frameworks/ORMs.
- **Frontend data** flows through `src/api/client.ts`; keep mock and real shapes identical (the `/api/v1` contract in `src/types`). Build new screens from the shared `DataTable` + `components/ui` primitives and the design tokens in `src/index.css` — don't hardcode colors.
- **Backend**: every response uses the `httpx` error envelope + correlation ID; long-running actions return a job; tenant-scoped handlers must authorize tenant access server-side. App logs never contain tokens/secrets; the audit trail is separate (DB).
- **Definition of Done (ADR-019)** for a feature: backend + frontend + API docs + permission checks + audit logging + tests + What-If (writes) + revert (where applicable).

## Commands

```bash
# frontend
cd frontend && npm install && npm run dev      # :5173
cd frontend && npm run build                   # tsc + vite build

# backend
cd backend && make run                          # :8080 (in-memory)
cd backend && make vet test build

# full stack
docker compose up --build                       # web :8088 · api :8080 · db :5432
```

## Demo server

RTM is deployed to a **shared** demo box (details in the `rtm-demo-server`
skill). It also runs unrelated **Hank** containers — never stop/remove/restart
anything that isn't RTM; scope every command to the `rtm` compose project.

- Live: `http://192.168.86.139:8090` (web, live mode) · `:8091/api/v1` (Go API).
- Admin bootstrap: `admin@rtm.local` / `ChangeMe!2026` — first GUI login forces
  a password rotation (the rotated password is NOT in this repo; ask Aaron).
  Demo technicians: `aisha.rivera@rarity.io` / `david.chen@rarity.io` with
  `RtmDemo!2026` (Technician role; every RTM user has access to all tenants).
- Deploy/redeploy: `RTM_DEMO_PASSWORD=… ./scripts/deploy-demo.sh` (rsync →
  `~/rtm-demo` → `docker compose -p rtm -f docker-compose.demo.yml up --build -d`).
- `docker-compose.demo.yml` is the **full stack**: Postgres + api + River worker
  + web (built `VITE_USE_MOCK=false`). Ports 8090/8091 avoid the box's existing
  listeners; Postgres stays internal to the `rtm` network.

## Current status

Roadmap complete; full stack live on the demo box and verified end-to-end:
Postgres API (pgx) on a **Goose-managed** schema, JWT auth with **refresh
rotation** + **rate limiting** (two roles — Admin and Technician; every RTM
user has access to every managed tenant, no per-tenant grant model; Admin adds
tenant lifecycle, technician management, write execution, and settings),
**River** worker processing write jobs, and a Graph provider with a sample impl
+ a live client-credentials client mapping all entities with **per-tenant token
authorities and per-tenant app credentials** (RTM tenant → its own Entra
authority; optional per-tenant client ID/secret stored write-only, falling back
to the global `RTM_ENTRA_*` app). Each tenant can also carry **dedicated app
registrations for Exchange Online and the SharePoint admin API** (set up in the
Connect Tenant modal just like the Graph app: client ID + secret write-only,
plus a SharePoint admin URL; empty = reuse the Graph app — `TenantCreds.
Resolved()` applies the fallback). Tenant responses expose a `connections`
`{graph, exchange, sharePoint, threatLocker}` boolean set (surfaced as a
Service Connections card on the tenant detail page); the live EXO/SharePoint
clients consume these creds via `graph.TenantAuth` when those integrations are
built. **Tenant
lifecycle from the GUI**: admins connect tenants (name, domain, directory ID,
optional per-service app creds; connection tested on create) and fully remove
them (type-name confirm; creds deleted, audited). Seeds ship **one example tenant** (Contoso) and a
**default admin** (`admin@rtm.local`) that must rotate its password on first
login (`POST /auth/change-password`; everything else 403s until then).
**Cross-tenant global reports** fan out over the managed tenants
(`internal/reports`; bounded concurrency, partial-failure tolerant). The
**write engine is real end-to-end** across twenty-seven actions — seven
directory (add/remove group membership, block/unblock sign-in, assign/remove
license, revoke sessions), six Exchange (set/clear mail forwarding,
enable/disable auto-reply, grant/revoke mailbox permission), three SharePoint
(grant/revoke site access, set external sharing level), eleven ThreatLocker
(see below):
What-If previews are computed from live tenant state, execute queues a job
(River, or an inline executor in memory mode) whose worker performs the Graph
write **per user** with partial-failure tolerance (live writes need
`GroupMember.ReadWrite.All` + `User.ReadWrite.All`), completes the job with a
real duration, appends the change record (before/after, execution log, revert
snapshot), and audits; revert replays the snapshot and marks the original
Reverted (session revocation, clear-forwarding, disable-auto-reply, and
sharing-level changes aren't revertible — no prior-state snapshot).
**Exchange/SharePoint detail reads**: mailbox settings (auto-reply +
forwarding; live via Graph `mailboxSettings` + an RTM-managed inbox rule,
`MailboxSettings.ReadWrite`), mailbox delegates, and site permissions (live
via `GET /sites/{id}/permissions`); the Exchange and SharePoint pages have
selection → What-If action dialogs plus detail modals, and sample-mode writes
persist so the demo behaves like a real tenant. Live mailbox ids are UPNs and
live site ids are Graph site ids so detail endpoints address them directly;
mailbox-permission and site writes on live tenants fail honestly with
NOT_IMPLEMENTED (they need EXO / SharePoint admin APIs, not Graph).
The Groups inventory must combine Microsoft Graph groups with Exchange Online
group inventory where Graph is incomplete: distribution lists, dynamic
distribution lists, and Exchange-specific mail-enabled security group metadata.
Keep `GET /tenants/{id}/groups` as the unified API surface and label each row
with its source service (`Graph` or `Exchange`).
**ThreatLocker module** (`RTM ThreatLocker Module.md` is the spec;
`internal/threatlocker` + `frontend/src/features/threatlocker`): RTM's first
non-Microsoft connector. One encrypted, write-only MSP parent connection is
managed in Admin Settings; tenant records contain no ThreatLocker credentials
or organization IDs. `RTM_THREATLOCKER_*` values are deployment-time
fallbacks. The ThreatLocker screen is parent-org scoped and stays stable when
switching active RTM tenants. **No sample mode** — missing global config gets `NOT_CONNECTED`
(409), and the live client is tested against a fake portal server. Reads cover
devices, device detail, device groups, approval requests + detail, policies via
`Policy/PolicyGetByParameters` (documented in the KB, absent from the trimmed
public Swagger), and Application Control apps/app files. The Apps tab lists
parent + tenant apps, supports rename, and guides native cleanup: a reviewed
child policy is promoted first when ThreatLocker must create the parent target;
the app family is then merged with `ApplicationUpdateForMerge`, preserved
policies are queued to the exact Global group one at a time, and RTM verifies
the retained app, file rules, source removal, and policy bindings. Applications
and policies are **org-addressed**: detail reads and policy operations use the
owning organization, while the merge itself uses the parent context. PolicyGetById/updates/deletes only work
with `managedOrganizationId` = the owning org (the per-app policy list spans
child orgs — "Unable to retrieve application policy" otherwise), so the
cleanup preview carries full `deletePolicies` rows, execute groups deletes per
owning org, and `GET /threatlocker/policies/{id}?orgId=` addresses child-org
policies; parent-pushed child copies (`PARENT ORG\Name`) are undeletable by
design and are excluded from the plan with a preview warning (details in
`RTM ThreatLocker Module.md`). A ThreatLocker
posture global report (one MSP workspace row; honest "Not connected" state),
and write actions through the same preview/execute/revert
pipeline. The **public ThreatLocker portal API** (verified against its Swagger)
supports live: `enter_maintenance_mode` (Monitor Only / Learning, via
`ComputerDisableProtection`; reverted by `secure_device`), `secure_device`
(`ComputerEnableProtection`), `restart_agent` (`ComputerUpdateShouldRestartByIds`;
not revertible), `approve_request` (permit flow via
`ApprovalRequestGetPermitApplicationById` + `ApprovalRequestPermitApplication`;
not revertible — creates a policy), and `deny_request`
(`ApprovalRequestUpdateForReject`). Lockdown, isolation, and tamper-protection
toggles are **not exposed by the public API** and fail honestly with
NOT_IMPLEMENTED (ErrNotSupported). Device reads map the real portal fields
(mode from the containment booleans + mode string, group, serviceVersion,
online derived from lastCheckin); device groups are aggregated from the device
list. No separate approval workflow: RTM tenant access confers approval rights;
everything is What-If gated + audited.
**Nothing operational is
seeded** — jobs/changes/audit/working sets start empty, the dashboard is
computed per request, technicians
ARE the login accounts (invite w/ one-time temp password + forced rotation,
role/status editing, delete), and app settings persist. Backend has a
**test suite** (`go test ./...`): auth rotation/reuse + RBAC + forced
rotation, httpx, store, server e2e (tenant isolation, write gates, the full
execute/revert pipeline, technician CRUD, settings), report fan-out, and the
live Graph client against a fake token+Graph server. Graph is **hybrid** (in
the provider-routing sense) when no global app is set: a tenant added in the GUI
with its own client ID/secret is live immediately; others serve sample data. Set
`RTM_ENTRA_*` to force live for everything.

**M365 operational tooling** (ideas ported from the old M365kissmyask PoC,
rebuilt RTM-style): (1) **Entra readiness global reports** — six extra
cross-tenant report types (`license-readiness`, `mfa-gaps`, `stale-guests`,
`privileged-roles`, `ca-exclusions`, `app-credentials`) backed by per-family
Provider reads (sample + live in `graph/sample_entra.go` /
`graph/client_entra.go`, rows in `reports/entra.go`); they fan out even in
sample mode. (2) **Permission preflight** — `POST /tenants/{id}/preflight`
probes each read feature area with harmless GETs and maps 403 → missing
consent; write permissions report `unchecked`; surfaced as a card on the
tenant detail page; audited. (3) **Raw user view (User Blowout)** —
`GET /tenants/{id}/users/{userId}/raw` returns the full directory object
(extension attributes, identities); audited per view (`user.raw_view`);
opened by clicking a user's name on the Users page. (4) **Share Detective**
(`server/sharedetective.go`, `features/share-detective/`) — tenant-scoped
shared-access investigation for offboarding: background scan over sites +
drive items with per-site coverage honesty (scanned/partial/skipped),
findings classified (`direct_user`, `specific_people_link`, `broad_link`,
`group_based`, `site_membership`, `inherited`), only confirmed direct grants
revocable. Revoke = admin-only preview → approval token → synchronous
execute (the ThreatLocker-cleanup pattern, NOT a River job), partial-failure
tolerant, audited + recorded in change history as non-revertible.
Investigations are ephemeral in-memory state (like pending approvals). Live
Graph adds transitiveMemberOf, bounded drive traversal (`shared` facet →
permissions), and DELETE on site/item permissions (`Sites.FullControl.All`).

**Hybrid AD / Entra source-of-authority awareness** (distinct from the
provider routing above — see `RTM Hybrid Implementation Plan.md` and
`hybrid-ad-entra-sync-framework.md`): users/groups carry a source of authority
read from `onPremisesSyncEnabled` (`model.User.SourceOfAuthority`,
`Group.Source`); the tenant detail endpoint computes an `identityMode`
(cloud/hybrid/mixed/unknown) + synced/cloud counts (`internal/server/hybrid.go`),
with the tenant-level `organization.onPremisesSyncEnabled` flag as the
authoritative cloud-vs-hybrid signal (object counts only refine hybrid→mixed).
A prominent Hybrid AD notice shows on the tenant detail + Users/Groups pages with
per-object source badges. The What-If gate is **source-aware**: it blocks only
on-prem-mastered writes (sign-in block/unblock on synced users, membership
changes on synced groups) via `WhatIfPreview.Blocked[]`, fails closed before the
job queue, and audits the attempt as Denied — while licensing, session
revocation, cloud-group membership, and all Exchange/SharePoint actions stay
usable on synced users. New hybrid-identity code lives in `server/hybrid.go`,
NOT `graph/hybrid.go` (the unrelated provider router). See `README.md`.
