# RTM API Specification
## Authentication
Initial authentication:
- RTM-native login
- JWT bearer tokens
- Refresh tokens
- RBAC
- Two roles — Admin and Technician. Every RTM user has access to every
  managed tenant (no per-tenant grant model); Admin adds platform
  administration (tenant lifecycle, technicians, write execution, settings).
- Forced password rotation: accounts seeded with default credentials carry a
  must-change flag; every endpoint except `GET /auth/me` and
  `POST /auth/change-password` returns `PASSWORD_CHANGE_REQUIRED` (403) until
  the password is rotated. `POST /auth/change-password` verifies the current
  password, enforces the policy (min 12 chars, must differ), and returns a
  fresh token pair. It is also available to normally authenticated operators
  as a self-service password change. Every successful password change bumps
  the account credential version and revokes all older access and refresh
  tokens.
Future authentication:
- Optional Microsoft Entra ID / OIDC as an identity provider
- RTM still issues its own JWT after successful authentication
## API Philosophy
RTM uses REST + workflow action endpoints.
There are two endpoint categories:
### Resource Endpoints
Expose objects and collections.
Examples:
- GET /api/v1/tenants
  - Tenant summaries and detail expose an authoritative `users` count from a
    lightweight Microsoft Graph advanced query (`User.Read.All`), rather than
    the placeholder captured when the tenant was connected. Counts fan out
    with bounded concurrency; if Microsoft is temporarily unavailable, RTM
    keeps the stored fallback instead of failing the complete tenant list.
- GET /api/v1/tenants/{tenantId}/users
  - Returns a column-ready directory projection: names, UPN/mail, employment,
    contact/location, identity source, account state, MFA registration,
    assigned product names, creation/sync timestamps, and the latest sign-in
    signal (`lastSuccessfulSignInDateTime`, falling back to the latest
    interactive attempt where Microsoft has not backfilled that property).
    License names are resolved tenant-wide from `subscribedSkus`
    without per-user calls. `lastSignInAvailable=false` distinguishes a tenant
    where Microsoft does not license the `signInActivity` property from a user
    who has never signed in.
- GET /api/v1/tenants/{tenantId}/groups
  - Returns Graph-visible groups plus Exchange-backed group inventory when the
    Exchange Online integration is available. `service` identifies the owning
    API surface (`Graph` or `Exchange`); Exchange coverage includes
    distribution lists and dynamic distribution lists that Microsoft Graph does
    not fully expose.
- GET /api/v1/tenants/{tenantId}/groups/{groupId}/members
- POST /api/v1/tenants/{tenantId}/groups — creates a Graph-backed Security or
  Microsoft 365 group. `{name,description,type}` are required; the purpose
  description is trimmed, limited to 1,024 characters, and sent to Microsoft
  Graph. Group creation requires the execute-changes capability and is audited.
- GET /api/v1/tenants/{tenantId}/exchange/mailboxes — directory-backed
  inventory with mailbox type independently enriched from Graph
  `mailboxSettings.userPurpose` in batches. When `Reports.Read.All` is
  consented and Microsoft exposes mailbox identities in reports, RTM also
  merges usage freshness, storage/item counts, last activity, deleted-item
  totals, archive state, and quotas. Missing report consent, report latency,
  or concealed identities never fail the inventory; `usageAvailable=false`
  and `usageDetail` make the exact coverage gap and remediation explicit.
- GET /api/v1/tenants/{tenantId}/exchange/mailboxes/{mailboxId}/settings —
  locale/working hours, mailbox purpose, full automatic-reply configuration,
  delegate meeting delivery, and every forwarding/redirect action visible in
  Inbox rules (live: Graph `mailboxSettings` + `messageRules`; needs
  `MailboxSettings.Read`). Rule-read failures return the settings with
  `rulesAvailable=false` rather than asserting there are no forwarding rules.
- GET /api/v1/tenants/{tenantId}/exchange/mailboxes/{mailboxId}/permissions —
  returns `{permissions, coverage}`. Live tenants read Send on Behalf through
  Microsoft's Exchange Online Admin API preview using app-only
  `Exchange.ManageAsAppV2` plus Exchange Recipient Management RBAC. Coverage
  marks Full Access and Send As `not_supported`; those grants still require
  controlled Exchange Online PowerShell and RTM makes no conclusion about
  them. A denied Admin API request returns the standard Microsoft permission
  error with consent/RBAC remediation. Sample tenants cover all three families.
- GET /api/v1/tenants/{tenantId}/users/{userId}/raw — the full directory
  object for one user ("User Blowout"): every attribute the app can `$select`,
  including on-prem extension attributes, identities, and proxy addresses.
  Read-only and audited per view (`user.raw_view`) — it is a deep PII read.
  Response `{id, attributes}` where `attributes` is the raw Graph map with
  nulls and `@odata` metadata stripped.
- GET /api/v1/tenants/{tenantId}/sharepoint/sites
- GET /api/v1/tenants/{tenantId}/sharepoint/sites/{siteId}/permissions —
  owners/members/visitors, direct grants, external users, sharing links
  (live: Graph `GET /sites/{id}/permissions`, `Sites.Read.All`).
- GET /api/v1/tenants/{tenantId}/sharepoint/inventory?scope=sites|onedrive|file_permissions —
  latest persistent hierarchy snapshot, totals, coverage, warnings, and
  freshness. `file_permissions` is an explicit on-demand scan scope.
- GET /api/v1/tenants/{tenantId}/sharepoint/scans — nightly/manual scan history.
- POST /api/v1/tenants/{tenantId}/sharepoint/scans — admin-only background
  scan; request `{scope,siteId?,nodeId?}`.
- GET /api/v1/tenants/{tenantId}/sharepoint/permissions?siteId=&driveId=&itemId=&kind=&path= —
  effective SharePoint REST role assignments, inheritance status, and source
  targets for site/library/folder/file scopes.
- POST /api/v1/tenants/{tenantId}/sharepoint/permissions/preview — admin-only
  What-If preview for grant, revoke, break inheritance, or restore inheritance.
- POST /api/v1/tenants/{tenantId}/sharepoint/permissions/execute — executes an
  approved preview token, audits it, and records change history.
- POST /api/v1/tenants/{tenantId}/sharepoint/permissions/revert — applies the
  stored inverse when available. Restoring inheritance is non-revertible.
- GET /api/v1/tenants/{tenantId}/share-detective/investigations — the
  tenant's Share Detective investigations (ephemeral, in-memory — findings
  should be exported or acted on, and a fresh scan beats a stale one).
- GET /api/v1/tenants/{tenantId}/share-detective/investigations/{invId} —
  one investigation: subject, status (`running`/`completed`/`failed`),
  per-site coverage (scanned / partial / skipped with the reason — a coverage
  gap is always visible, never silent), findings with a classification
  (`direct_user`, `specific_people_link`, `broad_link`, `group_based`,
  `site_membership`, `inherited`), and a summary rollup. Only confirmed
  direct grants are marked revocable. Investigations are tenant-scoped —
  another tenant's URL cannot read them.
- GET /api/v1/security/operations — one audited, cross-tenant Microsoft
  security snapshot. The API fans out to all managed tenants with bounded
  concurrency and returns summary metrics, open-severity counts, aggregate
  connector health, per-tenant coverage, normalized Defender incidents and
  RTM-native Microsoft 365 audit detections, and
  warnings. Tenant failures are partial results, not a global failure. Sample
  and planned connectors are explicit; the newest 100 incidents per tenant are
  loaded in Phase 1 and a Microsoft next page becomes a truncation warning.
  Native incident rows expose `detectionType`, `confidence`, `ruleId`, and
  `ruleVersion`; no raw provider evidence is returned.
  The snapshot also returns persisted `storylines`, sorted by deterministic
  risk score and recency. Each storyline identifies its correlation pack,
  tenants, normalized entities, attack stages, independent signal count,
  risk/confidence, the reasons RTM connected the activity, weak evidence, and
  suggested response actions. Storylines are an investigation layer above
  incidents; they do not replace or hide the underlying signals.
- GET /api/v1/security/storylines/{storylineId} — audited global storyline
  detail. Returns the persisted storyline plus its complete ordered evidence
  chain. Every evidence item names the detection/rule and attack stage, then
  links it to all supporting normalized audit events. The API intentionally
  exposes human-readable event projections instead of raw provider payloads.
- PATCH /api/v1/security/storylines/{storylineId} — audited RTM-local analyst
  workflow. Body accepts `status` (`New`, `In Progress`, `Resolved`, or
  `Dismissed`) and/or `assignment` (`me` or `unassigned`). Re-correlation and
  late evidence may change risk, stages, and evidence, but never overwrite the
  analyst's status or owner. This endpoint does not mutate Microsoft 365;
  recommended containment remains a separate What-If-gated RTM action.
- GET /api/v1/security/incidents/{tenantId}/{incidentId} — audited incident
  detail. Defender IDs return correlated Microsoft alerts and evidence;
  `rta_` IDs return the RTM rule match, normalized audit-event timeline, and a
  human-readable `evidence` projection containing actor, operation, target,
  related resource, workload, result, time, client IP, and a bounded list of
  meaningful before/after changes. Opaque ID lists and raw provider JSON stay
  out of this projection. The response also includes a deterministic
  `remediation` plan (`category`, `summary`, phased/priority `steps`, optional
  `rtmAction`, and `completionCriteria`). This is guidance only and cannot
  execute or approve a tenant write. No raw Graph/Management Activity payload
  is exposed.
- PATCH /api/v1/security/incidents/{tenantId}/{incidentId} — audited RTM-local
  SOC triage. Body accepts `status` (`New`, `In Progress`, `Resolved`, or
  `Dismissed`) and/or `assignment` (`me` or `unassigned`). This changes only
  RTM workflow metadata and never mutates the customer tenant or Microsoft
  Defender, so the tenant-write What-If gate is not involved.
- Security incident list/detail rows include `rtmReceivedAt`, the durable time
  RTM first observed or created the incident. It is distinct from Microsoft's
  provider `createdAt` and `updatedAt` timestamps.
- PATCH /api/v1/security/incidents — audited bulk RTM-local SOC triage for
  1–100 incident references per request. `action: accept` assigns each row to
  the current operator and advances only `New` rows to `In Progress`;
  `action: set_status` requires one of the four RTM statuses and preserves
  ownership. Results are partial-failure tolerant and report updated and
  failed rows independently. The UI batches larger visible selections.
- GET /api/v1/security/events — audited cross-tenant event search. Supports
  normalized-field filters, RFC3339 `from`/`to`, `limit` (1–100), and `offset`
  (0–10,000) within a maximum 180-day window. Rows expose contributing
  `sources` plus `occurredAt`, `availableAt` (first observed from Microsoft),
  and `ingestedAt` pipeline timestamps. Graph-fast and Management Activity
  copies are consolidated by a normalized tenant/operation/actor/object/IP/
  result fingerprint within a ten-second window, not merely by provider ID.
  The canonical event retains the earliest availability/ingestion timestamps,
  every contributing source, and a durable provider-record alias. Repeated
  actions outside that narrow window remain separate events.
- GET /api/v1/security/events/{tenantId}/{eventId} — audited normalized event,
  related RTM detections (whose `createdAt` completes the displayed pipeline
  latency), and recursively redacted raw JSON capped at 256 KiB.
- GET/POST /api/v1/security/offline-investigations — list or create an
  authenticated, case-scoped forensic workspace. A case uses an operator
  supplied tenant label; it is never joined to a managed tenant or to the live
  Security Operations event/incident tables.
- GET /api/v1/security/offline-investigations/{investigationId} — case summary,
  encrypted-file metadata, evidence coverage, latest 500 normalized timeline
  rows (configurable with `timelineLimit`, maximum 1,000), detections, and
  storylines. Each timeline row links its matching detection signals and may
  include a bounded allowlist of investigator-useful provider facts such as
  application, authentication type, Conditional Access result, location,
  external-access state, affected-item count, and device. Source payloads and
  non-allowlisted provider fields are not returned.
- POST /api/v1/security/offline-investigations/{investigationId}/files — one
  multipart `file` containing UTF-8 JSON, JSONL/NDJSON, or CSV. Supported
  evidence is Microsoft Graph sign-ins, Microsoft Graph directory audits, and
  Microsoft 365 Management Activity exports, including native Microsoft
  Purview audit-search CSVs whose complete event JSON is wrapped in the
  `AuditData` column. Files are limited to 1 GiB and
  10,000,000 records, classified and validated before being encrypted at rest,
  hashed with SHA-256, and recorded in the case audit trail. Large encrypted
  sources are persisted in bounded chunks. Duplicate hashes are rejected. The
  durable case cap is 20 files, 10 GiB, and 50,000,000 records; it is enforced
  transactionally across concurrent uploads.
- POST /api/v1/security/offline-investigations/{investigationId}/analyze —
  asynchronous River job. It normalizes and semantically deduplicates up to
  50,000,000 case records, evaluates the current built-in/custom detection rules,
  and derives case-only attack storylines. Re-analysis atomically replaces
  derived rows but never changes immutable source files.
- DELETE /api/v1/security/offline-investigations/{investigationId} —
  `security.manage` only. Cascades encrypted source files and all derived case
  data. Running cases cannot be deleted.
- GET /api/v1/security/detection-rules — immutable built-in baselines plus
  custom rules and scoped overrides. Built-in overrides can retain the
  specialized detector (`definition.triggerMode=builtIn`) or replace its
  trigger with an editable direct/threshold event match
  (`definition.triggerMode=custom`); alert name, description, severity,
  confidence, state, scope, match fields, thresholds, and exclusions are
  persisted in the override without mutating the shipped baseline. GET `/{ruleId}` loads one rule; GET
  `/{ruleId}/revisions` returns immutable stored revisions.
- GET /api/v1/security/detection-rules/options — audited, bounded condition
  choices for the rule editor. An optional `tenantId` scopes dynamic choices.
  Workload, operation, actor, client-IP, result, and object choices are drawn
  only from normalized columns in the latest 180 days (maximum 5,000 events)
  and merged with RTM's supported Microsoft 365 catalog. Raw-evidence choices
  are a curated list of safe field-name tokens; provider values and secrets are
  never projected into this response.
- POST /api/v1/security/detection-rules/preview — Admin-only 30-day/latest-
  50,000-event What-If returning match counts, sample normalized events, and a
  short-lived approval token.
- POST /api/v1/security/detection-rules and PUT
  /api/v1/security/detection-rules/{ruleId} — Admin-only creation/update.
  Enabled changes and all built-in overrides require the matching preview;
  updates use optimistic revisions.
- POST /api/v1/security/detection-rules/{ruleId}/revisions/{revision}/restore —
  Admin-only restore as a new revision; enabled restores are preview-gated.
- GET /api/v1/threatlocker/devices — global parent-organization ThreatLocker
  endpoints with protection mode, tamper state, agent version, last check-in.
  The ThreatLocker screen uses these tenantless endpoints so it stays stable
  when the active RTM tenant changes. The sole connection is configured in
  Admin Settings; `RTM_THREATLOCKER_*` values are deployment-time fallbacks.
  Missing global config returns `NOT_CONNECTED` (409). There are no
  tenant-scoped ThreatLocker credential or operation routes. The frontend does
  not preload these endpoints globally and backs off automatic retries after
  a connector failure; an operator-triggered refresh bypasses that backoff.
- GET /api/v1/threatlocker/devices/{deviceId}
- GET /api/v1/threatlocker/device-groups
- GET /api/v1/threatlocker/approval-requests?status= —
  application-control requests (`pending` default; execution / elevation /
  storage).
- GET /api/v1/threatlocker/approval-requests/{requestId}
- GET /api/v1/threatlocker/policies — policy list
  (`Policy/PolicyGetByParameters`; name, action, applies-to, status;
  editable by admins for the supported policy fields).
- GET /api/v1/threatlocker/apps — application list from ThreatLocker
  Application Control. Returns all apps visible to the parent org, including
  child organization apps; optional `search`, `searchBy`, and
  `source=tenant|parent` filters. The unfiltered inventory is shared with
  cleanup analysis for at most 60 seconds; `refresh=true` forces a new portal
  inventory.
- GET /api/v1/threatlocker/apps/{appId} — application detail plus file rules.
- GET /api/v1/working-sets — durable Working Sets ordered newest first. Each
  row includes the description, owning tenant ID/name, exact retained
  `userIds[]`, item count, creator, and last-used label.
- GET /api/v1/working-sets/{workingSetId} — opens one durable Working Set with
  its exact retained user IDs.
- POST /api/v1/working-sets — saves a user Working Set synchronously and
  audits `working_set.create`. Request
  `{name,description?,tenantId,userIds[]}`; name and tenant are required and
  1–5,000 unique non-empty user IDs are retained. Returns the created Working
  Set with HTTP 201. The operation does not modify Microsoft 365 and therefore
  does not use the What-If write gate.
- PUT /api/v1/working-sets/{workingSetId} — updates the shared Working Set's
  `{name,description,userIds[]}` while retaining its original tenant and
  creator. The same name/length/1–5,000 unique-user validation applies and the
  change is audited as `working_set.update`.
- GET /api/v1/jobs/{jobId}
- GET /api/v1/reports/{reportId}
### Workflow Action Endpoints
Execute operations or start jobs.
Examples:
- POST /api/v1/auth/change-password
- POST /api/v1/changes/preview — computes the What-If from live tenant state.
  Request `{action, tenantId, …}` where the target list depends on the action
  family: directory + site-access actions send `userIds[]`, Exchange actions
  send `mailboxIds[]`, `set_site_sharing` sends `siteIds[]`, ThreatLocker
  device actions send `deviceIds[]`, ThreatLocker approval actions send
  `approvalRequestIds[]`.
  Directory actions: `add_to_group` / `remove_from_group` (requires
  `groupId`; `GroupMember.ReadWrite.All`), `block_signin` / `unblock_signin`
  (`User.ReadWrite.All`), `assign_license` / `remove_license` (requires
  `skuId`; `User.ReadWrite.All`; warns when available license units are fewer
  than targets), legacy `revoke_sessions` (`User.RevokeSessions.All`, NOT
  revertible), `reset_password` (`User-PasswordProfile.ReadWrite.All`; returns
  one-time passwords only after execution), and `revoke_user_access`
  (`User-PasswordProfile.ReadWrite.All` +
  `UserAuthenticationMethod.ReadWrite.All` + `User.RevokeSessions.All`; resets
  the password, removes registered non-password authentication methods, and
  revokes sessions; NOT revertible).
  Exchange actions (6): `set_forwarding` (requires `forwardTo`; warns about
  exfiltration; live = RTM-managed inbox rule, `MailboxSettings.ReadWrite`) /
  `clear_forwarding` (NOT revertible — prior address isn't snapshotted),
  `enable_auto_reply` (requires `autoReplyMessage`) / `disable_auto_reply`
  (NOT revertible), `grant_mailbox_permission` / `revoke_mailbox_permission`
  (require `delegateId` + `permission` ∈ Full Access | Send As | Send on
  Behalf). Send on Behalf is live and revertible through the Exchange Online
  Admin API. Full Access and Send As fail closed with `NOT_IMPLEMENTED` until
  the controlled Exchange Online PowerShell connector lands.
  SharePoint actions (3): `grant_site_access` / `revoke_site_access` (require
  `siteId` + `role` ∈ Read | Edit | Full Control; `Sites.FullControl.All`),
  `set_site_sharing` (requires `sharingLevel` ∈ Internal | External | Anyone;
  NOT revertible — prior level isn't snapshotted; skips sites already at the
  requested level).
  ThreatLocker device actions: `enter_maintenance_mode` (requires
  `maintenanceType` ∈ monitor_only | learning — the modes the portal API's
  disable-protection endpoint accepts — and `durationMinutes` 1–1440; preview
  warns protection is reduced; reverted by `secure_device`), `secure_device`
  (NOT revertible — prior mode/expiry isn't snapshotted), and `restart_agent`
  (NOT revertible). `lockdown_device` / `release_lockdown`, `isolate_device` /
  `release_isolation`, and `enable_tamper_protection` /
  `disable_tamper_protection` are accepted by the API but the public
  ThreatLocker portal API does not expose them, so live execution fails with
  NOT_IMPLEMENTED. Offline devices aren't skipped — the preview warns the
  change applies at next check-in.
  ThreatLocker approval actions (2): `approve_request` (requires `scope` ∈
  computer | group | organization, optional RFC3339 `expiresAt` for a
  temporary permit; NOT revertible — it creates a ThreatLocker policy;
  preview says so) and `deny_request` (optional `reason`; NOT revertible).
  Non-pending requests are skipped.
  Response lists real changes vs skips (unknown
  user/mailbox/site/device/request, already/not a member, sign-in already
  blocked/not blocked, already at sharing level, device already in the target
  state, request no longer pending) with warnings; risk scoring treats
  forwarding, Full Access, Full Control, external sharing, lockdown,
  isolation, tamper-protection off, disable_protection maintenance, and
  organization-scope approvals as elevated.
- POST /api/v1/changes/execute — same request shape; normally queues a job that
  performs the write **per target** with partial-failure tolerance (job
  outcome Completed / Partial / Failed), records the change (before/after,
  execution log, revert snapshot covering exactly the targets that
  succeeded), and audits the outcome. `reset_password` and
  `revoke_user_access` are the security-sensitive exception: they execute as
  synchronous tracked jobs so generated passwords never enter River or a
  persistent payload. Their no-store response adds `oneTimePasswords[]`
  (`userId`, `user`, `upn`, `password`) and reports `succeeded`,
  `partial_success`, or `failed`; RTM never stores those password values.
  Password-bearing actions are capped at 10 users per request so the response
  can return every one-time credential safely within a bounded operation.
- POST /api/v1/changes/revert — `{id}` of a change; queues the stored revert
  payload and marks the original change Reverted. Reverts pair as:
  `add_to_group` ↔ `remove_from_group`, `block_signin` ↔ `unblock_signin`,
  `assign_license` ↔ `remove_license`, `grant_mailbox_permission` ↔
  `revoke_mailbox_permission`, `grant_site_access` ↔ `revoke_site_access`,
  `lockdown_device` ↔ `release_lockdown`, `isolate_device` ↔
  `release_isolation`, `enable_tamper_protection` ↔
  `disable_tamper_protection`; `set_forwarding` → `clear_forwarding`,
  `enable_auto_reply` → `disable_auto_reply`, and `enter_maintenance_mode` →
  `secure_device` are one-way; `revoke_sessions`, `reset_password`,
  `revoke_user_access`, `clear_forwarding`,
  `disable_auto_reply`, `set_site_sharing`, `secure_device`, `restart_agent`,
  `approve_request`, and `deny_request` have no revert. Conflicts (not
  eligible / already reverted) return REVERT_CONFLICT.
- POST /api/v1/admin/technicians — invite an operator (real login account);
  returns a one-time temp password; first login forces rotation.
- PATCH /api/v1/admin/technicians/{id} — role / status / isAdmin.
- POST /api/v1/admin/technicians/{id}/reset-password — replace another local
  RTM account's credential with a generated one-time password, force rotation
  at the next sign-in, and immediately revoke all of that account's access and
  refresh tokens. Requires `technicians.manage`, is rate limited and audited,
  returns the temporary password once, and refuses self-reset (operators use
  `/auth/change-password` for their own account).
- DELETE /api/v1/admin/technicians/{id} — remove the account (refresh tokens
  cascade; self-delete refused).
- GET /api/v1/admin/roles — persisted Admin and Technician role policies,
  including `permissionKeys`, locked capability keys, presentation level, and
  live assigned-account count.
- PUT /api/v1/admin/roles/{name} — update `{description, permissionKeys}`.
  Permission keys are allowlisted, the Admin role must retain every elevated
  capability, changes are audited as `role.update`, and authorization reloads
  the assigned role on every request so grants/revocations apply immediately.
- PATCH /api/v1/admin/settings/{key} — persist a platform setting (locked
  settings refuse changes). Boolean toggles accept `{enabled}`. The
  `session_timeout` setting accepts `{value}` in minutes, bounded to `30`,
  `60`, `240`, `480`, `720`, or `1440`; it applies to access tokens issued by
  subsequent sign-ins, password rotations, and refreshes.
- GET /api/v1/admin/threatlocker — admin-only status for the global
  ThreatLocker MSP connection. Returns the portal instance, parent
  organization ID, source (`database`, `environment`, or `none`), and whether
  a token is stored; it never returns the token.
- PUT /api/v1/admin/threatlocker — admin-only replacement of the global MSP
  connection: `{instance, token, parentOrganizationId}`. All three fields are
  required; the token is encrypted at rest and write-only. Database settings
  take precedence over `RTM_THREATLOCKER_*` environment fallback values.
- GET /api/v1/tenants/{tenantId}/preflight — return the last durable permission
  snapshot without contacting Microsoft. Returns `OBJECT_NOT_FOUND` until the
  tenant has completed its first run. Every check includes an RTM feature
  `category` (`Security Operations`, `Directory & Identity`, `Exchange`,
  `SharePoint`, or `Licensing`) plus the exact resource and permission.
- POST /api/v1/tenants/{tenantId}/preflight — run and persist the tenant
  permission preflight (any technician; POST like `/test` because it performs
  live diagnostics; audited as `tenant.preflight`). Probes each read feature area
  with a harmless GET and classifies the outcome per required Graph
  application permission: `ok` (consented), `missing` (Microsoft returned
  403 without an effective grant — grant admin consent), `not_provisioned`
  (the permission is granted but the optional Defender XDR service is not
  licensed/onboarded), `error` (Microsoft's own reason attached), `sample`
  (no live connection). RTM reads the Microsoft-issued resource
  token's application `roles` claim to verify write permissions without a
  write. Documented broader grants report `ok` with `grantedVia` (for example,
  `Directory.ReadWrite.All` satisfying `User.ReadWrite.All`). Graph and
  SharePoint Online are evaluated independently. SharePoint checks both Graph
  `Sites.ReadWrite.All` and `Sites.FullControl.All`, plus the separate
  SharePoint Online `Sites.FullControl.All` grant. Security Operations adds a
  harmless `/security/incidents?$top=1` probe for
  `SecurityIncident.Read.All`. Microsoft 365 Audit adds an independent Office
  365 Management APIs subscription-list probe for `ActivityFeed.Read`. Response
  `{mode, ranAt, checks[{category, area, resource, permission, status, detail, grantedVia?}]}`.
- POST /api/v1/tenants/{tenantId}/exchange/bootstrap/preview — admin-only,
  actor-bound What-If preview for the exact Exchange role, tenant scope,
  runtime permission, temporary delegated permission, API version, and token
  retention behavior. Returns a five-minute single-use `approvalToken`, the
  exact `callbackUrl`, and whether the deployment is HTTPS-ready.
- POST /api/v1/tenants/{tenantId}/exchange/bootstrap — admin-only start for
  one-click Exchange authorization; requires that exact preview's
  `approvalToken` plus a one-time `clientId` and `clientSecret`, and returns a
  tenant-bound Microsoft authorization URL. The submitted bootstrap client asks
  for delegated `RoleManagement.ReadWrite.Exchange` without `offline_access`.
  The credentials are held only in process memory and purged after callback or
  ten-minute expiry; they are never deployment configuration or stored data.
  After the administrator returns to
  `POST /api/v1/microsoft/exchange/bootstrap/callback` using OAuth
  `response_mode=form_post` (the code never enters browser history or proxy
  query logs), RTM uses Graph beta to
  idempotently assign the built-in **Recipient Management** role, tenant-wide,
  to the tenant's runtime Exchange service principal. The callback is protected
  by a ten-minute, one-use state value and PKCE; it verifies the runtime token's
  tenant, client, and service-principal object ID. RTM then discards the
  delegated token and redirects to Tenant Detail, which re-runs preflight.
  Start and completion are separately audited. The callback itself is the only
  unauthenticated route in this workflow and never accepts or returns a token.
- POST /api/v1/tenants/{tenantId}/share-detective/investigations — start a
  Share Detective scan: `{subjectId}` (member or guest). Returns 202 with the
  running investigation; the client polls the GET endpoint. The scan is
  read-only: it enumerates the tenant's sites, reads site permissions and
  drive items with their own sharing state (bounded traversal), classifies
  everything granting the subject access, and reports coverage honestly.
  Audited as `share_detective.start`.
- POST /api/v1/tenants/{tenantId}/share-detective/investigations/{invId}/revoke-preview —
  admin-only What-If for revoking selected findings: `{findingIds[]}`.
  Returns the plan (per finding: `delete_permission` for confirmed direct
  grants — deleting affects only the subject — or `manual_review` with the
  resolution path), warnings (including that deleted permissions and sharing
  links cannot be recreated — no revert), risk, and an `approvalToken`.
- POST /api/v1/tenants/{tenantId}/share-detective/investigations/{invId}/revoke —
  admin-only execution of the previewed plan: `{findingIds[], approvalToken}`.
  Deletes the confirmed direct grants synchronously with partial-failure
  tolerance (`Completed` / `Partial` / `Failed` + per-finding outcome),
  audits the run (`share_detective.revoke`), and records a non-revertible
  change ("Revoke shared access") in change history. Group-based, inherited,
  and broad-link findings are never deleted here — the preview points at the
  right path (remove-from-group action, parent folder, manual link review).
- POST /api/v1/tenants — connect a managed tenant (admin-only): name, domain,
  Microsoft directory (tenant) ID, and optionally the tenant's own Entra
  (Graph) app client ID + client secret (write-only: never returned by any
  endpoint; empty = use the globally configured app). Optionally also a
  dedicated Exchange Online app using `exchangeClientId` +
  `exchangeClientSecret`. SharePoint administration requires
  `sharePointAdminUrl`; it always authenticates with RTM's deployment-managed
  central certificate application, never a tenant-uploaded credential.
  Optional `historyWindow` is `start_now`, `last_24h`, `last_7d`, or
  `maximum_available`; optional `historicalIncidentMode` is `recent_24h`
  (recommended), `all`, or `baseline_only`. A non-zero window creates a
  separate `Security history import` job and the response includes its
  write-safe `historyImport` progress record. Live collectors do not wait for
  the import. The current maximum is seven days because Management Activity
  requests are limited to seven days and each request window is at most 24
  hours.
  All secrets are write-only. The Graph connection is tested on create.
  Tenant responses carry a `connections` object
  (`{graph, exchange, sharePoint}` booleans) reporting which tenant services
  are configured — never the credentials themselves. `sharePoint` means the
  admin URL is present. ThreatLocker fields are rejected because its
  connection is global.
- DELETE /api/v1/tenants/{tenantId} — fully remove a managed tenant
  (admin-only, audited); deletes stored credentials.
- PUT /api/v1/tenants/{tenantId} — admin-only settings update for tenant
  metadata, Graph/Exchange credentials, and SharePoint admin URL.
  Omitted or blank secrets preserve the stored value. `clearGraph`,
  and `clearExchange` explicitly remove stored credentials/use fallback.
  Changed client IDs require replacement secrets; changed connections are
  tested and previous settings restored on failure.
- GET /api/v1/admin/threatlocker — admin-only status for the single MSP parent
  connection. The token is never returned.
- PUT /api/v1/admin/threatlocker — validates and then replaces the global
  portal instance, API token, and MSP parent organization ID. A failed test
  preserves the current connection. A blank token preserves the current
  write-only token.
- PATCH /api/v1/threatlocker/apps/{appId} — rename/update a
  ThreatLocker application (admin-only, audited). Body supports `name` and
  `description`; the provider preserves the portal fields RTM does not render.
- GET /api/v1/threatlocker/apps/cleanup-candidates —
  admin-only ranked cleanup queue. RTM conservatively groups non-built-in
  applications by normalized family name and OS across organizations, then
  scores parent-app availability, exact cross-organization names, record
  count, file-rule count, and policy count. The response explains every score
  and recommends a parent-owned retained app when one exists. Scores never
  authorize a write; the live preview remains authoritative. The route reuses
  the current 60-second application inventory; `refresh=true` bypasses it.
- POST /api/v1/threatlocker/apps/cleanup-preview —
  admin-only preview for merging selected applications into a retained
  parent-owned app. Body `{appIds[], retainedAppId?, retainedPolicyId?,
  name?, confirmDelete?}`. Response includes the exact Global destination,
  unique file-rule count, preserved policy snapshots, merge-source apps,
  warnings, blockers, and a deterministic cleanup fingerprint. When no
  parent-owned target exists it also returns an approval-bound
  `parentPromotion` proposal.
- POST /api/v1/threatlocker/apps/cleanup-parent-promote —
  admin-only, audited pre-merge policy promotion. The approved child-owned
  policy is queued to the exact Global group in its owning organization
  context; ThreatLocker uses that lifecycle to materialize the required
  parent-owned application. RTM records the write before submission and
  requires parent-app verification before retrying.
- POST /api/v1/threatlocker/apps/cleanup-execute —
  admin-only, audited application cleanup. Execution requires a live
  parent-owned target, refreshes every application in its owning organization,
  submits ThreatLocker's native application merge in the parent context,
  verifies the retained name, and queues each preserved child policy to the
  exact Global group serially. It does not use direct application insertion or
  the legacy policy/application delete endpoints. The response includes
  `operationId`, `verificationStatus`, preserved policies, and promoted policy
  IDs.
  RTM writes the operation as `submitted` before the first portal mutation,
  changes it to `verification_pending` after successful responses, or to
  `needs_reconciliation` when the external outcome may be partial or
  uncertain. Requires global parent credentials:
  `RTM_THREATLOCKER_INSTANCE`, `RTM_THREATLOCKER_TOKEN`, and
  `RTM_THREATLOCKER_PARENT_ORG_ID`.
- GET /api/v1/threatlocker/apps/cleanup-operations —
  admin-only list of the most recent durable global cleanup operations.
- POST /api/v1/threatlocker/apps/cleanup-operations/{operationId}/verify —
  admin-only, audited portal verification. RTM re-reads the application and
  policy inventories plus the retained app's file rules. Parent-promotion
  operations verify that the new parent app appeared. Merge operations verify
  that the retained parent app exists, all merge sources disappeared, expected
  file rules remain, and every preserved policy is enabled, Global, and bound
  to the retained app. Only an all-pass merge result becomes `verified`; any
  mismatch becomes `needs_reconciliation` and can be checked again.
- POST /api/v1/threatlocker/apps/cleanup-operations/{operationId}/reconcile —
  admin-only, audited manual reconciliation fallback.
  Body `{resolution:"verified"|"not_applied"}`. `verified` records the expected
  final state; `not_applied` records that no mutation occurred and releases the
  fingerprint for a safe retry. Partial or unclear outcomes must remain
  `needs_reconciliation`.
- GET /api/v1/global-reports/{type} — read-only reports. Microsoft report
  types put the tenant column first and fan out with bounded concurrency and
  partial-failure tolerance. `threatlocker` returns one global MSP workspace
  row. Types: the original `mfa`,
  `license`, `inactive`, `guests`, `threatlocker`, plus the Entra readiness
  reviews — `license-readiness` (enabled members missing a usage location or
  holding no license), `mfa-gaps` (users not MFA-registered from the
  authentication-methods registration report, admins ranked first;
  `AuditLog.Read.All`), `stale-guests` (no sign-in in 90 days / never, and
  invites stuck pending; sign-in activity degrades gracefully without an
  Entra ID P1 license), `privileged-roles` (every directory-role assignment;
  `RoleManagement.Read.Directory`), `ca-exclusions` (Conditional Access
  excluded users/groups/apps per policy; `Policy.Read.All`), and
  `app-credentials` (app secrets/certificates expired or expiring within 90
  days; `Application.Read.All`). The readiness reports fan out in every mode
  — sample tenants contribute seeded rows.
- POST /api/v1/sync/refresh
- POST /api/v1/reports/generate
- POST /api/v1/global-reports/generate
- POST /api/v1/working-sets
- POST /api/v1/changes/preview
- POST /api/v1/changes/execute
- POST /api/v1/changes/revert
- POST /api/v1/exports/generate — authenticated, synchronous audit
  acknowledgement for interactive CSV exports whose rows are already loaded
  in the browser. Accepts `kind`, a plain `.csv` `filename`, `rowCount`, and an
  optional managed `tenantId`; the server validates the metadata and tenant,
  records `exports.generate` with the authenticated actor and correlation ID,
  then returns `{ "status": "recorded" }`. The browser must not create the
  download until this call succeeds. Large server-generated export artifacts
  remain asynchronous River work.
## Async Operations
Long-running or potentially long-running actions should run asynchronously through River jobs.
The API should return a job response instead of blocking:
```json
{
  "job_id": "...",
  "status": "queued"
}
```
The frontend should retrieve job status and results using job endpoints.
## Core Endpoint Groups
- /auth
- /tenants
- /users
- /groups
- /licenses
- /exchange
- /sharepoint
- /security
- /working-sets
- /changes/preview
- /changes/execute
- /changes/revert
- /reports
- /global-reports
- /audit
- /jobs
- /sync
- /exports
## API Principles
- Versioned under /api/v1
- RESTful resources
- Workflow-oriented actions
- Consistent error responses
- Pagination
- Filtering
- Request validation
- OpenAPI documentation
- No frontend access to Microsoft Graph directly
- Tenant authorization enforced server-side on every tenant-scoped request
- Correlation IDs on requests and errors
## Not in Initial Scope
- GraphQL
- Direct frontend Microsoft Graph calls
- Raw Graph proxy endpoint
## Error Response Philosophy
RTM should separate user-facing errors from diagnostic logging.
Standard error response shape:
```json
{
  "error": {
    "code": "TENANT_ACCESS_DENIED",
    "message": "You do not have access to this tenant.",
    "correlation_id": "..."
  }
}
```
Error categories:
- AUTHENTICATION_FAILED
- AUTHORIZATION_DENIED
- TENANT_ACCESS_DENIED
- MICROSOFT_CONNECTION_FAILED
- MICROSOFT_THROTTLED
- MICROSOFT_PERMISSION_MISSING
- OBJECT_NOT_FOUND
- VALIDATION_FAILED
- WHAT_IF_FAILED
- CHANGE_FAILED
- REVERT_CONFLICT
- PARTIAL_SUCCESS
- INTERNAL_ERROR
Rules:
- Always include correlation ID.
- Never expose secrets or tokens.
- Translate Microsoft API failures into technician-friendly messages.
- Store raw diagnostics in logs.
- Partial Success must be modeled explicitly.
- Errors should state whether anything changed where applicable.
