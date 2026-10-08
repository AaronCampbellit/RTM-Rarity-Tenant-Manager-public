# RTM Security Operations Module

## Purpose

Give an MSP technician one honest, cross-tenant queue for suspicious Microsoft
365 activity. Defender XDR remains the source of truth for Defender incidents;
RTM also ingests immutable Microsoft 365 Management Activity records and owns
the detections produced by its versioned rules. Coverage reporting never
presents sample, initializing, or failed connectors as live.

## Phase 1 — Implemented

- Cross-tenant Microsoft Defender XDR incident snapshot with bounded
  concurrency and partial-failure tolerance.
- Normalized incident rows: tenant, severity, Microsoft status, RTM status,
  Microsoft and RTM owners, alert/entity counts, source, and timestamps.
- Incident detail with correlated alerts, normalized evidence entities, and an
  evidence timeline.
- Explicit per-tenant coverage (`healthy`, `missing_permission`,
  `not_provisioned`, `degraded`, or `sample`) and aggregate connector health.
  Microsoft 403 responses that explicitly say the Defender account is not
  provisioned are reported as a licensing/onboarding issue instead of being
  mislabeled as missing Graph consent.
- RTM-local assignment and status (`New`, `In Progress`, `Resolved`,
  `Dismissed`). Triage is audited but does not PATCH Microsoft Defender or
  change a customer tenant, so it does not use the M365 What-If write gate.
- Sample/live parity across the Go provider and frontend mock client.
- Permission preflight for `SecurityIncident.Read.All`; a granted permission
  plus Defender's `Account is not provisioned` response is labeled as an
  unavailable optional service, not missing consent.

## Phase 2 — Implemented

- Office 365 Management Activity subscriptions for Azure AD, Exchange,
  SharePoint, and General audit content.
- A separate one-minute Microsoft Graph fast lane for `/auditLogs/signIns` and
  `/auditLogs/directoryAudits`, using the existing tenant-scoped Graph app and
  `AuditLog.Read.All`. It accelerates successful/failed sign-ins and Entra
  directory, account, group, role, application, consent, and credential
  changes without requiring Defender or Event Hub.
- A separate per-tenant `https://manage.office.com/.default` app-only token;
  Graph tokens are never reused against the audit resource.
- Five-minute River ingestion with an immediate startup run, per-workload
  checkpoints, a 30-minute overlap, provider-record deduplication, partial
  tenant/workload failure tolerance, and 180-day retention.
- Immutable normalized events plus server-only raw JSON for replay and future
  investigation. The browser can request only a recursively redacted, bounded
  projection for one explicitly selected event; unredacted provider payloads
  never leave the API boundary.
- Deterministic, versioned direct detections for mailbox delegation and
  forwarding, inbox/transport rules, Exchange connectors, account/password/
  authentication-method lifecycle, guests and privileged roles, group owners
  and membership, applications/consent/high-impact permissions/credentials,
  SharePoint permissions/external sharing, audit searches/configuration, and
  legacy authentication when the audit record contains the client protocol.
- High-impact configuration detections for domain federation/authentication,
  hybrid authentication, security defaults, authorization and cross-tenant
  access policies, Conditional Access named locations, privileged-role/PIM
  policy, tenant-domain lifecycle, application ownership and configuration,
  reported MFA fraud, Exchange mail-protection policies, mailbox audit bypass,
  and explicit organization-wide mailbox auditing disablement.
- Bounded threshold and correlation detections for mass forwarding, large
  group changes, bulk SharePoint/OneDrive activity, repeated administrative
  failures, rapid object changes, cross-tenant admin bursts, and repeated
  failed logins followed by success.
- Baseline/identity heuristics for new forwarding domains, newly observed admin
  IP/country/UTC hour, possible impossible travel, and possible session/token
  reuse. Every native incident carries its type and confidence.
- A 30-day, latest-50,000-event correlation window and a versioned one-time
  direct-rule replay checkpoint. Deterministic IDs keep recurring evaluation
  idempotent.
- RTM-native detections and Defender incidents share the same incident queue,
  detail contract, local triage workflow, and tenant/source filters.
- Every incident detail includes a deterministic, read-only response playbook
  selected from normalized rule, alert, workload, and evidence context. Plans
  separate containment, investigation, eradication, recovery, and validation;
  point to the relevant RTM workspace or What-If action; and provide explicit
  resolution criteria. Guidance never executes a tenant change or bypasses the
  normal RTM What-If and approval gate.
- Permission preflight for Office 365 Management APIs `ActivityFeed.Read`.
- Tenant onboarding offers `start now`, 24-hour, seven-day (recommended), and
  maximum-available history choices. History runs as a separate River job in
  newest-to-oldest one-day source windows while live polling starts
  independently. Operators choose whether imported matches open incidents for
  the latest 24 hours (default), all imported history, or no imported history.
  The persisted incident cutoff prevents later correlation cycles from
  re-opening suppressed historical matches while retaining all evidence for
  baselines, rule previews, and the Raw Event Explorer.
- Connector Health reports each tenant history job's progress, retained-event
  and detection totals, and partial source failures. Imported records carry a
  visible `historical_backfill` source marker and still deduplicate by tenant +
  Microsoft provider record ID against both live lanes.

The frontend exposes this as **Operations → Security Operations**. It is a
global view and therefore labels the context as **All managed tenants** instead
of implying that the active tenant switcher scopes the queue.

## Detection Operations — Implemented

- **Operations → Detection Rules** presents the complete 53-rule built-in
  catalog plus persisted custom rules and scoped overrides.
- Built-in match implementations are code-owned and locked. Admins can create
  global or tenant-scoped overrides for enabled state, severity, confidence,
  supported thresholds/windows, and exact/contains exclusions. Tenant scope
  takes precedence over a global override.
- Custom rules support normalized/raw-text direct matching and bounded
  threshold evaluation grouped by actor, client IP, object, or tenant.
- Every enabled rule change requires a fresh 30-day/latest-50,000-event
  preview token. Disabled custom drafts may be saved without activation.
- Persisted configurations use optimistic revisions; every revision is an
  immutable snapshot and can be previewed and restored as a new revision.
- **Operations → Raw Event Explorer** provides authenticated cross-tenant
  search over a maximum 180-day range, 100 rows per page, and offset 10,000.
  Detail reads recursively redact token/secret/password/cookie fields and
  sensitive name/value parameters, cap each retained provider payload at 256
  KiB, show semantically deduplicated Graph and Management Activity evidence
  separately with source provenance, show related detections, and are audited.
  Admins can prefill a disabled custom rule from a selected event.
- Rule/event reads follow the v1 all-managed-tenants operator model; create,
  update, and restore require Admin.

## Data Flow

1. The worker schedules `entra_fast_identity_ingest` on startup and every
   minute, plus `m365_audit_ingest` on startup and every five minutes. Both fan
   out to managed tenants with bounded concurrency and independent checkpoints.
2. The fast job queries Graph sign-ins and directory audits with a one-hour
   bounded lookback and five-minute overlap. The unified-audit job ensures the subscription,
   lists content for the checkpoint window, validates Microsoft content URLs,
   normalizes records, evaluates rules, and atomically stores canonical events,
   every source-native provider payload, detections, and the new checkpoint.
3. After collection, the worker evaluates bounded multi-event rules. A new
   direct-rule pack is replayed once over bounded history and checkpointed.
4. The browser requests `GET /api/v1/security/operations` once.
5. The API reads tenants, audit checkpoints/native detections, and RTM
   incident-state overlays.
6. `internal/securityops` fans out to each tenant through the existing hybrid
   Graph provider, with at most four tenant reads in flight.
7. The live provider requests the newest 100 incidents from Microsoft Graph
   `/security/incidents?$top=100&$expand=alerts`. Microsoft returns newest
   incidents first; `@odata.nextLink` becomes a visible truncation warning.
8. The service merges native detections, overlays RTM owner/status, computes
   severity and connector summaries, and returns one snapshot. A broken tenant contributes a visible
   coverage failure without suppressing successful tenants.
9. Selecting an incident loads its detail on demand. Every snapshot and detail
   read is audited.

Microsoft tokens and unredacted provider responses never reach the browser.
The event explorer returns only a bounded, recursively redacted projection for
one selected audit record. The Graph boundary emits at most eight deduplicated
entity labels per incident.

## API Contract

- `GET /api/v1/security/operations` — cross-tenant snapshot: generated time,
  summary, severity counts, connector health, tenant coverage, incidents, and
  warnings.
- `GET /api/v1/security/incidents/{tenantId}/{incidentId}` — one incident with
  correlated alerts, its provider-derived timeline, and an incident-specific
  remediation plan with phased steps and completion criteria.
- `PATCH /api/v1/security/incidents/{tenantId}/{incidentId}` — RTM-local triage.
  Body may contain `status` and/or `assignment` (`me` or `unassigned`).
- `PATCH /api/v1/security/incidents` — bounded bulk RTM-local triage. Accept
  assigns the current operator and advances New rows to In Progress; set-status
  moves the selected rows while preserving ownership. Each row reports its own
  outcome so a stale provider incident does not mask successful updates.
- `GET /api/v1/security/events` — audited, bounded event search. Supports
  `query`, `tenantId`, `workload`, `operation`, `actor`, `clientIp`, `result`,
  `from`, `to`, `limit`, and `offset`.
- `GET /api/v1/security/events/{tenantId}/{eventId}` — normalized event,
  related detections, the backward-compatible canonical raw projection, and a
  `sourceEvidence` collection of separately redacted/capped provider payloads.
- `GET /api/v1/security/detection-rules`, `GET .../{ruleId}`, and
  `GET .../{ruleId}/revisions` — built-in/custom catalog and stored history.
- `GET /api/v1/security/detection-rules/options` — safe condition catalog,
  optionally tenant-scoped, merged from supported values and normalized
  retained evidence. It never returns raw evidence values.
- Admin `POST .../detection-rules/preview`, `POST .../detection-rules`,
  `PUT .../detection-rules/{ruleId}`, and `POST .../restore` — preview-gated
  management.

All routes require an authenticated RTM account. In v1, every active RTM user
can read every managed tenant under the platform's documented two-role model.

## Storage and Retention

Defender incident evidence is read on demand. RTM persists the durable time an
incident was first observed by RTM plus local workflow in
`security_incident_states`; audit ingestion positions in
`security_audit_checkpoints`; immutable normalized/raw records in
`security_audit_events`; and rule matches in `security_native_detections`.
Each event records all contributing sources plus `occurred_at`, first-observed
Microsoft availability (`available_at`), and RTM persistence (`ingested_at`).
Provider-record uniqueness merges a later unified-audit copy into the Graph
fast-lane event instead of creating a second event or detection. Because
Microsoft does not expose an internal publication timestamp, `available_at`
is explicitly an upper-bound observation time, not a claimed service timestamp.
Native rows include detection type (`direct`, `threshold`, `correlation`, or
`heuristic`) and confidence (`high`, `medium`, or `low`).
`security_detection_replays` records completion of bounded historical rule-pack
replays.
`security_history_imports` stores the onboarding window, incident policy,
durable cutoff, job progress, coverage totals, and terminal result. It contains
no provider evidence or credentials and cascades with the tenant.
`security_detection_rules` stores custom definitions and built-in overrides;
`security_detection_rule_revisions` stores immutable JSON snapshots for audit
and rollback. Built-in baselines remain source-controlled.
Checkpoints, events, and detections are tenant-scoped and cascade on tenant
removal; replay metadata is global to the deployed rule pack. Event deletion is
limited to the worker's explicit 180-day retention cutoff; detections cascade
with their source event. Overlapping windows and unique provider IDs make
replay idempotent.

## Permissions and Microsoft Prerequisites

- Microsoft Graph application permission: `SecurityIncident.Read.All` with
  tenant admin consent. RTM does not request `SecurityIncident.ReadWrite.All`.
- The tenant must have Microsoft security workloads that produce Defender XDR
  incidents. Empty, correctly authorized feeds are valid.
- Office 365 Management APIs application permission: `ActivityFeed.Read` with
  admin consent. This is added under **Office 365 Management APIs**, not under
  Microsoft Graph. Microsoft 365 unified auditing must also be enabled.
- Microsoft Graph application permission: `AuditLog.Read.All` with tenant
  admin consent for the one-minute identity lane. The existing RTM Graph app
  and per-tenant credential resolver are reused; no Event Hub is configured.
- Future Entra risk ingestion uses `IdentityRiskEvent.Read.All` and may depend
  on Microsoft Entra ID P1/P2 licensing for the required signals.

## Audit Events

- `security.operations.view`
- `security.incident.view`
- `security.incident.triage`
- `security.audit_ingest` (one aggregate system record per tenant/run; never
  one audit row per provider event)
- `security.identity_fast_ingest` (one aggregate system record per tenant/run)
- `security.history_backfill.request` and `security.history_backfill`
- `security.events.search`
- `security.event.raw_view`
- `security.rule.preview`, `.create`, `.update`, and `.restore`
- `security.rules.view`, `security.rule.view`, and
  `security.rule.revisions_view`
- `security.rule_options.view`

Audit resources contain the tenant/incident display identity, never raw
evidence or secrets. Application logs may record tenant names, Microsoft HTTP
status, and correlation data, but not tokens or evidence bodies.

## Coverage Honesty

The snapshot reports Defender and Microsoft 365 Audit independently per
tenant. A tenant without Defender can still be monitored by the audit
connector. Entra ID Protection remains `planned`. Sample tenants are always
labeled `sample` in the banner, connector summary, tenant coverage, incident
rows, and incident detail.

## Native Detection Thresholds and Limits

Native severity combines likely impact with evidence strength:

- **Critical** is reserved for high-confidence evidence of tenant-wide control
  or defense evasion, or a high-confidence broad exfiltration sequence. The
  default pack uses it for federation/authentication trust changes, explicit
  organization-wide mailbox-auditing disablement, and mass mailbox forwarding.
- **High** covers high-impact access/control changes and strong attack
  sequences requiring prompt triage. Medium-confidence app-permission and
  session-reuse heuristics do not become Critical solely because their worst
  case is severe.
- **Medium** covers meaningful but commonly legitimate administration or
  lower-confidence contextual anomalies that require validation.
- **Low** covers common lifecycle/hygiene evidence and weak context-only
  anomalies. Confidence remains a separate field and is never implied by the
  severity badge.

- Mass forwarding: five distinct mailboxes in 30 minutes; large group change:
  20 membership operations in 15 minutes.
- Bulk SharePoint/OneDrive: 50 downloads/accesses, 20 deletions, or 10 sharing
  changes against distinct objects in 15 minutes.
- Administrative failures: five in 10 minutes; rapid object change: 15
  distinct objects in 10 minutes; cross-tenant burst: 15 distinct objects in
  at least two tenants in 15 minutes.
- Failed-then-success: five failures in the 15 minutes before a success.
- Possible travel compares different countries on successful audit events no
  more than two hours apart. It is not an Entra risk verdict; VPNs, proxies,
  mobile networks, and missing country data limit accuracy.
- Possible session reuse requires the same session/token identifier from two
  different IPs within 30 minutes. It is an investigation lead, not proof of a
  stolen session, and Microsoft does not emit a stable identifier in every
  audit record.
- New IP/country/time and forwarding-domain rules require retained baseline
  evidence. UTC-hour detection stays low-confidence until tenant-local working
  hours are configurable. RTM never invents absent geolocation evidence.

The default operation names are maintained against Microsoft's
[Entra audit activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities),
[Microsoft 365 audit activity catalog](https://learn.microsoft.com/en-us/purview/audit-log-activities),
and [mailbox auditing guidance](https://learn.microsoft.com/en-us/purview/audit-mailboxes).

## Offline Investigation Cases

Offline cases reuse the normalizers and rule/storyline engine over uploaded
Graph sign-in, Graph directory-audit, and Microsoft 365 activity exports. They
use a synthetic `offline:<case-id>` scope and separate persistence; imported
events and derived detections can never enter the live incident queue. Source
files are format/record bounded, SHA-256 identified, encrypted at rest, and
never returned by the case API. Coverage explicitly distinguishes present,
partial, and missing source fields. In particular, single-factor conclusions
require Entra's explicit `authenticationRequirement` evidence; missing MFA or
Conditional Access fields are reported as a coverage limitation, not inferred
as insecure behavior.

## Next Milestones

1. **Entra risk signals** — risk detections and risky-user correlation with
   Defender incidents.
2. **Detection enrichment** — MITRE mapping, analyst suppression, and
   false-positive feedback. Rule management, scoped thresholds, and exclusions
   are implemented.
3. **Alert operations** — notification routing, SLAs, comments, evidence
   export, and optional Microsoft incident write-back behind explicit
   permissions and an approved workflow.
4. **SOC platform controls** — legal/tenant data
   boundaries, RBAC beyond the v1 two-role model, health/SLO dashboards,
   disaster recovery, and cost/volume budgets.

Phases 1–2 provide a production-shaped security monitoring and durable audit
foundation. RTM is not represented as a replacement for Microsoft
Sentinel, Defender XDR, or a mature 24×7 SOC process.
