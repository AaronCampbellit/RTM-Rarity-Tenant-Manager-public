# RTM UI/UX Specification
## Purpose
Define the user interface, navigation, workflows, and interaction patterns for RTM - Rarity Tenant Manager.
## Primary Users
- MSP Admin
- Engineer
- Read-Only Technician
- Auditor
- Approver
- Global Reporting Admin
## Main Navigation
- **Global** — Dashboard, Security Operations, and the parent-scoped
  ThreatLocker workspace. These destinations operate across all managed
  tenants and do not change scope with the tenant switcher.
- **Tenant Tools** — Users, Groups, Licensing, Exchange, and SharePoint. These
  destinations use the tenant currently selected in the tenant switcher.
  The selector's user count comes from the current Graph tenant summary, not
  the tenant's creation-time placeholder. Tenant-scoped screens must hold a
  loading state until tenant discovery has resolved and must never issue an
  API request with an empty tenant path. The API also rejects `/tenants//...`
  as a validation failure so a future UI regression fails closed.
- **Operations** — Working Sets, Jobs, and Change History.
- **Governance** — Global Reports and Audit Logs.
- **System** — Tenants, Detection Rules, Admin Settings, and Documentation.

Admin Settings → Roles presents the persisted Admin and Technician policies as
clickable cards. Selecting a role opens an editor for its description and
named elevated capabilities. Saving is explicit, audited, and reports API
errors in the dialog. Technician capabilities are editable; Admin capabilities
remain visibly locked while its description can be changed.

Admin Settings → Technicians shows whether each local account has current
credentials or must rotate its password. An authorized operator can reset
another account behind an explicit confirmation. The generated temporary
password appears once with a copy action, while the dialog explains that all
existing sessions were revoked and rotation is required at the next sign-in.
Self-reset is omitted from this flow. Every signed-in operator instead has a
**Change password** action in the account menu that verifies the current
password, confirms the replacement, and keeps the current browser signed in
with newly issued credentials.
## Core UX Principles
- Tenant context must always be visible.
- Dangerous actions must require What If preview and approval.
- Read-only reports and write actions must be clearly separated.
- Results should be exportable only when the user has export permission.
- Every table should support search, filtering, pagination, and CSV export where appropriate.
- Every action should show clear success, warning, and error states.
## Dashboard
Show:
- Assigned tenants
- Global open, critical, and high-severity incident cards that link to Security
  Operations.
- A compact Active & Failed Jobs panel containing only queued/running work and
  unacknowledged failed/partial jobs. Completed jobs remain available on Jobs.
- Recent Changes as the durable human-readable activity ledger.
- Failed job count
- Pending approvals
- Quick report shortcuts
## Tenant Detail Page
Show:
- Tenant name
- Microsoft tenant ID
- Connection status
- Last successful Graph test
- Enabled modules
- Recent jobs
- Recent changes
- Assigned technicians
- Admin-only Edit Tenant Settings dialog. Blank secret fields preserve stored
  values; explicit controls return a service to its global app or disconnect
  it without deleting the tenant.
- Permission Preflight is a collapsed disclosure, not an automatic live probe.
  Its header loads the last saved result and check time; expanding it performs
  no Microsoft request. A separate Run/Re-run control explicitly refreshes the
  durable snapshot. Expanded requirements are grouped by the RTM section that
  consumes them: Security Operations, Directory & Identity, Exchange,
  SharePoint, and Licensing, with per-category missing/attention summaries.

## SharePoint Workspace
The SharePoint navigation item is one workspace with:
- **Sites** — site, library, and folder hierarchy with exact aggregate sizes,
  file totals, unique-permission markers, freshness, and scan coverage.
- **OneDrive** — the same inventory model in a separate view.
- **Access Investigations** — the Share Detective offboarding workflow,
  embedded rather than duplicated in navigation.
- **Scan History** — nightly and manual persistent snapshots with progress,
  timestamps, warnings, and partial-failure visibility.

Selecting a securable object opens its effective permissions. Inherited access
guides the operator to the source assignment by default. Breaking inheritance
is an explicit advanced action. File permission enumeration is on demand.
Every grant, revoke, inheritance break, or inheritance restore requires a
What-If preview and approval.

## Exchange Workspace

Selecting a mailbox opens a three-section detail dialog:

- **Overview** — Graph directory identity and clearly sourced Microsoft 365
  Reports usage/quota data, including its refresh date. Unknown report data is
  labeled `Not collected`; zero is reserved for a confirmed zero. Mailbox type
  is sourced independently from Graph mailbox settings, so report privacy does
  not make the type unknown. When report identities are concealed, the
  workspace shows one coverage banner with the tenant-admin path to restore
  matching instead of repeating unexplained dashes in every row.
- **Mail flow** — all Inbox-rule forwarding, redirects, forward-as-attachment
  actions, automatic replies, locale, and working-hours settings. RTM-managed
  rules are visibly distinguished from user/admin-created rules.
- **Access** — a per-permission coverage strip prevents an empty result from
  implying complete coverage. Send on Behalf delegates come from the Exchange
  Online Admin API and are listed when that connector is authorized. Full
  Access and Send As are labeled `Not supported` until the controlled Exchange
  Online PowerShell reader lands; RTM makes no delegate conclusion for those
  families. Consent/RBAC failures show an actionable Exchange-specific error.

## Security Operations UX

Security Operations lives under **Global**, directly below Dashboard, and is
explicitly cross-tenant.
The header says **All managed tenants** instead of presenting the active tenant
as the queue scope.

Below the monitoring metrics, severity distribution, and connector health, a
compact **Attack Storylines** queue provides RTM's primary correlated
investigation surface. A storyline is a persisted, deterministic progression
assembled from multiple independent detections; individual incidents remain
visible in the queue beneath it. The storyline queue defaults to Active but can
search all retained storylines, filter by tenant, severity, or workflow status,
and sort by risk, activity, or title. Compact rows prioritize severity, title,
attack stages, affected tenants/entities, workflow status, risk, independent
signal count, and last activity. Selecting a row opens an analyst drawer with:

- a chronological attack progression and complete supporting evidence chain;
- explicit reasons the activity was connected and any weak or missing evidence;
- blast radius across users, resources, workloads, and tenants;
- recommended investigation, containment, recovery, and hardening actions;
- RTM-local assignment/status controls. Tenant mutations always launch their
  normal What-If workflow and are never executed from correlation alone.

Late evidence expands the stable storyline instead of creating a duplicate.
Resolved or dismissed storylines remain available through search and status
filters while the default Active view stays focused. Cross-tenant MSP
correlation requires a normalized
administrator identity plus independent behavior; a shared IP alone is never
sufficient.

The page is table-first and shows:
- Open, critical, and high incident metrics.
- Connector health summary and latest fan-out ingestion health.
- Open severity distribution and connector health. Defender, Entra fast
  identity, and Microsoft 365 Audit report health independently; planned
  connectors are labeled `Planned`.
- A search/filter incident queue with tenant, severity, provider/RTM source, RTM
  owner/status, a compact inline alert count only for multi-alert incidents, the
  durable time RTM first received the incident, and a visible native-detection
  confidence label. Search includes native rule IDs and classifications. The
  status filter defaults to **New**, making an empty queue the visible operating
  goal; operators can explicitly select all or handled stages when reviewing
  history.
- Accessible row and select-all-visible checkboxes with a bulk action rail.
  **Accept selected** assigns the current operator and advances only New rows
  to In Progress; an explicit stage selector moves selected rows to New, In
  Progress, Resolved, or Dismissed. Filter changes clear hidden selection, and
  partial failures remain selected for retry.
- A right-side evidence drawer with summary, provider state, RTM-local triage,
  normalized entities, correlated alerts, timeline, and native rule version,
  detection type, and confidence.
- The drawer presents an incident-specific **Recommended response** before
  triage controls. It orders steps by containment, investigation, eradication,
  recovery, and validation; identifies the applicable RTM workspace or
  What-If action; states that guidance does not execute changes; and includes a
  collapsible resolution checklist.

Assignment and status controls must say that they update RTM workflow only and
do not mutate the source provider. Sample evidence is labeled in connector
health, incident rows, and the drawer. Missing tenant consent gives the operator
the exact required permission (`SecurityIncident.Read.All` for Defender or
Office 365 Management APIs `ActivityFeed.Read` for audit ingestion). A tenant
without Defender can still show healthy native audit monitoring.

**Detection Rules** lives under **System**. **Raw Event Explorer** opens from a
button on Security Operations instead of appearing as a separate navigation
destination. Both retain the global **All managed tenants** context. Detection
Rules is table-first with catalog/enabled/custom/override metrics, filters,
locked built-in labels, and a right-side editor. Technicians have read-only
catalog access. Admins can tune scope, severity, confidence, thresholds, and
exclusions; custom rules also expose normalized/raw match fields. Applying an
enabled change remains unavailable until the exact form has a successful
evidence preview. Revision restore is an explicit preview-and-restore action.
Every match condition and exclusion value uses a searchable/selectable choice
control instead of requiring operators to memorize provider strings. Choices
combine RTM's supported Microsoft 365 catalog with tenant-aware normalized
values observed in retained evidence. Existing saved values stay selectable;
raw-evidence choices expose safe field names only, never evidence values or
secrets.

Raw Event Explorer uses an applied-search form so typing does not continuously
query evidence. It includes tenant/workload/operation/actor/IP/result and date
filters, bounded pagination, tenant-labeled rows, and an on-demand drawer. It
labels Graph-fast versus unified-audit sources and shows the event's occurred
→ first observed → stored → detection-created lifecycle. The
drawer separates normalized evidence, related detections, and each retained
source-native provider payload. Semantically equivalent Graph-fast and unified-
audit JSON remain visibly distinct after recursive redaction; each payload
labels its source, content type, observation time, and truncation state. The
drawer offers **Create rule from event** only to Admins. Missing collection
fields from older or partial records normalize to safe empty values before
rendering. A route-level error boundary contains any unexpected render fault
inside the workspace so the RTM shell never becomes a blank screen.

**Offline Investigations** is a separate Global workspace. It accepts exported
Graph sign-in, Graph directory-audit, and Microsoft 365 activity evidence from
tenants that are not connected to RTM. The case list shows tenant labels,
analysis state, evidence volume, and last activity. A draft case uses a compact
drag/drop manifest with explicit format and size limits. The analyzed case has
Overview, Timeline, Detections, and Evidence tabs, with storylines as the
primary output. Overview pairs attack storylines with a bounded Case Detections
list; its top metrics summarize available evidence-source families alongside
events, detections, priority, and storylines. Every selected storyline uses the
same evidence-backed explanation structure: a plain-language observation,
risk and confidence, evidence window, connected-signal count, attack-stage
progression, affected identity and scope, chronological contributing detection
highlights, deterministic correlation reasons, weak-evidence warnings, and
recommended investigation steps. The explanation is explicitly a correlation
hypothesis that requires analyst validation; it never presents a storyline as
confirmed compromise. The Timeline tab is an
investigator activity feed: matching records are collapsed into 15-minute
bursts and expose actor-to-target context, client IP, result, useful
allowlisted evidence facts, and linked detection signals. Search plus workload,
detection-match, failure, and external-access filters let an analyst isolate
actionable records without exposing raw provider payloads. The Evidence tab
retains the detailed coverage panel that calls out missing MFA,
Conditional Access, or source-family fields. Every case is labeled **Offline ·
read-only**: no result enters the live incident queue and no case view exposes
tenant-write actions. Admin deletion explicitly removes encrypted files and
derived case data.

## Working Set UX
A Working Set is a reusable list of users or objects created from reports or searches.
Workflow:
1. Run report or search.
2. Select users or objects.
3. Save as Working Set. The dialog submits the exact tenant and selected IDs,
   stays open with actionable errors if persistence fails, and confirms the
   saved name/count before offering **View Working Sets**.
4. Open another tool.
5. Load Working Set.
6. Run What If preview.
7. Approve action.

The Working Sets page is not a read-only ledger. Selecting a row opens its
details and retained users. Operators can edit the name, description, and
exact user membership, then save the durable set. **Open in Users** switches to
the set's tenant, selects its retained users, and exposes the normal Working
Set and What-If action rail.

## Group UX

Group creation requires a name, a purpose description, and one of the two
Graph-creatable types. The description field is visibly marked required and
explains that it gives future technicians the context needed before changing
membership. Opening an assigned Graph group exposes **Add users** directly on
the Group Members page. The user picker excludes existing members and sends
the exact selection through the standard What-If preview. Dynamic and
Exchange-managed membership show why direct editing is unavailable.
## What If Preview Dialog
Must show:
- Action summary
- Tenant name
- Target objects
- Expected changes
- Skipped objects
- Warnings
- Errors
- Risk level
- Required permission
- Approval button
## Change History UX
Show last 50 changes by default.
Columns:
- Timestamp
- Technician
- Tenant
- Action
- Target
- Status
- Revert status
Each change detail view should show:
- Before state
- After state
- Microsoft request IDs if available
- Execution logs
- Revert option when supported
## Revert UX
Workflow:
1. Select change from history.
2. View revert eligibility.
3. Run What If Revert.
4. Approve revert.
5. Log revert as a new change.
## Global Reports UX
Global Reports must be visually separate from tenant-specific tools.
Rules:
- Read-only only.
- Admin-only.
- Tenant column always visible.
- Results grouped or filterable by tenant.
- Exports audited.
## Error UX
Errors should be written for technicians, not developers.
Each error should include:
- What failed
- Which tenant was affected
- Whether anything changed
- Recommended next step
- Correlation ID

## Embedded Documentation
Documentation is an authenticated RTM workspace organized into visible Setup,
Safe operations, Tenant tools, Global & security, and Administration & help
sections. It provides searchable guides, a Start Here path, stable deep links,
responsive tables, callouts, and expandable screenshots.

The Setup section contains the complete Microsoft authorization reference,
grouped by RTM feature area. Every row identifies the exact Microsoft resource,
permission or RBAC role, permission type, runtime use, and when it is required
or optional. It also explains admin consent, the temporary GUI Exchange
bootstrap, Recipient Management assignment, SharePoint certificate model, and
the stored Permission Preflight verification workflow.

## Future UI Features
- Saved report templates
- Scheduled reports
- Report comparison
- Approval inbox
- Notification center
- Dark mode

### Optional security event timeline

Raw Event Explorer defaults to its existing table and offers a Timeline toggle.
The timeline reuses the applied search filters and displays local calendar dates
chronologically from left to right. Date dots are navigation, not activity counts.
Selecting a date opens a 24-hour timeline; selecting an hour lists its loaded
matching events chronologically and opens the existing event detail drawer.
The first and last day are clipped to the applied search times. Day reads use the
existing audited event-search API in 100-event batches, with explicit partial-day
coverage and a Load more control until all matching evidence has been loaded.
Empty dates remain selectable; errors offer retry. Times show the browser timezone,
and all timeline controls support keyboard use and horizontal scrolling.

### Storyline timeline views

Attack storylines and the complete evidence chain each offer List / Timeline,
with List as the default. The overview plots each filtered storyline at its
latest activity; the detail timeline plots signals at their occurrence times.
Both use the security-event timeline's horizontal date dots and hourly groups,
with local timezone labels, counts, keyboard-operable selection, and horizontal
scrolling. Dates without activity are omitted, explicitly labeled. Cards retain
tenant and severity context; detail cards retain supporting evidence. Timeline
ordering is chronological and the overview list-sort control is disabled in
Timeline mode. Existing list views, triage, and audited detail reads remain.
