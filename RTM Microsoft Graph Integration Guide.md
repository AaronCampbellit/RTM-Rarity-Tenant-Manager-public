# RTM Microsoft Graph Integration Guide
## Purpose
Define how RTM interacts with Microsoft 365 services through Microsoft Graph, Exchange Online, and SharePoint APIs.
## Integration Strategy
Microsoft Graph should be the first-choice API for Microsoft 365 data and actions.
Use service-specific APIs only when Graph lacks coverage or does not expose the required detail.
## Primary Microsoft Services
- Microsoft Entra ID / Azure AD
- Microsoft Graph
- Exchange Online
- SharePoint Online
- OneDrive for Business later
- Teams-backed Microsoft 365 Groups later
## Authentication Model
General Graph features support per-tenant client credentials or the global
`RTM_ENTRA_*` application.

SharePoint administration uses one RTM-managed, multi-tenant Entra application
with a deployment-managed X.509 certificate. Tenant administrators grant
application consent; tenants do not upload certificates or private keys to
RTM. Configure:

- `RTM_SHAREPOINT_CLIENT_ID`
- `RTM_SHAREPOINT_CERTIFICATE_PATH`
- `RTM_SHAREPOINT_PRIVATE_KEY_PATH`

The certificate and key must be PEM encoded, match, and be readable by the API
and worker. The private key belongs in the deployment secret store.
Later:
- Delegated auth for technician-context actions.
- Conditional Access-aware sign-in.
- Separate permission profiles for lower-risk and higher-risk modules.
## Permission Strategy
Use least privilege.
Permissions should be documented per feature.

The in-app **Documentation → Setup → Microsoft 365 setup & permissions** guide
is the operator-facing checklist. Its complete least-privilege authorization
map is:

| RTM area | Microsoft resource | Permission or role | Type | Purpose |
|---|---|---|---|---|
| Security Operations | Microsoft Graph | `AuditLog.Read.All` | Application | Fast sign-ins, directory audits, identity detections, and MFA registration reporting. |
| Security Operations | Office 365 Management APIs | `ActivityFeed.Read` | Application | Unified audit ingestion, history, Raw Event Explorer, and native detections. |
| Security Operations | Microsoft Graph | `SecurityIncident.Read.All` | Application | Optional Defender XDR incident and alert reads. |
| Directory & Identity | Microsoft Graph | `User.Read.All` | Application | Users, guests, raw detail, hybrid signals, mailbox identities, and SharePoint principals. |
| Directory & Identity | Microsoft Graph | `Group.Read.All` | Application | Group inventory and metadata. |
| Directory & Identity | Microsoft Graph | `GroupMember.Read.All` | Application | Membership and group-based SharePoint access. |
| Directory & Identity | Microsoft Graph | `RoleManagement.Read.Directory` | Application | Privileged-role reporting. |
| Directory & Identity | Microsoft Graph | `Policy.Read.All` | Application | Conditional Access reporting. |
| Directory & Identity | Microsoft Graph | `Application.Read.All` | Application | App registrations and credential-expiry reporting. |
| Directory & Identity | Microsoft Graph | `User.ReadWrite.All` | Application | Sign-in and licensing write actions. |
| Directory & Identity | Microsoft Graph | `User-PasswordProfile.ReadWrite.All` | Application | Password reset and the password step of compromised-user containment. Sensitive/admin targets can additionally require an Entra directory role for the service principal. |
| Directory & Identity | Microsoft Graph | `UserAuthenticationMethod.ReadWrite.All` | Application | Remove registered authentication methods during compromised-user containment. |
| Directory & Identity | Microsoft Graph | `User.RevokeSessions.All` | Application | Invalidate refresh tokens and browser sessions during compromised-user containment. |
| Directory & Identity | Microsoft Graph | `GroupMember.ReadWrite.All` | Application | Cloud-group membership writes. |
| Licensing | Microsoft Graph | `Organization.Read.All` | Application | Subscribed SKUs, capacity, and readiness. |
| Exchange | Microsoft Graph | `Reports.Read.All` | Application | Optional mailbox usage, size, item, archive, quota, and activity enrichment. |
| Exchange | Microsoft Graph | `MailboxSettings.ReadWrite` | Application | Automatic replies, forwarding settings, and RTM-managed inbox rules. |
| Exchange | Office 365 Exchange Online | `Exchange.ManageAsAppV2` | Application | Runtime Exchange Admin API token. |
| Exchange | Exchange Online | `Recipient Management` | Exchange RBAC | Restricts runtime mailbox cmdlets such as `Get-Mailbox` and `Set-Mailbox`. |
| Exchange bootstrap | Microsoft Graph | `RoleManagement.ReadWrite.Exchange` | Temporary delegated | GUI-only creation of the Recipient Management assignment; token and credentials are discarded. |
| SharePoint | Microsoft Graph | `Sites.Read.All` | Application | Site, library, drive, item, and sharing discovery. |
| SharePoint | Microsoft Graph | `Sites.ReadWrite.All` | Application | Supported drive-item permission management. |
| SharePoint | Microsoft Graph | `Sites.FullControl.All` | Application | Direct site and item permission grants/revocations. |
| SharePoint | SharePoint Online | `Sites.FullControl.All` | Application | REST role assignments and inheritance through the certificate app. |

The central SharePoint certificate app also uses Graph `User.Read.All` and
`GroupMember.Read.All`. Broader directory grants may satisfy conservative
preflight parent relationships, but are not the recommended setup and do not
replace AuditLog, Policy, Reports, Sites, Exchange, SharePoint Online, or
Office 365 Management API consent.
## Group Coverage
RTM should account for:
- Microsoft 365 Groups
- Security Groups
- Mail-enabled Security Groups
- Distribution Lists
- Dynamic Distribution Lists
- Teams-backed groups
- Synced on-prem groups
Some Exchange group types may require Exchange Online PowerShell, Exchange REST-backed cmdlets, or alternate APIs if Graph does not expose all necessary details.
## SharePoint Coverage
RTM uses Microsoft Graph for site/drive discovery, identities, items, and size
metadata. It uses SharePoint REST for unique inheritance, role assignments,
SharePoint groups, and permission writes.

The default persistent scan enumerates sites, libraries, folders, and file
metadata so folder sizes and file totals are exact. It checks folder
inheritance but does not enumerate every file's permissions. File-level
permission scans are explicitly requested. Sites and OneDrive are separate
views; Share Detective is the workspace's Access Investigations view.

Writes support grant, revoke, break inheritance, and restore inheritance at
site/library/folder/file scope. All writes require What-If and approval.
Inherited revocation guides the operator to its source assignment; breaking
inheritance locally is an explicit advanced choice.

Run `scripts/setup-sharepoint-app.sh` to generate the deployment certificate
and print the app-registration checklist. Add each tenant's SharePoint admin
URL when connecting it, then run Permission Preflight to test both resources.

## Permission Preflight Resolution

Preflight reads the application `roles` claim from the access token Microsoft
issues for each resource. Exact roles display **Granted**. A conservative,
documented parent relationship displays **Granted via**, such as
`Directory.ReadWrite.All` satisfying supported user and group directory
permissions. It does not imply unrelated Sites, mailbox, Conditional Access,
audit-report, or SharePoint Online permissions.

Graph and SharePoint Online tokens are evaluated separately. Harmless read
probes remain a second signal; if a token contains a role but Microsoft denies
the corresponding read, RTM reports an error rather than a healthy result.

## Security Operations Coverage

Phase 1 reads Microsoft Defender XDR incidents through the Microsoft Graph v1
endpoint `/security/incidents?$top=100&$expand=alerts`. The live provider uses
the least-privileged application permission `SecurityIncident.Read.All`; it
does not request write access to Microsoft incidents. Microsoft returns recent
incidents first. RTM surfaces `@odata.nextLink` as a truncation warning instead
of silently implying complete history.

The security service fans out through the same per-tenant authority and
credential resolver as other Graph features. A 403 is reported as missing
consent, a 401 as rejected tenant credentials, and throttling as degraded
coverage. Successful tenants remain visible when another tenant fails.

Incident and alert bodies are normalized at the provider boundary. Tokens and
raw evidence payloads never leave the Go backend; the frontend receives a
small deduplicated entity projection. Microsoft remains the Defender incident
source of truth. RTM stores only local triage for those Defender incidents;
the separate audit connector owns its immutable events and rule detections.
That audit connector has a separate authenticated explorer: list/search stays
normalized, while one selected event may return only a recursively redacted,
size-bounded projection. Unredacted Management Activity bodies remain inside
the Go/PostgreSQL boundary.

Microsoft 365 Audit is a live, separate connector in `internal/m365audit`. Its
authoritative backfill requests a tenant-scoped
`https://manage.office.com/.default` token, requires Office 365 Management APIs
application permission `ActivityFeed.Read`, maintains the four core activity
subscriptions, and persists checkpointed/deduplicated records. The detection
engine uses a bounded 30-day/latest-50,000-event window for threshold,
cross-tenant, login-sequence, and baseline rules. Country/session/client
signals are consumed only when Microsoft includes them in the audit record;
they are not Graph Identity Protection verdicts. Entra ID
Protection remains planned; risk detections
require `IdentityRiskEvent.Read.All` and may require P1/P2 licensing for the
signals being queried.

The same package owns a separate one-minute fast identity lane. It uses a
tenant-scoped `https://graph.microsoft.com/.default` token and application
permission `AuditLog.Read.All` to poll `/auditLogs/signIns` and
`/auditLogs/directoryAudits`. The collectors keep independent checkpoints;
provider-record IDs deduplicate Graph records against later Management
Activity backfill while both source-native payloads remain available as
separately redacted evidence. Event Hub streaming is intentionally not part of
this design.

When a tenant is connected, RTM may also queue a bounded history import. It
uses newest-to-oldest one-day windows for both Graph identity feeds and all
four Management Activity feeds, marks imported evidence as historical, and
keeps the periodic checkpoints independent so live coverage starts at once.
The current onboarding maximum is seven days. Imported evidence participates
in baselines and rule previews; a persisted per-tenant incident cutoff decides
whether a match may enter the incident queue.
## Exchange Online Coverage
Use Graph when available, but expect Exchange-specific handling for:
- Distribution groups
- Dynamic distribution groups
- Mail-enabled security group Exchange-specific metadata
- Mailbox permissions
- Send As
- Send on Behalf
- Shared mailbox details
Long-term approach may include controlled Exchange Online PowerShell execution through backend workers when API coverage is incomplete.

RTM currently reads mailbox identity, settings, automatic replies, and Inbox
forwarding/redirect actions through Microsoft Graph. Mailbox inventory batches
`mailboxSettings.userPurpose` to classify user, shared, room, and equipment
mailboxes independently from reports. It optionally merges the Microsoft 365
mailbox usage report. If that report conceals identities, RTM must not guess a
join: size, item, archive, quota, and activity values remain **not collected**
and the UI directs an administrator to Microsoft 365 admin center → Settings →
Org settings → Reports. Dedicated Exchange credentials may be stored on a
tenant. RTM uses Microsoft's Exchange Online Admin API preview for Send on
Behalf inventory and writes. It requests an app-only token for
`https://outlook.office365.com/.default`; the app needs
`Exchange.ManageAsAppV2` admin consent and Exchange Recipient Management RBAC.
Every request uses the documented v2.0 POST envelope and app-only system-mailbox
anchor. The preview API does not currently expose Full Access or Send As, so
those families and litigation hold display as **not supported/not collected**,
never as empty and never as a failed Graph connection. They remain reserved for
a controlled Exchange Online PowerShell connector.
## API Reliability
Implement:
- Retry logic
- Backoff for throttling
- Pagination handling
- Delta queries where useful
- Batching where safe
- Correlation IDs
- Microsoft request ID capture
- Partial failure handling
## Job Design
Large Microsoft 365 operations should run through River jobs.
Examples:
- Tenant user inventory
- Tenant group inventory
- Group membership report
- SharePoint permissions scan
- Global reports
- CSV exports
- Bulk group changes
- License changes
- Revert jobs
## What If Support
Before executing write actions, RTM should query current state and calculate expected changes.
Preview should show:
- Objects that will change
- Objects already in desired state
- Objects that cannot be changed
- Permissions needed
- Risk level
- Expected after-state
## Change Logging
For every write action, capture:
- Tenant
- Technician
- Action type
- Target object
- Before state
- After state
- Microsoft request IDs
- Success/failure state
- Error details
## Future Integration Features
- Delta sync for reports
- Tenant health checks
- License optimization reporting
- SharePoint external sharing review
- Scheduled global reports
- Webhook support where applicable
