# RTM Hybrid AD / Entra Sync Framework
## Purpose
RTM must support Microsoft tenants that are cloud-only and tenants that use hybrid identity, where on-prem Active Directory synchronizes to Microsoft Entra ID through Entra Connect / Azure AD Connect / Cloud Sync.
Hybrid support is required because many MSP clients still manage the source of authority on-prem while exposing users, groups, licenses, mailboxes, and access in Microsoft 365.
## Core Principle
RTM should treat Entra ID as the primary cloud management surface, but it must detect and respect when an object is mastered on-premises.
RTM should not blindly attempt cloud-side writes against synced objects when the correct source of authority is on-prem AD.
## Identity Modes
Each tenant should have an identity mode classification:
1. Cloud-only tenant
   - Users and groups are created and managed directly in Entra ID / Microsoft 365.
   - RTM can use Graph-backed write actions where permissions allow.
2. Hybrid tenant
   - Some or all users/groups are synced from on-prem AD.
   - Entra ID contains cloud representations of objects, but the source of authority may be on-prem.
   - RTM must detect synced objects and route actions accordingly.
3. Mixed tenant
   - Tenant contains both cloud-only and synced objects.
   - RTM must evaluate source of authority per object, not only per tenant.
## Object Source of Authority
RTM should store source-of-authority metadata for users and groups:
- tenant_id
- object_id
- object_type
- display_name
- user_principal_name or mail
- on_premises_sync_enabled
- on_premises_immutable_id
- on_premises_security_identifier
- on_premises_domain_name
- on_premises_sam_account_name
- on_premises_distinguished_name
- source_of_authority: cloud | on_prem | unknown
- last_cloud_sync_seen_at
- last_inventory_refresh_at
## Hybrid Detection
During tenant inventory, RTM should inspect Microsoft Graph fields that indicate on-prem sync state, including:
- onPremisesSyncEnabled
- onPremisesImmutableId
- onPremisesSecurityIdentifier
- onPremisesDomainName
- onPremisesSamAccountName
- onPremisesDistinguishedName
If these fields indicate sync, RTM should mark the object as on-prem mastered.
## Write Action Rules
RTM write actions must be source-aware.
For cloud-only objects:
- Allow supported Graph / Microsoft 365 write actions after What If preview.
- Continue using approval, audit, change history, and revert framework.
For synced on-prem objects:
- Block direct cloud-side writes when Microsoft 365 will reject them or when the change should be made on-prem.
- Show a clear technician-facing message: "This object is synced from on-prem AD. Make this change in on-prem Active Directory, then allow Entra sync to update Microsoft 365."
- Where safe, allow cloud-side changes that are valid for synced objects, such as license assignment or cloud-only service configuration.
- Mark actions as cloud-writable, on-prem-required, or unsupported.
## Action Classification
Every RTM workflow should declare its hybrid behavior:
- cloud_supported
- hybrid_supported
- hybrid_limited
- on_prem_required
- unsupported
Examples:
User display name:
- Cloud-only: Graph write allowed.
- Synced: on-prem required.
User license assignment:
- Cloud-only: Graph write allowed.
- Synced: Graph write usually allowed because licensing is cloud-side.
Group membership:
- Cloud-only Microsoft 365/security group: Graph write allowed.
- Synced security group: on-prem required.
- Distribution group/mail-enabled group: may require Exchange-specific handling.
Password reset:
- Cloud-only: cloud reset supported if permissions allow.
- Synced: depends on password writeback and tenant configuration; otherwise on-prem required.
Account disable:
- Cloud-only: Graph write allowed.
- Synced: should generally be on-prem required unless explicitly supported and tested.
## Hybrid Tenant Connection Model
RTM v1 should not require direct domain controller access.
Initial support should be cloud-side hybrid awareness:
- Detect hybrid tenants.
- Detect synced objects.
- Prevent unsafe writes.
- Explain source-of-authority restrictions.
- Include hybrid status in reports.
- Include synced object filters in user/group inventory.
Future support may add an optional On-Prem Connector:
- Lightweight agent installed on client network or domain-joined server.
- Communicates outbound to RTM API over HTTPS.
- Performs approved on-prem AD reads/writes.
- Supports AD user/group queries, OU placement, group membership changes, password resets, and account disable/enable actions.
- Requires strong authentication, signed jobs, tenant isolation, audit logging, and restricted service account permissions.
## On-Prem Connector Future Requirements
If implemented, the connector must follow the same RTM safety model:
- No inbound firewall requirement.
- Outbound-only connection to RTM.
- Per-tenant connector registration.
- Connector identity bound to tenant_id.
- Signed job payloads.
- Short-lived job tokens.
- Least-privilege AD service account.
- Full audit trail for every on-prem read/write.
- What If preview before write actions.
- Revert support where technically safe.
- Clear failure and partial-success handling.
## UI Requirements
RTM should visibly show hybrid state.
Tenant page:
- Identity mode: Cloud-only / Hybrid / Mixed / Unknown
- Last inventory sync
- Synced object count
- Cloud-only object count
- Domains detected from on-prem attributes
User and group detail pages:
- Source of authority badge: Cloud or On-Prem AD
- Sync metadata
- Which actions are available
- Which actions are blocked and why
Workflow pages:
- What If preview must identify objects that cannot be changed because they are on-prem mastered.
- Bulk operations must separate successful, skipped, blocked, and failed objects.
## Reporting Requirements
Hybrid-aware reports should include:
- Synced users
- Cloud-only users
- Synced groups
- Cloud-only groups
- Objects with unknown source
- Objects with missing or stale sync metadata
- Group membership source-of-authority report
- License assignment report across synced and cloud users
## Database Additions
RTM should include source-of-authority fields in cached object tables and report result tables.
Suggested additions:
- identity_mode on tenant records
- source_of_authority on user/group cache records
- on_premises_* metadata fields where available
- hybrid_action_support metadata per workflow/action
- connector_id for future on-prem connector support
## Security Notes
Hybrid support must not become a shortcut around RTM security.
- No direct LDAP/LDAPS or domain controller credentials should be stored in RTM v1.
- Any future on-prem connector must use least privilege and outbound-only communication.
- On-prem actions must be audited with the same detail as Graph actions.
- RTM should never hide the fact that a change requires on-prem AD.
## MVP Scope
For v1, implement hybrid-aware cloud management, not direct on-prem AD management.
MVP should include:
1. Tenant hybrid detection.
2. Per-object source-of-authority detection.
3. Hybrid-aware user inventory.
4. Hybrid-aware group inventory.
5. Hybrid-aware group membership reporting.
6. Write-action blocking for on-prem mastered objects.
7. Clear What If preview messaging.
8. Hybrid filters and badges in the UI.
9. Audit logging for skipped/blocked hybrid actions.
10. Documentation for which actions are cloud-writable vs on-prem-required.
## Later Scope
Later versions may add:
- On-prem connector agent.
- Direct AD read inventory.
- Direct AD group membership changes.
- OU-aware user lifecycle workflows.
- Password reset / unlock workflows.
- Hybrid deprovisioning workflows.
- Entra Connect health visibility if Microsoft APIs or customer permissions allow it.
## Product Decision
RTM should be designed from the beginning to understand hybrid AD environments.
The product does not need to directly manage on-prem AD in v1, but it must correctly detect, display, report, and safely handle synced objects so MSP technicians can use RTM confidently across cloud-only, hybrid, and mixed Microsoft tenants.
