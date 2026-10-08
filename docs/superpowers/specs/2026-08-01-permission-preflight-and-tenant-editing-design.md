# Permission Preflight and Tenant Editing Design

## Goal

Make RTM's tenant permission preflight report the effective application
permissions actually granted to the tenant's app registrations, including
documented coverage from broader Microsoft permissions. Let administrators
edit an existing tenant without deleting it or re-entering unchanged secrets.

## Permission Preflight

### Sources of truth

RTM will combine two independent signals:

1. Application-role assignments on the tenant's Microsoft Graph and
   SharePoint Online service principals.
2. Existing harmless endpoint probes, which prove that a feature can currently
   read its Microsoft resource.

RTM will resolve the active app registration for each service after applying
the existing per-tenant/global fallback rules. It will inspect that app's
application-role assignments for the corresponding resource service
principal. The preflight will never perform a write to test consent.

### Effective-grant resolution

Every required permission will be classified as:

- `granted`: the exact application permission is assigned.
- `granted_via_parent`: a broader assigned permission is in RTM's explicit
  implication map. The response identifies the parent permission.
- `missing`: assignments were read successfully and neither an exact nor a
  supported parent grant exists.
- `error`: RTM could not inspect assignments or the runtime probe failed for a
  reason other than missing consent.
- `sample`: the tenant is not using a live Microsoft connection.

The UI will label the first two states **Granted** and **Granted via
Directory.ReadWrite.All** (or the applicable parent). It will not display
application permissions as `Unchecked`.

The implication map will be conservative, resource-specific, and covered by
tests. A parent grant is recognized only where Microsoft's application
permission model gives it the required capability. RTM will not infer coverage
from similar names. Graph and SharePoint Online assignments remain separate;
a Graph grant never satisfies a SharePoint Online permission.

Endpoint probes remain useful runtime evidence. If an assignment is present
but its associated probe receives a permission denial, the row becomes
`error` and explains the conflict rather than claiming a healthy grant.

### Inspection permission

RTM must be able to read service principals and app-role assignments.
Preflight will report a dedicated diagnostic when the active app lacks the
directory/application read access needed to inspect its own assignments. It
will not silently convert an inspection failure into `missing`.

## Editable Tenant Settings

### API and authorization

Add an admin-only tenant settings update endpoint. It accepts:

- Tenant display name, primary domain, and Microsoft directory ID.
- Graph client ID and optional replacement secret.
- Exchange Online client ID and optional replacement secret.
- SharePoint admin URL.
- ThreatLocker portal instance, organization ID, and optional replacement
  token.
- Explicit clear flags for stored Graph, Exchange, and ThreatLocker
  credentials.

The central SharePoint certificate remains deployment-managed and is not
editable or uploadable from the tenant UI.

### Secret semantics

- A blank or omitted secret preserves the currently stored secret.
- Supplying a nonblank secret replaces it.
- Removing stored credentials requires an explicit clear control.
- Clearing Graph or Exchange credentials returns that service to its documented
  global/fallback application.
- Clear and replacement cannot be requested for the same credential in one
  operation.
- Secrets are encrypted at rest and never returned by the API, audit trail, or
  logs.

Client ID changes require either a replacement secret or an explicit clear to
fallback; RTM will not pair a new client ID with an unrelated old secret.

### Validation and connection tests

The server validates domains, directory IDs, SharePoint admin URLs, credential
pairs, and ThreatLocker organization requirements. It tests every changed live
connection before finalizing the update. If a connection test fails, the
update is rejected atomically and the previous settings remain active.

An unchanged service is not retested as part of saving unrelated metadata.
The existing Test Connection and Permission Preflight actions remain available
for explicit diagnostics.

### User interface

Tenant Detail gains an admin-only **Edit Tenant Settings** button. The dialog
uses the same grouped service layout as Connect Tenant:

- Existing secrets display as **Configured**, never as masked values.
- Secret inputs say that blank preserves the current value.
- Each stored service credential has an explicit **Use global app** or
  **Disconnect** control with confirmation.
- Save summarizes changed metadata and connections.
- Successful save refreshes the tenant detail and service connection cards.

Tenant removal remains a separate destructive workflow.

## Auditing

Every update records actor, tenant, timestamp, result, changed non-secret
fields, credential replacement/clear events, and connection-test outcome.
Audit data records only facts such as `graph_secret_replaced`; it never stores
secret values.

## Compatibility

Existing tenant creation and credential fallback behavior remain supported.
The preflight response adds effective-grant metadata while retaining the
existing area, resource, permission, status, and detail fields. The frontend
will tolerate older responses during a rolling deployment.

## Verification

Tests will cover:

- Exact Graph and SharePoint Online grants.
- Supported broader Graph grants, including `Directory.ReadWrite.All`.
- No cross-resource inheritance.
- Missing consent and assignment-inspection errors.
- Assignment/probe conflicts.
- Blank-secret preservation and explicit credential clearing.
- Client-ID changes without replacement secrets being rejected.
- Atomic rollback when a changed connection test fails.
- Admin-only authorization, tenant isolation, and secret-safe auditing.
- Memory and PostgreSQL store parity.
- Mock/real frontend contract parity and production frontend build.
- Demo migration, health, fresh bundle, authenticated tenant edit, and
  permission-preflight response.
