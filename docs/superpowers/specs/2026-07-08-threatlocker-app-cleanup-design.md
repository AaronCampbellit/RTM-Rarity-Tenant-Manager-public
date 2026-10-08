# ThreatLocker Apps Cleanup Design

## Goal

Add a ThreatLocker Apps tab that lets RTM operators consolidate duplicate
tenant applications into parent-owned global applications and global policies,
matching the cleanup workflow available in the ThreatLocker portal.

## Source Of Truth

Use the internal ThreatLocker Portal API reference at
`/Users/aaroncampbell/Library/Mobile Documents/com~apple~CloudDocs/threatlocker-portal-api.md`
for endpoint names and quirks. The relevant confirmed or documented surfaces
are:

- `Application/ApplicationGetByParameters` for application search.
- `Application/ApplicationGetById` for application detail.
- `Application/ApplicationUpdateById` for rename/redescribe.
- `Application/ApplicationInsert` for creating a custom application.
- `Application/ApplicationUpdateForDelete` for deleting apps without policies.
- `Application/ApplicationConfirmUpdateForDelete` for cascade deletion when
  policies still reference the app.
- `ApplicationFile/ApplicationFileGetByApplicationId` for app file rules. This
  is `GET`; `POST` returns 405.
- `ApplicationFile/ApplicationFileInsert` for copying file rules into the
  retained app.
- `Policy/PolicyGetByParameters` and `Policy/PolicyGetForViewPoliciesByApplicationId`
  for policy discovery.
- `Policy/PolicyUpdateById`, `Policy/PolicyInsert`, and
  `Policy/PolicyUpdateForDeleteByIds` for global policy cleanup.
- `DeployPolicyQueue/DeployPolicies` for pushing queued policy changes.

Required ThreatLocker role permissions include `View Application Control
Applications`, `Edit Application Control Applications`, `Allow Application
Merge`, `View Application Control Policies`, `Edit Application Control
Policies`, `Promote To Entire Organization`, and the general `Promote to
Global` permission where the tenant uses that role split.

## Product Behavior

The ThreatLocker page gains an `Apps` tab next to Devices, Approval Requests,
and Policies.

The Apps tab shows every application returned by the API for the active RTM
tenant and, when configured, the parent/global ThreatLocker organization. Rows
show app name, owning organization, source scope (`Parent` or `Tenant`), OS,
status, built-in/custom marker, policy count, file-rule count, and last-seen or
updated information when the portal returns it. Search must call the backend so
large app libraries are not filtered only in the browser.

Operators can rename one application from the Apps tab. Rename uses
`Application/ApplicationUpdateById`, preserves unedited fields from
`ApplicationGetById`, and audits the change. Built-in apps are read-only.

Operators can select similar custom apps and start cleanup. Cleanup has a
preview step before mutation. The preview identifies:

- Which selected app will become the retained parent-owned application.
- Whether RTM will reuse an existing parent app, promote one selected tenant app
  by recreating it in the parent org, or create a new parent app.
- Which app files will be copied into the retained app.
- Which tenant policies reference selected apps.
- Which policy will become or remain global.
- Which redundant policies and apps will be deleted after merge.
- Which connected tenants cannot be processed because of missing connection,
  missing permissions, or API errors.

Execution should follow the ThreatLocker portal model:

1. Resolve or create the retained parent-owned app.
2. Copy all unique file rules from selected duplicate apps into the retained app.
3. Rewrite or create the retained global policy so it targets the parent-owned
   app and the entire organization/global scope.
4. Remove redundant policies with `Policy/PolicyUpdateForDeleteByIds`.
5. Delete old duplicate apps with `ApplicationUpdateForDelete`; when the portal
   reports policy dependencies remain and the operator confirmed cleanup, use
   `ApplicationConfirmUpdateForDelete`.
6. Push queued changes with `DeployPolicyQueue/DeployPolicies`.

The result reports every app, policy, file rule, and tenant touched. Partial
failure is allowed, but RTM must stop before destructive deletion if the
retained parent app or retained global policy was not created or updated.

## Backend Design

The ThreatLocker provider gains an application-management surface:

- Search applications by tenant org, parent org, search text, search type, OS,
  and include-child-orgs flag.
- Read one application detail.
- Read application file rules.
- Rename an application.
- Create a parent-owned custom application.
- Insert application file rules one at a time.
- Delete or confirm-delete applications.
- List policies by application.
- Delete policies.
- Deploy queued policy changes.

RTM also needs a first-class parent/global ThreatLocker org context. Add
configuration for the parent organization ID, separate from each managed
tenant's child org ID. The existing `RTM_THREATLOCKER_INSTANCE` and
`RTM_THREATLOCKER_TOKEN` remain the parent API credentials; the new parent org
ID tells RTM where global applications and policies live. A tenant without a
child org ID remains `NOT_CONNECTED`, but the Apps cleanup action should also
fail clearly if the parent org ID is not configured.

Backend API endpoints should be admin-only for mutation:

- `GET /api/v1/tenants/{tenantId}/threatlocker/apps?search=...`
- `GET /api/v1/tenants/{tenantId}/threatlocker/apps/{appId}`
- `PATCH /api/v1/tenants/{tenantId}/threatlocker/apps/{appId}`
- `POST /api/v1/tenants/{tenantId}/threatlocker/apps/cleanup-preview`
- `POST /api/v1/tenants/{tenantId}/threatlocker/apps/cleanup-execute`

Preview returns a deterministic plan and warnings. Execute revalidates the plan
from live state instead of trusting the browser's preview payload.

Cleanup execution should run through the job system because it performs several
external writes and can partially fail per endpoint or tenant. The audit trail
records preview denial/failure, execution start, execution result, and each
destructive cleanup action in plain English without tokens or raw secrets.

## Frontend Design

The Apps tab uses existing table, toolbar, badge, button, checkbox, dialog, and
input primitives. It should feel like an operational cleanup console, not a
marketing page.

Expected controls:

- Search box and OS/source filters.
- Multi-select checkboxes.
- Rename action for one editable custom app.
- Cleanup action enabled only when at least two custom apps are selected.
- Cleanup preview dialog with retained parent app choice, global policy choice,
  counts, warnings, and a confirm checkbox before execution.
- Result dialog or notice showing completed, partial, and failed items.

The UI should not expose raw endpoint names. Error messages should explain the
missing ThreatLocker permission or configuration when the backend can derive it
from the portal error envelope.

## Error Handling

All ThreatLocker failures continue through the existing `httpx` error envelope
with correlation IDs. Missing parent org config returns a validation/config
error, not `INTERNAL_ERROR`. Permission failures should preserve ThreatLocker's
permission text when safe, because the portal names the exact missing role
permission.

Destructive cleanup is fail-closed:

- Do not delete source apps until the retained app exists and has received all
  required file rules.
- Do not delete redundant policies until the retained global policy exists or
  was successfully promoted.
- Do not call `ApplicationConfirmUpdateForDelete` unless the operator confirmed
  destructive cleanup in the execution request.

## Testing

Add fake ThreatLocker portal coverage for:

- App search requiring non-empty `searchText`.
- App file list using `GET`.
- App rename using `PUT ApplicationUpdateById`.
- Parent app creation plus file-rule copy.
- Policy-by-app discovery and policy deletion.
- Cleanup fail-closed behavior when retained app creation fails.
- Cleanup partial failure reporting when one duplicate app delete fails.

Add server tests for admin-only access, missing parent org config, preview shape,
execute job result, audit entries, and ThreatLocker permission error mapping.

Add frontend mock data and build coverage for the Apps tab, rename dialog, and
cleanup preview dialog.

## Non-Goals

- No Storage Control, Elevation Control, Web Control, Network Control, or
  Config Manager cleanup in this slice.
- No low-level app-file rule editing UI beyond the merge/copy behavior.
- No direct portal-session automation. RTM uses the Portal API only.
- No best-effort delete when the retained parent app/global policy failed.
