# Permission Preflight and Tenant Editing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Report exact and broader effective Microsoft application grants in tenant preflight and let administrators safely edit existing tenant settings without re-entering unchanged secrets.

> **Status reconciliation — 2026-08-18:** Implemented locally in commit
> `2b04195`. Effective-grant resolution, Graph/SharePoint assignment evidence,
> atomic memory/Postgres tenant updates, admin-only handlers, secret-preserving
> frontend edits, and focused tests are present in the files named below. The
> unchecked boxes are historical execution notes. Central SharePoint app
> consent and authenticated live-tenant acceptance still require external
> administrator access and were not claimed here.

**Architecture:** Add a resource-specific application-role assignment inspector behind the Graph provider, then merge assignment evidence with existing runtime probes through a conservative permission implication resolver. Add one atomic store update contract and admin-only tenant settings endpoint, surfaced by a focused edit dialog that preserves blank secrets and uses explicit clear flags.

**Tech Stack:** Go 1.26, chi, pgx, PostgreSQL, React 19, TypeScript, Vite, existing RTM API/mock/UI primitives.

## Global Constraints

- Graph and SharePoint Online permissions are separate resources; never infer coverage across them.
- Blank or omitted secrets preserve stored values; credential removal requires an explicit clear flag.
- A changed client ID requires a replacement secret or an explicit fallback clear.
- Changed live connections must pass validation before the update commits atomically.
- Secrets never appear in API responses, audit entries, logs, test failures, or frontend state after submit.
- Only administrators may update tenant settings.
- Preserve memory/PostgreSQL and mock/real API shape parity.
- Do not use subagents because repository instructions prohibit delegation.
- Do not create commits, push Git, or deploy until explicitly authorized; the checkout has no tracked baseline.

---

### Task 1: Effective Permission Resolution

**Files:**
- Create: `backend/internal/graph/preflight_permissions.go`
- Create: `backend/internal/graph/preflight_permissions_test.go`
- Modify: `backend/internal/model/model.go`
- Modify: `frontend/src/types/index.ts`

**Interfaces:**
- Produces: `resolveEffectiveGrant(resource, required string, assigned map[string]struct{}) (status, grantedVia string)`
- Produces: `PreflightCheck.GrantedVia string`
- Consumes: canonical resource names `Microsoft Graph` and `SharePoint Online`

- [ ] **Step 1: Write failing table tests for exact, broader, missing, and cross-resource grants**

```go
func TestResolveEffectiveGrant(t *testing.T) {
    tests := []struct {
        name, resource, required string
        assigned                 []string
        status, via              string
    }{
        {"exact", "Microsoft Graph", "User.ReadWrite.All", []string{"User.ReadWrite.All"}, "ok", ""},
        {"directory parent", "Microsoft Graph", "User.ReadWrite.All", []string{"Directory.ReadWrite.All"}, "ok", "Directory.ReadWrite.All"},
        {"directory read parent", "Microsoft Graph", "GroupMember.Read.All", []string{"Directory.Read.All"}, "ok", "Directory.Read.All"},
        {"missing", "Microsoft Graph", "Sites.ReadWrite.All", []string{"User.Read.All"}, "missing", ""},
        {"no cross resource", "SharePoint Online", "Sites.FullControl.All", []string{"Directory.ReadWrite.All"}, "missing", ""},
    }
    // Convert assigned to a set, call resolveEffectiveGrant, compare both fields.
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `cd backend && go test ./internal/graph -run TestResolveEffectiveGrant -count=1`

Expected: FAIL because `resolveEffectiveGrant` does not exist.

- [ ] **Step 3: Implement a conservative resource-specific implication map**

```go
var permissionParents = map[string]map[string][]string{
    "Microsoft Graph": {
        "User.Read.All":             {"User.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
        "User.ReadWrite.All":        {"Directory.ReadWrite.All"},
        "Group.Read.All":            {"Group.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
        "GroupMember.Read.All":      {"GroupMember.ReadWrite.All", "Group.Read.All", "Group.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
        "GroupMember.ReadWrite.All": {"Group.ReadWrite.All", "Directory.ReadWrite.All"},
        "Organization.Read.All":     {"Directory.Read.All", "Directory.ReadWrite.All"},
        "Application.Read.All":      {"Application.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
    },
}

func resolveEffectiveGrant(resource, required string, assigned map[string]struct{}) (string, string) {
    if _, ok := assigned[required]; ok {
        return "ok", ""
    }
    for _, parent := range permissionParents[resource][required] {
        if _, ok := assigned[parent]; ok {
            return "ok", parent
        }
    }
    return "missing", ""
}
```

Do not add a parent relationship unless it is supported by Microsoft's application permission capability. Keep SharePoint Online exact-only unless a documented broader SharePoint application role is added deliberately.

- [ ] **Step 4: Add `grantedVia` to backend/frontend preflight types**

```go
type PreflightCheck struct {
    Area, Resource, Permission, Status, Detail string
    GrantedVia string `json:"grantedVia,omitempty"`
}
```

```ts
export interface PreflightCheck {
  area: string;
  resource: string;
  permission: string;
  status: "ok" | "missing" | "error" | "sample";
  detail?: string;
  grantedVia?: string;
}
```

- [ ] **Step 5: Run the focused tests**

Run: `cd backend && go test ./internal/graph -run TestResolveEffectiveGrant -count=1`

Expected: PASS.

---

### Task 2: Inspect Actual Application-Role Assignments

**Files:**
- Create: `backend/internal/graph/client_preflight_assignments.go`
- Create: `backend/internal/graph/client_preflight_assignments_test.go`
- Modify: `backend/internal/graph/client_entra.go`
- Modify: `backend/internal/graph/sharepoint_certificate.go`
- Modify: `backend/internal/graph/sample_entra.go`

**Interfaces:**
- Consumes: `resolveEffectiveGrant`
- Produces: `applicationRoleAssignments(ctx, tenantID, resourceAppID, clientID string) (map[string]struct{}, error)`
- Produces: live `Preflight` rows with no `unchecked` application permissions

- [ ] **Step 1: Write a fake-Microsoft-server test for assignment discovery**

The fake must handle:

```text
GET /servicePrincipals?$filter=appId eq '{clientID}'&$select=id
GET /servicePrincipals/{clientServicePrincipalID}/appRoleAssignments
GET /servicePrincipals/{resourceServicePrincipalID}?$select=appRoles
```

Return an assignment whose `resourceId` is the Graph service principal and
whose `appRoleId` maps to `Directory.ReadWrite.All`. Assert that
`User.ReadWrite.All` and `GroupMember.ReadWrite.All` return `status=ok` with
`grantedVia=Directory.ReadWrite.All`.

- [ ] **Step 2: Run the test and verify it fails**

Run: `cd backend && go test ./internal/graph -run TestPreflightReadsEffectiveAppRoleAssignments -count=1`

Expected: FAIL because assignment inspection is not implemented.

- [ ] **Step 3: Implement assignment lookup and role-ID-to-value mapping**

Use the active resolved client ID. Resolve its tenant service principal, list
its `appRoleAssignments`, load `appRoles` from each relevant resource service
principal, and join `appRoleId` to the role's `value`. Follow
`@odata.nextLink`. Treat 403 as an inspection error, not as proof of missing
permissions.

- [ ] **Step 4: Merge assignment evidence with runtime probes**

For read rows:

```go
status, via := resolveEffectiveGrant(area.resource, area.permission, assigned[area.resource])
check.Status, check.GrantedVia = status, via
probeErr := c.get(ctx, tenantID, area.path, &out)
if status == "ok" && isForbidden(probeErr) {
    check.Status = "error"
    check.Detail = "Permission assignment is present, but Microsoft denied the runtime probe."
}
```

For write rows, resolve from assignments directly. Remove `unchecked`. Add one
diagnostic row when assignments cannot be inspected.

- [ ] **Step 5: Keep sample mode honest**

Sample permission rows remain `sample`; they do not claim actual consent.

- [ ] **Step 6: Add SharePoint Online assignment inspection**

Use resource application ID `00000003-0000-0ff1-ce00-000000000000` and the
central SharePoint certificate app client ID. Keep the existing harmless REST
probe as runtime evidence for `Sites.FullControl.All`.

- [ ] **Step 7: Run Graph tests**

Run: `cd backend && go test ./internal/graph -count=1`

Expected: PASS with exact, parent, missing, pagination, 403 inspection, and
assignment/probe-conflict coverage.

---

### Task 3: Atomic Editable Tenant Store Contract

**Files:**
- Modify: `backend/internal/store/store.go`
- Modify: `backend/internal/store/mem.go`
- Modify: `backend/internal/store/pg.go`
- Modify: `backend/internal/store/mem_test.go`
- Create: `backend/internal/store/pg_tenant_update_test.go` if the existing PG test harness supports database-backed mutation tests

**Interfaces:**
- Produces: `TenantUpdate`
- Produces: `Store.UpdateTenant(ctx context.Context, id string, update TenantUpdate) (model.Tenant, error)`
- Consumes: existing encryption protector and `connectionsFor`

- [ ] **Step 1: Write failing memory-store tests**

Cover:

```go
update := TenantUpdate{Name: ptr("Renamed"), SharePointAdminURL: ptr("https://new-admin.sharepoint.com")}
```

Assert metadata changes while Graph, Exchange, and ThreatLocker secrets remain
byte-for-byte unchanged. Then test `ClearGraph=true`,
`ClearExchange=true`, and `ClearThreatLocker=true`.

- [ ] **Step 2: Run the store test and verify it fails**

Run: `cd backend && go test ./internal/store -run TestUpdateTenant -count=1`

Expected: FAIL because `TenantUpdate` and `UpdateTenant` do not exist.

- [ ] **Step 3: Define explicit optional update fields**

```go
type TenantUpdate struct {
    Name, Domain, MicrosoftTenantID *string
    ClientID, ClientSecret          *string
    ExchangeClientID, ExchangeClientSecret *string
    SharePointAdminURL              *string
    ThreatLockerInstance, ThreatLockerToken, ThreatLockerOrgID *string
    ClearGraph, ClearExchange, ClearThreatLocker bool
}
```

Nil means preserve. A pointer to an empty non-secret field means clear only
where validation allows it.

- [ ] **Step 4: Implement memory-store updates under its mutex**

Copy the current tenant and credentials, apply changes to the copy, then replace
both maps only after every operation succeeds.

- [ ] **Step 5: Implement PostgreSQL updates in one transaction**

Read and decrypt current credentials, merge the update, seal replacement
secrets, execute one tenant row update, and commit. Reuse
`connectionsFor` when returning the updated tenant. Never concatenate SQL field
names from request data.

- [ ] **Step 6: Run store tests**

Run: `cd backend && go test ./internal/store -count=1`

Expected: PASS.

---

### Task 4: Admin-Only Tenant Settings API and Audit

**Files:**
- Create: `backend/internal/server/tenant_settings.go`
- Create: `backend/internal/server/server_tenant_settings_test.go`
- Modify: `backend/internal/server/server.go`
- Modify: `backend/internal/server/handlers.go` only to reuse shared validation helpers
- Modify: `RTM API Specification.md`

**Interfaces:**
- Consumes: `Store.UpdateTenant`, `TenantUpdate`, Graph/ThreatLocker connection tests
- Produces: `PUT /api/v1/tenants/{tenantId}`
- Produces: response `{tenant, connectionTests}`

- [ ] **Step 1: Write failing endpoint tests**

Tests must prove:

- Technician receives 403.
- Blank secrets preserve stored values.
- A new client ID without a replacement secret receives 400.
- Explicit clear switches Graph/Exchange to fallback and disconnects
  ThreatLocker.
- Failed changed-connection validation leaves the old row and secrets intact.
- Audit entry lists non-secret changed fields and credential events only.

- [ ] **Step 2: Run focused server tests and verify failure**

Run: `cd backend && go test ./internal/server -run TenantSettings -count=1`

Expected: FAIL because the route does not exist.

- [ ] **Step 3: Register the admin route**

```go
r.With(s.auth.RequireAdmin).Put("/", s.updateTenantSettings)
```

- [ ] **Step 4: Decode and validate update semantics**

Use pointer JSON fields so omitted differs from supplied blank. Reject:

- Empty required name/domain/directory ID.
- Client ID changes without a nonblank replacement secret.
- Clear plus replacement for the same service.
- Invalid SharePoint admin URLs that are not HTTPS `*.sharepoint.com`.
- ThreatLocker instance/token without an organization ID.

- [ ] **Step 5: Test changed connections before persistence**

Build candidate credentials without altering the store. Add provider methods
that test an explicit candidate credential set, or a narrowly scoped server
validator that constructs the appropriate live client. Only call
`Store.UpdateTenant` after all changed-service tests succeed.

- [ ] **Step 6: Audit without secrets**

Record an action such as `tenant.settings_update` with a resource summary:

```text
fields=name,sharePointAdminUrl; credentials=graph_secret_replaced
```

Do not include IDs if the project treats them as sensitive, and never include
secret/token values.

- [ ] **Step 7: Run focused and full server tests**

Run:

```bash
cd backend
go test ./internal/server -run TenantSettings -count=1
go test ./internal/server -count=1
```

Expected: PASS.

---

### Task 5: Tenant Settings Dialog and Preflight Presentation

**Files:**
- Create: `frontend/src/features/tenants/EditTenantSettingsDialog.tsx`
- Modify: `frontend/src/features/tenants/TenantDetailPage.tsx`
- Modify: `frontend/src/api/client.ts`
- Modify: `frontend/src/api/mock.ts`
- Modify: `frontend/src/types/index.ts`
- Modify: `RTM UI-UX Specification.md`

**Interfaces:**
- Consumes: `PUT /tenants/{id}` and extended `PreflightCheck`
- Produces: `api.tenants.update(id, body)`
- Produces: admin-only Edit Tenant Settings workflow

- [ ] **Step 1: Add frontend update types and API methods**

```ts
export interface TenantSettingsUpdate {
  name?: string;
  domain?: string;
  microsoftTenantId?: string;
  clientId?: string;
  clientSecret?: string;
  clearGraph?: boolean;
  exchangeClientId?: string;
  exchangeClientSecret?: string;
  clearExchange?: boolean;
  sharePointAdminUrl?: string;
  threatLockerInstance?: string;
  threatLockerToken?: string;
  threatLockerOrgId?: string;
  clearThreatLocker?: boolean;
}
```

The mock must preserve secrets conceptually through connection booleans and
honor explicit clear flags.

- [ ] **Step 2: Build the focused edit dialog**

Initialize visible metadata from `Tenant`. Never initialize secret inputs.
Show `Configured` badges from `tenant.connections`. Blank secret copy must say
“Leave blank to keep the current secret.” Clear actions set explicit flags and
disable the corresponding replacement fields until undone.

- [ ] **Step 3: Add client-side safety validation**

Match server rules for new client IDs, explicit clears, SharePoint URL, and
ThreatLocker organization requirements. Server validation remains
authoritative.

- [ ] **Step 4: Wire Tenant Detail**

Add an admin-only **Edit Tenant Settings** button beside Test Connection.
After success, close the dialog, refresh tenant detail, and show a concise
success message. Keep Remove Tenant separate.

- [ ] **Step 5: Render effective parent grants**

For `status=ok`:

```tsx
{c.grantedVia ? `Granted via ${c.grantedVia}` : "Granted"}
```

Remove `Unchecked` handling from the new response contract while retaining a
safe neutral fallback for an older server during rolling deployment.

- [ ] **Step 6: Build the frontend**

Run: `cd frontend && npm run build`

Expected: TypeScript and Vite complete with exit code 0.

---

### Task 6: Documentation, Full Verification, and Authorized Demo Deployment

**Files:**
- Modify: `RTM Microsoft Graph Integration Guide.md`
- Modify: `README.md`
- Modify: `.env.example` only if inspection permissions require clarified setup
- Modify: `scripts/deploy-demo.sh` only if deployment contract changes

**Interfaces:**
- Consumes: all prior tasks
- Produces: documented application-role inspection requirement and verified demo behavior

- [ ] **Step 1: Document preflight interpretation**

Explain exact grants, `Granted via`, resource separation, assignment inspection
failure, and runtime-probe conflicts. Add the permission needed for RTM to
inspect the active service principal's role assignments.

- [ ] **Step 2: Run backend completion gates**

Run: `cd backend && make vet test build`

Expected: vet, all Go tests, API build, and worker build pass.

- [ ] **Step 3: Run frontend completion gate**

Run: `cd frontend && npm run build`

Expected: exit code 0.

- [ ] **Step 4: Review secret safety and working tree**

Run targeted searches for the new secret fields in response/audit serialization,
inspect `git status --short`, and confirm no certificate, key, `.env`, token, or
password file is newly included.

- [ ] **Step 5: Deploy only after explicit authorization**

Use the RTM demo deployment workflow. Inspect shared-host containers first,
operate only on compose project `rtm`, deploy with `scripts/deploy-demo.sh`,
then verify:

```text
docker compose -p rtm -f docker-compose.demo.yml ps
GET http://192.168.86.139:8091/api/v1/version
GET http://192.168.86.139:8090/
```

- [ ] **Step 6: Exercise authenticated live acceptance**

Verify an admin can:

1. Open Edit Tenant Settings.
2. Save a metadata-only change without replacing credentials.
3. Re-run Permission Preflight.
4. See exact and broader grants labeled correctly.
5. Restore the metadata field if the acceptance change was temporary.

Do not clear or replace live credentials during acceptance unless the user
explicitly authorizes that exact mutation.
