# ThreatLocker Apps Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a ThreatLocker Apps tab that consolidates duplicate tenant applications into parent-owned global applications and global policies.

> **Status reconciliation — 2026-08-18:** Implemented in commit `2b04195`.
> Client primitives, fail-closed preview/execute/reconcile handlers, durable
> operation records, frontend lifecycle states, and focused tests now live in
> `backend/internal/threatlocker`, `backend/internal/server/threatlocker.go`,
> `frontend/src/features/threatlocker`, and their test files. The unchecked
> boxes below are historical execution notes. Live portal acceptance was not
> rerun without external credentials.

**Architecture:** Add ThreatLocker application primitives to the provider, expose admin-only preview/execute APIs, and run destructive cleanup through RTM's job/audit path. The frontend adds an Apps tab with backend search, rename, multi-select cleanup preview, and execution results.

**Tech Stack:** Go chi API, RTM `httpx` envelopes, in-memory/Postgres store patterns, ThreatLocker Portal API, React/Vite/TypeScript/Tailwind.

## Global Constraints

- Use the internal ThreatLocker Portal API reference for endpoint names and method quirks.
- Do not log or return ThreatLocker tokens.
- Tenant-scoped handlers must authorize tenant access server-side.
- Mutating app cleanup endpoints are admin-only.
- Cleanup is fail-closed: do not delete source apps or redundant policies until the retained parent app and retained global policy exist.
- `ApplicationFile/ApplicationFileGetByApplicationId` must use `GET`; `POST` returns 405.
- ThreatLocker permission errors should preserve the safe permission text from the portal error envelope.
- Missing parent organization configuration must return a clear config/validation error, not `INTERNAL_ERROR`.

---

### Task 1: ThreatLocker App Models And Config

**Files:**
- Modify: `backend/internal/model/model.go`
- Modify: `backend/internal/config/config.go`
- Modify: `backend/internal/threatlocker/threatlocker.go`
- Modify: `frontend/src/types/index.ts`

**Interfaces:**
- Produces `model.TLApplication`, `model.TLApplicationDetail`, `model.TLApplicationFile`, `model.TLAppCleanupPreview`, `model.TLAppCleanupResult`.
- Produces provider request structs `threatlocker.AppSearchRequest`, `threatlocker.AppCleanupRequest`.
- Adds `Config.ThreatLockerParentOrgID`, loaded from `RTM_THREATLOCKER_PARENT_ORG_ID`.

- [ ] **Step 1: Add frontend/backend model definitions**

Define backend structs with JSON names that match frontend types:

```go
type TLApplication struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	OrganizationID  string `json:"organizationId"`
	Organization    string `json:"organization"`
	Source          string `json:"source"` // "parent" | "tenant"
	OSType          int    `json:"osType"`
	OS              string `json:"os"`
	Status          string `json:"status"`
	BuiltIn         bool   `json:"builtIn"`
	Hidden          bool   `json:"hidden"`
	PolicyCount     int    `json:"policyCount"`
	FileCount       int    `json:"fileCount"`
	UpdatedAt       string `json:"updatedAt"`
}
```

- [ ] **Step 2: Add config field**

Load `RTM_THREATLOCKER_PARENT_ORG_ID` in `backend/internal/config/config.go`.

- [ ] **Step 3: Run compile check**

Run: `go test ./internal/model ./internal/config -count=1`

Expected: PASS.

### Task 2: Provider Application Primitives

**Files:**
- Modify: `backend/internal/threatlocker/threatlocker.go`
- Modify: `backend/internal/threatlocker/client.go`
- Modify: `backend/internal/threatlocker/client_test.go`

**Interfaces:**
- Produces provider methods:
  `Applications(ctx, tenantID string, req AppSearchRequest) ([]model.TLApplication, error)`,
  `Application(ctx, tenantID, appID string) (model.TLApplicationDetail, error)`,
  `ApplicationFiles(ctx, tenantID, appID string) ([]model.TLApplicationFile, error)`,
  `UpdateApplication(ctx, tenantID string, patch model.TLApplicationPatch) (model.TLApplicationDetail, error)`,
  `CreateApplication(ctx, auth Auth, detail model.TLApplicationDetail) (model.TLApplicationDetail, error)`,
  `InsertApplicationFile(ctx, auth Auth, file model.TLApplicationFile) error`,
  `DeleteApplication(ctx, tenantID, appID string, confirm bool) error`,
  `PoliciesForApplication(ctx, tenantID, appID string) ([]model.TLPolicy, error)`,
  `DeletePolicies(ctx, tenantID string, policyIDs []string) error`,
  `DeployPolicies(ctx, auth Auth) error`.

- [ ] **Step 1: Write failing client tests**

Add tests for app search payload, app file `GET`, app rename `PUT`, app delete endpoint selection, policy delete `PUT`, and deploy queue `POST`.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/threatlocker -run 'Application|PolicyDelete|DeployPolicies' -count=1`

Expected: FAIL because provider methods do not exist.

- [ ] **Step 3: Implement primitives**

Add wire-shape decoders that tolerate bare arrays and `{data:[rows]}` envelopes. Use `doMethod` for non-default methods and never include tokens in errors.

- [ ] **Step 4: Verify GREEN**

Run: `go test ./internal/threatlocker -run 'Application|PolicyDelete|DeployPolicies' -count=1`

Expected: PASS.

### Task 3: App Cleanup Preview And Execution

**Files:**
- Modify: `backend/internal/server/server.go`
- Modify: `backend/internal/server/threatlocker.go`
- Modify: `backend/internal/server/server_tl_test.go`

**Interfaces:**
- Adds `GET /api/v1/tenants/{tenantId}/threatlocker/apps?search=dell`.
- Adds `PATCH /api/v1/tenants/{tenantId}/threatlocker/apps/{appId}`.
- Adds `POST /api/v1/tenants/{tenantId}/threatlocker/apps/cleanup-preview`.
- Adds `POST /api/v1/tenants/{tenantId}/threatlocker/apps/cleanup-execute`.

- [ ] **Step 1: Write failing server tests**

Cover app listing, admin-only rename, missing parent org config, cleanup preview, fail-closed execute, partial delete failure, and audit entries.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/server -run 'ThreatLocker.*App|ThreatLocker.*Cleanup' -count=1`

Expected: FAIL with missing routes or missing methods.

- [ ] **Step 3: Implement handlers**

Wire routes under the existing tenant ThreatLocker route group. Preview computes the retained parent app and global policy plan from live state. Execute revalidates live state, performs app/file/policy operations in order, and returns `TLAppCleanupResult`.

- [ ] **Step 4: Verify GREEN**

Run: `go test ./internal/server -run 'ThreatLocker.*App|ThreatLocker.*Cleanup' -count=1`

Expected: PASS.

### Task 4: Apps Tab UI

**Files:**
- Modify: `frontend/src/types/index.ts`
- Modify: `frontend/src/api/client.ts`
- Modify: `frontend/src/api/mock.ts`
- Modify: `frontend/src/features/threatlocker/ThreatLockerPage.tsx`
- Create: `frontend/src/features/threatlocker/AppRenameModal.tsx`
- Create: `frontend/src/features/threatlocker/AppCleanupDialog.tsx`

**Interfaces:**
- Produces API client methods `apps`, `updateApp`, `cleanupAppsPreview`, and `cleanupAppsExecute`.
- Adds `Apps` to the existing ThreatLocker tabs.

- [ ] **Step 1: Add TypeScript types and mock data**

Mirror backend model JSON exactly. Mock should include parent and tenant duplicate apps with file/policy counts.

- [ ] **Step 2: Add API client methods**

Use `/tenants/${tenantId}/threatlocker/apps` and cleanup endpoints.

- [ ] **Step 3: Build Apps tab**

Use `PageToolbar`, `SearchInput`, `DataTable`, `Checkbox`, `Badge`, and icon buttons. The cleanup button is enabled for two or more selected custom apps.

- [ ] **Step 4: Add rename and cleanup dialogs**

Rename patches name/description. Cleanup dialog calls preview first, shows retained app/policy/deletion counts, requires explicit confirmation, then executes.

- [ ] **Step 5: Verify frontend build**

Run: `npm --prefix frontend run build`

Expected: PASS.

### Task 5: Docs And Full Verification

**Files:**
- Modify: `RTM API Specification.md`
- Modify: `RTM ThreatLocker Module.md`
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `CLAUDE.md`

**Interfaces:**
- Documents app cleanup endpoints, parent org config, required ThreatLocker permissions, and fail-closed destructive cleanup behavior.

- [ ] **Step 1: Update docs/specs**

Add the Apps tab and cleanup workflow to the authoritative RTM docs.

- [ ] **Step 2: Run backend verification**

Run: `cd backend && make vet test build`

Expected: PASS.

- [ ] **Step 3: Run frontend verification**

Run: `npm --prefix frontend run build`

Expected: PASS.

- [ ] **Step 4: Demo deploy if credentials are available**

Run: `RTM_DEMO_PASSWORD="$RTM_DEMO_PASSWORD" ./scripts/deploy-demo.sh`

Expected: RTM web and API remain healthy on ports 8090/8091.
