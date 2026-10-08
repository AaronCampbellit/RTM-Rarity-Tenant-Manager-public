# ThreatLocker Policy Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add editable ThreatLocker policies plus RTM policy-template actions for promote, merge, and deploy.

> **Status reconciliation — 2026-08-18:** Implemented in the imported
> application commit `2b04195`. Provider detail/update/create behavior is
> covered in `backend/internal/threatlocker/client_test.go`; authenticated
> policy and template workflows are covered in
> `backend/internal/server/server_tl_test.go`; the frontend edit surface is
> `frontend/src/features/threatlocker/PolicyEditModal.tsx`. The unchecked boxes
> below are historical execution notes, not the current backlog. Live portal
> acceptance was not rerun during this reconciliation because no tenant
> credentials were supplied.

**Architecture:** Extend the ThreatLocker provider with policy detail/update/create methods, add server REST endpoints for policy edits and template workflows, and upgrade the Policies tab from read-only to actionable. Keep live unsupported operations explicit and non-crashing.

**Tech Stack:** Go chi API, pgx/mem store patterns, ThreatLocker Portal API, React/Vite/TypeScript/Tailwind.

## Global Constraints

- Do not log or return ThreatLocker tokens.
- Tenant-scoped handlers must authorize tenant access server-side.
- Writes must be previewed/audited or explicitly identified as unsupported.
- Unknown ThreatLocker live endpoints return `NOT_IMPLEMENTED`, never `INTERNAL_ERROR`.

---

### Task 1: Provider Policy Detail And Edit

**Files:**
- Modify: `backend/internal/model/model.go`
- Modify: `backend/internal/threatlocker/threatlocker.go`
- Modify: `backend/internal/threatlocker/client.go`
- Modify: `backend/internal/threatlocker/client_test.go`

**Interfaces:**
- Produces `model.TLPolicyDetail`.
- Produces provider methods `Policy(ctx, tenantID, policyID string)`, `UpdatePolicy(ctx, tenantID string, patch model.TLPolicyPatch)`, `CreatePolicy(ctx, tenantID string, detail model.TLPolicyDetail)`.

- [ ] Add failing provider tests for detail, update, and insert.
- [ ] Implement detail mapping from `Policy/PolicyGetById`.
- [ ] Implement update by loading detail, applying a patch, and posting to `Policy/PolicyUpdateById`.
- [ ] Implement create via `Policy/PolicyInsert`.
- [ ] Run `go test ./internal/threatlocker -count=1`.

### Task 2: Server Policy Endpoints

**Files:**
- Modify: `backend/internal/server/server.go`
- Modify: `backend/internal/server/threatlocker.go`
- Modify: `backend/internal/server/server_tl_test.go`

**Interfaces:**
- Adds `GET /api/v1/tenants/{tenantId}/threatlocker/policies/{policyId}`.
- Adds `PATCH /api/v1/tenants/{tenantId}/threatlocker/policies/{policyId}` admin-only.

- [ ] Add failing server tests for detail, edit success, tech forbidden, and provider error mapping.
- [ ] Wire routes.
- [ ] Decode and validate a conservative patch body.
- [ ] Audit successful policy edits.
- [ ] Run `go test ./internal/server -run ThreatLocker -count=1`.

### Task 3: Template Workflow API

**Files:**
- Modify: `backend/internal/model/model.go`
- Modify: `backend/internal/store/store.go`
- Modify: `backend/internal/store/mem.go`
- Modify: `backend/internal/server/threatlocker.go`
- Modify: `backend/internal/server/server.go`
- Modify: `backend/internal/server/server_tl_test.go`

**Interfaces:**
- Adds `POST /api/v1/threatlocker/policy-templates/promote`.
- Adds `POST /api/v1/threatlocker/policy-templates/merge`.
- Adds `POST /api/v1/threatlocker/policy-templates/{templateId}/deploy`.

- [ ] Add failing tests for promoting a policy to an RTM template.
- [ ] Add failing tests for merging selected policies into a template.
- [ ] Add failing tests for deploy preview/result with partial per-tenant failures.
- [ ] Implement in-memory template storage.
- [ ] Keep Postgres unsupported for template persistence unless schema is added in a later task.
- [ ] Run `go test ./internal/server -run ThreatLocker -count=1`.

### Task 4: Frontend Editable Policies

**Files:**
- Modify: `frontend/src/types/index.ts`
- Modify: `frontend/src/api/client.ts`
- Modify: `frontend/src/api/mock.ts`
- Modify: `frontend/src/features/threatlocker/ThreatLockerPage.tsx`
- Create: `frontend/src/features/threatlocker/PolicyEditModal.tsx`

**Interfaces:**
- Adds client methods for policy detail, update, promote, merge, and deploy.
- Converts Policies tab from read-only to edit/action surface.

- [ ] Add TypeScript types for policy detail, patch, template, and deploy result.
- [ ] Add API client methods and mock equivalents.
- [ ] Add Edit modal for conservative fields.
- [ ] Add row actions: Edit, Promote, Merge, Deploy.
- [ ] Run `npm --prefix frontend run build`.

### Task 5: Verification And Demo Deploy

**Files:**
- Modify docs if endpoint behavior differs from implementation.

- [ ] Run `make vet test build` in `backend`.
- [ ] Run `npm --prefix frontend run build`.
- [ ] Deploy with `RTM_DEMO_PASSWORD=... ./scripts/deploy-demo.sh`.
- [ ] Verify live policy list still returns 200.
- [ ] Verify unsupported live global/template operations return explicit errors.
