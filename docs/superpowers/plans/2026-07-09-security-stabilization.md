# Security Stabilization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the confirmed authentication, secret-at-rest, ThreatLocker configuration, and server-side What-If enforcement gaps without changing the product's two-role model.

> **Status reconciliation — 2026-08-18:** Implemented in commit `2b04195`.
> Current tests cover live account hydration, production key validation,
> AES-GCM field protection, ThreatLocker parent configuration, and actor-bound
> single-use write approvals. Both Compose files validate locally. The
> unchecked boxes below are historical execution notes; a shared-demo
> deployment was deliberately not performed during this reconciliation.

**Architecture:** Authentication will verify the signed token and then hydrate the current account record, so authorization is never derived from stale claims. PostgreSQL will encrypt every per-tenant credential using a versioned AES-GCM envelope and will migrate existing plaintext values during startup. What-If responses will issue a short-lived, single-use, actor-bound approval token which every external write consumes.

**Tech Stack:** Go, chi, pgx/PostgreSQL, AES-GCM, React/TypeScript, Docker Compose.

## Global Constraints

- Production requires externally supplied JWT and field-encryption keys.
- Do not change the all-tenants-access model or address item 6 repository/CI hygiene.
- Every external write remains admin-only, audited, and protected by a server-side preview approval.
- Preserve existing tenant credential API shapes; credentials remain write-only.

---

### Task 1: Harden JWT configuration and live account authorization

**Files:**
- Modify: `backend/internal/config/config.go`, `backend/internal/auth/auth.go`, `backend/internal/server/server_test.go`, `docker-compose.demo.yml`, `.env.example`

- [ ] Write tests proving a valid token for a disabled or demoted account is rejected and that refresh reloads current account role/status.
- [ ] Require a non-empty, non-demo JWT signing key in production; move demo configuration to environment substitution.
- [ ] Validate issuer and hydrate the active account in access-token middleware and refresh issuance.
- [ ] Run `go test ./internal/auth ./internal/server`.

### Task 2: Encrypt tenant credentials at rest

**Files:**
- Create: `backend/internal/securefields/securefields.go`, `backend/internal/securefields/securefields_test.go`
- Modify: `backend/internal/config/config.go`, `backend/internal/store/pg.go`, `backend/cmd/api/main.go`, `backend/cmd/worker/main.go`, `backend/internal/config/config_test.go`, `.env.example`, `docker-compose.demo.yml`

- [ ] Write unit tests for versioned AES-GCM encryption, wrong-key rejection, and legacy plaintext migration detection.
- [ ] Add `RTM_FIELD_ENCRYPTION_KEY` decoding and production validation; accept a base64 32-byte key only.
- [ ] Encrypt/decrypt all tenant client secrets and ThreatLocker tokens at the Postgres store boundary, with a startup transaction converting existing plaintext records.
- [ ] Ensure API and worker share the same protector and fail closed when PostgreSQL is configured without it.
- [ ] Run `go test ./internal/config ./internal/securefields ./internal/store`.

### Task 3: Restore parent-scoped ThreatLocker runtime wiring

**Files:**
- Modify: `backend/cmd/api/main.go`, `backend/cmd/worker/main.go`, `docker-compose.demo.yml`, `backend/internal/server/server_tl_test.go`

- [ ] Write an entrypoint-config regression test proving the parent organization identifier reaches the live ThreatLocker client.
- [ ] Pass `ThreatLockerParentOrgID` to both live client constructors and forward all global ThreatLocker variables from demo Compose.
- [ ] Run `go test ./internal/threatlocker ./internal/server`.

### Task 4: Enforce single-use What-If approvals for writes

**Files:**
- Modify: `backend/internal/model/model.go`, `backend/internal/server/server.go`, `backend/internal/server/handlers.go`, `backend/internal/server/threatlocker.go`, `backend/internal/server/server_test.go`, `backend/internal/server/server_tl_test.go`, `frontend/src/types/index.ts`, `frontend/src/api/client.ts`, affected What-If dialogs and ThreatLocker edit dialogs

- [ ] Write failing API tests proving execute/revert and direct ThreatLocker external writes reject missing, mismatched, expired, or replayed approvals.
- [ ] Add an actor-bound, five-minute, single-use approval registry and return its token from each preview endpoint.
- [ ] Require and consume the token immediately before all external writes; keep revalidation of current state.
- [ ] Update React callers to request previews and supply the returned approval token only after the user confirms the modal.
- [ ] Run focused backend tests and `npm run build`.

### Task 5: Final regression and deployment-readiness checks

**Files:**
- Modify: `README.md`, `RTM API Specification.md`, `RTM Security Specification.md`, `AGENTS.md`, `CLAUDE.md`

- [ ] Document required secrets, approval-token semantics, and the ThreatLocker parent configuration.
- [ ] Run `make vet test build`, `npm run build`, and `npm audit --omit=dev --audit-level=high`.
- [ ] Validate Compose syntax if Docker is available; otherwise report that limitation without deployment.
