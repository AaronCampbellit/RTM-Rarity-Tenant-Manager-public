# Backlog Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the actionable dependency, export-audit, live-readiness, and documentation gaps identified by the 2026-08-18 repository audit.

**Architecture:** Keep export creation local for the already-materialized interactive datasets, but require an authenticated server audit acknowledgement before the browser download begins. Add a secret-free configuration readiness model and CLI, update vulnerable packages deliberately, and make historical planning documents distinguish shipped code from external acceptance and deferred roadmap work.

**Tech Stack:** Go 1.26, chi, React, TypeScript, Vite, Node test runner, npm audit, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-08-18-backlog-closure-design.md`

> **Execution status — 2026-08-18:** Tasks 1–5 are implemented and committed
> on `codex/finish-backlog`. Focused red/green tests, full backend/frontend
> checks, zero-finding `npm audit`, and Compose rendering passed. Task 6 is the
> publication procedure; its GitHub result is recorded in the pull request,
> not by rewriting this plan after publication.

## Global Constraints

- Never include credential values, tokens, certificate contents, or private-key paths in audit resources or readiness details beyond the configured path name already supplied by the operator.
- An export download must not start unless its server audit request succeeded.
- Preserve the two-role v1 model and existing tenant authorization behavior.
- Mock and live API clients must retain the same request and result shape.
- Do not deploy to the shared demo environment.
- Do not claim external live acceptance without external tenant access.

---

### Task 1: Dependency advisory remediation

**Files:**
- Modify: `frontend/package.json`
- Modify: `frontend/package-lock.json`

**Interfaces:**
- Consumes: existing React Router component APIs used throughout `frontend/src`
- Produces: a lockfile with zero `npm audit` findings

- [ ] **Step 1: Capture the current security trigger**

Run:

```bash
cd frontend
npm audit --json
```

Expected: nonzero result naming vulnerable `react-router`,
`react-router-dom`, `nanoid`, and `postcss` dependency paths.

- [ ] **Step 2: Install the bounded patched versions**

Run:

```bash
cd frontend
npm install react-router-dom@^7.18.2
npm audit fix
```

Do not use `--force`; the direct Router major is intentional and the audit
fix is limited to lockfile-compatible transitive patches.

- [ ] **Step 3: Verify compatibility and advisory closure**

Run:

```bash
cd frontend
npm test
npm run build
npm audit
```

Expected: all tests pass, the Vite production build succeeds, and audit
reports zero vulnerabilities.

- [ ] **Step 4: Commit the remediation**

```bash
git add frontend/package.json frontend/package-lock.json
git commit -m "fix: update vulnerable frontend dependencies"
```

---

### Task 2: Server-side export audit acknowledgement

**Files:**
- Create: `backend/internal/server/exports.go`
- Create: `backend/internal/server/server_exports_test.go`
- Modify: `backend/internal/server/server.go`
- Modify: `RTM API Specification.md`

**Interfaces:**
- Consumes: `store.Store.AppendAudit`, `store.Store.Tenant`, authenticated `auth.Principal`, and the request correlation ID
- Produces: `POST /api/v1/exports/generate` accepting `exportGenerateRequest` and returning `{ "status": "recorded" }`

- [ ] **Step 1: Write failing route tests**

Add tests that send a valid tenant export, then inspect the real memory store:

```go
func TestExportGenerateAuditsAuthenticatedDownload(t *testing.T) {
    h, st := newTestAPI(t)
    token := login(t, h, techEmail, seed.DemoPassword).AccessToken
    rec := call(t, h, http.MethodPost, "/api/v1/exports/generate", token,
        `{"kind":"users","filename":"users.csv","rowCount":3,"tenantId":"ten_1"}`, nil)
    if rec.Code != http.StatusOK { t.Fatalf("status = %d: %s", rec.Code, rec.Body.String()) }
    entries, _ := st.Audit(t.Context())
    if entries[0].Action != "exports.generate" || entries[0].Actor == "" {
        t.Fatalf("audit = %+v", entries[0])
    }
}
```

Add table cases for path-like filenames, unknown kinds, negative/oversized row
counts, unknown tenant IDs, malformed JSON, and missing authentication. Assert
that rejection does not append an `exports.generate` success entry.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
cd backend
go test ./internal/server -run ExportGenerate -count=1
```

Expected: valid requests return 404 because the route is not registered.

- [ ] **Step 3: Implement the minimal validated handler**

Create a fixed allowlist and request type in `exports.go`:

```go
type exportGenerateRequest struct {
    Kind     string `json:"kind"`
    Filename string `json:"filename"`
    RowCount int    `json:"rowCount"`
    TenantID string `json:"tenantId,omitempty"`
}

var exportKinds = map[string]struct{}{
    "users": {}, "group-members": {}, "mailboxes": {},
    "change-history": {}, "global-report": {}, "share-detective": {},
    "threatlocker-applications": {}, "threatlocker-devices": {},
}
```

Reject unknown fields with `json.Decoder.DisallowUnknownFields`, validate the
kind, basename, `.csv` suffix, filename length, and row-count range, resolve a
supplied tenant through `s.store.Tenant`, then append:

```go
model.AuditEntry{
    Actor: auth.UserFromContext(r.Context()).Name,
    Action: "exports.generate",
    Resource: normalizedExportResource(body),
    Result: "Success",
    CorrelationID: httpx.CorrelationID(r.Context()),
}
```

Register `r.Post("/exports/generate", s.generateExport)` inside the authenticated,
password-rotated group.

- [ ] **Step 4: Verify GREEN and full backend compatibility**

Run:

```bash
cd backend
go test ./internal/server -run ExportGenerate -count=1
go test ./...
go vet ./...
```

Expected: focused and full tests pass with no vet findings.

- [ ] **Step 5: Document and commit the contract**

Document the request validation, synchronous audit acknowledgement, and
client-generated interactive CSV boundary in `RTM API Specification.md`.

```bash
git add backend/internal/server/exports.go backend/internal/server/server_exports_test.go backend/internal/server/server.go 'RTM API Specification.md'
git commit -m "feat: audit CSV export generation"
```

---

### Task 3: Audit-first browser CSV utility

**Files:**
- Create: `frontend/tests/csv.test.ts`
- Modify: `frontend/src/lib/csv.ts`
- Modify: `frontend/src/api/client.ts`
- Modify: `frontend/src/api/mock.ts`
- Modify: `frontend/src/features/users/UsersPage.tsx`
- Modify: `frontend/src/features/groups/GroupMembersPage.tsx`
- Modify: `frontend/src/features/exchange/ExchangePage.tsx`
- Modify: `frontend/src/features/change-history/ChangeHistoryPage.tsx`
- Modify: `frontend/src/features/global-reports/GlobalReportsPage.tsx`
- Modify: `frontend/src/features/share-detective/ShareDetectivePage.tsx`
- Modify: `frontend/src/features/threatlocker/ThreatLockerPage.tsx`

**Interfaces:**
- Consumes: `api.exports.generate(request: ExportGenerateRequest): Promise<{status: "recorded"}>`
- Produces: `downloadAuditedCsv(request, audit, dependencies?): Promise<boolean>`

- [ ] **Step 1: Write failing orchestration tests**

Test the real utility with injected external boundaries:

```ts
test("downloads only after the audit acknowledgement", async () => {
  const events: string[] = [];
  const ok = await downloadAuditedCsv(request,
    async () => { events.push("audit"); return { status: "recorded" }; },
    { download: () => events.push("download"), notify: () => events.push("notify") });
  assert.equal(ok, true);
  assert.deepEqual(events, ["audit", "download"]);
});

test("blocks download when the audit request fails", async () => {
  const events: string[] = [];
  const ok = await downloadAuditedCsv(request,
    async () => { throw new Error("offline"); },
    { download: () => events.push("download"), notify: () => events.push("notify") });
  assert.equal(ok, false);
  assert.deepEqual(events, ["notify"]);
});
```

- [ ] **Step 2: Run the utility test and verify RED**

Run:

```bash
cd frontend
node --test tests/csv.test.ts
```

Expected: import failure because `downloadAuditedCsv` does not exist.

- [ ] **Step 3: Implement the utility and API parity**

Export `ExportGenerateRequest`, `AuditExport`, and `downloadAuditedCsv` from
`src/lib/csv.ts`. Await the supplied audit function; invoke `downloadCsv` only
after success; on failure call the injected notifier or `window.alert` with a
fixed message and return `false`.

Add `api.exports.generate` to call `/exports/generate`, and add a mock function
that prepends a matching `exports.generate` entry to `mock.audit`.

- [ ] **Step 4: Route every CSV button through the audited utility**

Replace all eight direct calls with:

```ts
void downloadAuditedCsv(
  { kind: "users", filename: "users.csv", rowCount: rows.length, tenantId: activeTenant?.id },
  api.exports.generate,
);
```

Use the surface-specific kind and omit tenant ID only for global report and
global ThreatLocker exports.

- [ ] **Step 5: Verify frontend behavior and production compilation**

Run:

```bash
cd frontend
node --test tests/csv.test.ts
npm test
npm run build
```

Expected: audit sequencing tests and the full suite pass; TypeScript and Vite
build without errors.

- [ ] **Step 6: Commit the frontend integration**

```bash
git add frontend/src frontend/tests/csv.test.ts
git commit -m "feat: require audit before CSV downloads"
```

---

### Task 4: Secret-free integration readiness command

**Files:**
- Create: `backend/cmd/readiness/main.go`
- Create: `backend/internal/config/readiness.go`
- Create: `backend/internal/config/readiness_test.go`
- Modify: `backend/Makefile`
- Modify: `README.md`
- Modify: `backend/README.md`

**Interfaces:**
- Consumes: `*config.Config` fields already loaded from environment
- Produces: `Config.IntegrationReadiness() []IntegrationCheck` and CLI flag `--require`

- [ ] **Step 1: Write failing readiness classification tests**

Use literal configurations and temporary certificate files to cover Graph
live/sample, SharePoint live/not-configured/invalid, and ThreatLocker
live/not-configured. Assert `Missing` contains environment variable names and
that no secret value appears in marshalled results.

```go
func TestIntegrationReadinessDoesNotExposeSecrets(t *testing.T) {
    cfg := &Config{EntraClientID: "id", EntraClientSecret: "top-secret", EntraTenantID: "tenant"}
    raw, _ := json.Marshal(cfg.IntegrationReadiness())
    if bytes.Contains(raw, []byte("top-secret")) { t.Fatal("readiness exposed a secret") }
}
```

- [ ] **Step 2: Run the config test and verify RED**

Run:

```bash
cd backend
go test ./internal/config -run IntegrationReadiness -count=1
```

Expected: compile failure because `IntegrationReadiness` is undefined.

- [ ] **Step 3: Implement deterministic classifications**

Define:

```go
type IntegrationCheck struct {
    Name string `json:"name"`
    Mode string `json:"mode"`
    Missing []string `json:"missing,omitempty"`
    Problems []string `json:"problems,omitempty"`
}
```

Use fixed environment-variable names and `os.Stat` for configured SharePoint
certificate/key paths. Report only missing names and safe problem categories.

- [ ] **Step 4: Add the CLI and Make target**

The command loads config, prints indented JSON, parses a comma-separated
`--require` list, and exits status 2 when a required integration is not live.
Add `readiness` to the backend Makefile:

```make
readiness:
	go run ./cmd/readiness
```

- [ ] **Step 5: Verify tests, command behavior, and builds**

Run:

```bash
cd backend
go test ./internal/config -run IntegrationReadiness -count=1
go run ./cmd/readiness
go run ./cmd/readiness --require=graph
go test ./...
go vet ./...
go build ./cmd/readiness ./cmd/api ./cmd/worker
```

Expected: the default command exits zero and reports Graph sample mode locally;
the required Graph command exits 2 without credentials; all package checks and
builds pass.

- [ ] **Step 6: Document and commit readiness**

Document local inspection and deployment gating without secret examples.

```bash
git add backend/cmd/readiness backend/internal/config/readiness.go backend/internal/config/readiness_test.go backend/Makefile README.md backend/README.md
git commit -m "feat: add integration readiness checks"
```

---

### Task 5: Reconcile historical plans and final repository state

**Files:**
- Modify: `docs/superpowers/plans/2026-07-07-threatlocker-policy-management.md`
- Modify: `docs/superpowers/plans/2026-07-08-threatlocker-app-cleanup.md`
- Modify: `docs/superpowers/plans/2026-07-09-security-stabilization.md`
- Modify: `docs/superpowers/plans/2026-08-01-permission-preflight-and-tenant-editing.md`
- Modify: `docs/superpowers/plans/2026-08-03-threatlocker-session-preload.md`
- Modify: `README.md`
- Modify: `backend/README.md`
- Modify: `RTM Hybrid Implementation Plan.md`

**Interfaces:**
- Consumes: current tests, routes, types, commits, and explicit provider limits
- Produces: dated plan status blocks and a categorized current backlog

- [ ] **Step 1: Add evidence-based status blocks**

Each historical plan gets a 2026-08-18 block immediately after its goal that
states `Implemented`, `Implemented; external acceptance pending`, or
`Superseded`, cites concrete files/tests/commits, and says the old unchecked
boxes are execution history rather than current backlog.

- [ ] **Step 2: Categorize current README work**

Replace the ambiguous remaining-work lists with:

1. operational prerequisites requiring tenant/admin input;
2. verified provider limitations that intentionally return explicit errors;
3. deferred architectural projects that require their own design and tests.

Keep Postgres integration tests, Redis rate limiting, sqlc, Exchange REST/MFA,
hybrid reports, and the on-prem connector visible; do not label them shipped.

- [ ] **Step 3: Verify documentation consistency**

Run:

```bash
rg -n 'Current status|Operational prerequisites|Provider limitations|Deferred architecture|Status reconciliation' README.md backend/README.md 'RTM Hybrid Implementation Plan.md' docs/superpowers/plans
rg -n 'audited export endpoint|FIXME|XXX' --glob '!frontend/node_modules/**' --glob '!frontend/dist/**' --glob '!backend/bin/**' .
```

Expected: status sections are present and no active source marker remains for
audited exports.

- [ ] **Step 4: Run the complete verification gate**

Run:

```bash
cd backend && make vet test build
cd ../frontend && npm test && npm run build && npm audit
cd .. && docker compose -f docker-compose.yml config -q
docker compose -f docker-compose.demo.yml config -q
git diff --check
git status --short
```

Expected: every command exits zero and only intentional tracked changes exist
before the documentation commit.

- [ ] **Step 5: Commit the reconciliation**

```bash
git add README.md backend/README.md 'RTM Hybrid Implementation Plan.md' docs/superpowers/plans
git commit -m "docs: reconcile implemented and deferred work"
```

---

### Task 6: Publish for review

**Files:**
- No source changes

**Interfaces:**
- Consumes: verified `codex/finish-backlog` branch
- Produces: pushed branch and pull request against `main`

- [ ] **Step 1: Inspect final branch scope**

```bash
git status --short --branch
git log --oneline origin/main..HEAD
git diff --stat origin/main...HEAD
```

- [ ] **Step 2: Push without rewriting history**

```bash
git push -u origin codex/finish-backlog
```

- [ ] **Step 3: Open a pull request**

Create a ready-for-review pull request against `main` summarizing dependency
closure, fail-closed export auditing, readiness checks, documentation status,
and the verification commands from Task 5.
