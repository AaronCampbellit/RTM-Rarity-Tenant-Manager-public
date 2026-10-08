# RTM — Backend

Go API + worker on the finalized stack (chi · pgx · Goose · River). Runs
against Postgres when `RTM_DATABASE_URL` is set, otherwise from an in-memory
store so it works offline. The Microsoft layer is a `graph.Provider` with
three modes: live client-credentials Graph for everything when the global
`RTM_ENTRA_*` app is configured, **hybrid** otherwise (tenants connected via
the GUI with their own app credentials read live, the rest serve sample
data), and pure sample when neither exists.

```bash
make run          # API on :8080 (in-memory, no database)
make run-worker   # River worker (requires RTM_DATABASE_URL)
make vet test     # static analysis + tests
make build        # bin/api, bin/worker
```

Inspect optional live-provider configuration without printing secrets:

```bash
make readiness
go run ./cmd/readiness --require=graph,sharepoint,threatlocker
```

The default inspection exits successfully for local sample mode. Requiring an
integration makes a non-live or invalid configuration exit with status 2.

## Layout (Coding Standards → Repository Layout)

```
backend/
├── cmd/
│   ├── api/         HTTP server entrypoint (graceful shutdown)
│   └── worker/      River worker: consumes write jobs, updates status, audits
├── internal/
│   ├── auth/        RTM JWTs (access + rotating refresh), bcrypt, RBAC middleware
│   ├── config/      env-based system config, validated at startup (ADR-017)
│   ├── graph/       Microsoft provider: sample impl + live client-credentials client
│   ├── httpx/       error envelope, correlation IDs, logging/recover/CORS, rate limit
│   ├── jobs/        River enqueuer + worker (no-op enqueuer without Postgres)
│   ├── model/       /api/v1 entity types shared by store, graph, and handlers
│   ├── reports/     cross-tenant global-report fan-out over the managed tenants
│   ├── seed/        canonical demo dataset (mem store, PG seeder, sample Graph)
│   ├── server/      route table (/api/v1) + handlers
│   └── store/       Store interface: in-memory + Postgres (pgx) implementations
├── migrations/      Goose schema (RTM Database Design), embedded + auto-applied
├── sqlc.yaml        typed query generation config (queries dir not yet populated)
└── Dockerfile       distroless api + worker images
```

## What the backend enforces

- **Standard error envelope** `{ error: { code, message, correlation_id } }` with
  the full code set from the API spec.
- **Correlation IDs** on every request + response (`X-Correlation-ID`), flowing
  into structured logs.
- **Versioned routes** under `/api/v1`, resource + workflow-action style; async
  actions return a queued **job** processed by the River worker.
- **Write engine covers directory actions** — group membership add/remove,
  sign-in block/unblock, license assign/remove, password reset, and
  compromised-user containment (password + MFA registrations + sessions) —
  each executed **per user** with partial-failure tolerance (job outcome
  Completed/Partial/Failed) behind What-If preview and revert. Live writes need
  Graph app permissions are surfaced exactly in Permission Preflight. Password
  outputs are returned once from synchronous tracked jobs and never persisted.
- **Auth**: short-lived access JWTs + rotating refresh tokens (reuse of a
  rotated token is rejected); login/refresh are rate limited per IP. The
  seeded default admin (`admin@rtm.local`) carries a must-change flag: every
  route except `/auth/me` and `/auth/change-password` answers
  `PASSWORD_CHANGE_REQUIRED` until the password rotates (min 12 chars).
  Password changes and admin-issued one-time resets increment a stored
  credential version and delete refresh state, immediately rejecting all
  previously issued access and refresh tokens. Admin resets require
  `technicians.manage`, are rate limited, force rotation, and are audited
  without storing the temporary password.
- **Tenant lifecycle**: `POST /tenants` connects a managed tenant (admin-only;
  optional per-tenant Entra app credentials, stored write-only and never
  echoed; connection tested on create), `DELETE /tenants/{id}` fully removes
  one (credentials deleted, grants revoked, audited).
- **Layered authorization**: bearer token → per-tenant access (admins bypass,
  technicians need explicit grants; denials audited) → admin gate on writes.
  Tenant access is verified server-side on every tenant-scoped route — UI
  visibility is never a security boundary.
- **Global reports are read-only** and fan out across all managed tenants
  (`internal/reports`): each tenant is read through the Graph provider — with
  its own app-only token in live mode — and per-tenant failures are skipped and
  logged so one broken tenant doesn't kill the report.
- **Per-tenant Graph authority**: in live mode the client resolves each RTM
  tenant id to that tenant's Entra authority (Microsoft tenant id, falling back
  to the verified domain) and caches one token per authority.
- **No secrets in logs**; app logs are separate from the (DB-backed) audit trail.

## Tests

`make test` (or `go test ./...`) covers:

- `internal/httpx` — envelope shape, correlation ID propagation, panic
  recovery, CORS preflight, per-IP rate limiting and window reset.
- `internal/auth` — login verification, refresh rotation + reuse rejection,
  middleware 401 paths (missing/expired/forged/refresh-as-access tokens),
  tenant-access grants with audited denials, admin gate.
- `internal/store` — in-memory store behaviors, grants, refresh-token
  lifecycle, defensive copies.
- `internal/graph` — the live client against a fake token + Graph server
  (token caching per authority, expiry, per-tenant authority resolution,
  entity mapping, graceful MFA-report degradation) plus the sample provider.
- `internal/reports` — fan-out ordering, per-report filters, partial-failure
  tolerance, sample-mode delegation.
- `internal/server` — end-to-end over the real router: login/refresh flows,
  tenant isolation (200 vs 403 + audit), write gates, job enqueue (202 + job
  ref), working-set validation, rate limiting, correlation echo.

## Operational prerequisites

- Set `RTM_ENTRA_*`, or store tenant-specific app credentials, to use live
  Microsoft Graph; fake Microsoft servers cover the token flow and mappings in
  local tests.
- Configure and consent the central SharePoint certificate app, then add each
  tenant's SharePoint admin URL. `make readiness` inspects configuration
  without printing credential values.

## Explicit provider limitations

- Exchange/SharePoint-admin-only fields and writes that Microsoft Graph cannot
  supply return explicit unsupported errors in live mode. This includes
  mailbox type/archive/hold, selected mailbox and site administration, and
  MFA-method reset.
- ThreatLocker operations that are absent from its public API also remain
  explicit unsupported results.

## Deferred architecture

- Dockerized integration tests for the hand-written pgx Postgres store.
- sqlc-generated queries over the Goose schema.
- Shared Redis rate limiting for multi-instance deployments.
- Additional hybrid reports and the future on-prem connector.
