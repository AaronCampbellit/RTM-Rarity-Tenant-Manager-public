# RTM Architecture Decision Records
## ADR-001: Language
- Backend: Go
- Reason: Performance, simplicity, concurrency, strong Graph support, single binary deployment.
## ADR-002: Frontend
- React + Vite + TypeScript
- Reason: Modern, maintainable, fast development.
## ADR-003: Database
- PostgreSQL
- Reason: Mature relational database, JSON support, River compatibility.
## ADR-004: Background Jobs
- River
- Reason: PostgreSQL-backed queue, fewer moving parts than Redis.
## ADR-005: Deployment
- Docker containers.
## ADR-006: Authentication
- Microsoft Entra ID (OIDC) for technician authentication.
- JWT bearer tokens.
- RBAC.
- Hybrid Microsoft tenant connection model.
- Default: Single multi-tenant Entra application.
- Optional: Dedicated per-tenant app registrations for customers requiring stricter isolation or compliance.
- Backend abstracts both models behind the same connection interface.
## ADR-007: Microsoft Integration
- Microsoft Graph first, Exchange Online where required, SharePoint Graph/REST where appropriate.
## ADR-008: Security
- Tenant isolation.
- Audit-first.
- What If previews required before writes.
- No approval workflow.
- Revert support.
## ADR-011: Platform Future, Microsoft First
- RTM should be architected so it can eventually become a broader MSP operations platform.
- The current implementation focus remains the Microsoft 365 module suite.
- Microsoft 365 is the first and primary module set for v1.
- Future non-Microsoft connectors should not drive current MVP scope.
- Core architecture should still avoid Microsoft-only assumptions where reasonable.
- Future expansion may include a connector framework, module framework, and common object model for users, devices, tenants, assets, permissions, and operations.
- Current build priority: Entra ID, Microsoft Graph, Exchange Online, SharePoint Online, licensing, reporting, Working Sets, What If previews, change history, and revert functionality.
## ADR-012: API Philosophy
- RTM will use REST + workflow action endpoints.
- Resource-style endpoints expose objects such as users, groups, tenants, jobs, reports, working sets, licenses, and SharePoint sites.
- Action-style endpoints execute workflows such as sync refresh, report generation, What If preview, change execution, revert, and export generation.
- Long-running or potentially long-running operations should run asynchronously through River jobs.
- The API should return a job ID for async workflows instead of blocking the request.
- API design should remain versioned under `/api/v1`.
- GraphQL is not part of the initial architecture.
## ADR-013: Background Job Philosophy
- RTM will use River as the background job system backed by PostgreSQL.
- Small read operations may return directly from the API.
- Large reads, reports, global reports, exports, sync refreshes, What If previews, write operations, and reverts should run as River jobs when they may take noticeable time or require reliable tracking.
- Jobs should track status, progress, tenant, creator, type, result reference, error details, correlation ID, retry count, and timestamps.
- Standard job statuses: queued, running, succeeded, failed, cancelled, partial_success.
- Read-only jobs may be retried automatically when safe.
- Write jobs must be idempotent and state-aware before retrying.
- Write jobs must verify current Microsoft 365 state before making changes.
- Revert jobs must verify current state and avoid silently overwriting newer conflicting changes.
## ADR-014: Error Philosophy
- RTM should fail safely, explain clearly, and log deeply.
- Technician-facing messages should be separated from developer diagnostic details.
- Every error response should include a correlation ID.
- Secrets, tokens, and sensitive internal implementation details must never be exposed to users.
- Microsoft API errors should be translated into technician-friendly language while preserving raw diagnostics in logs.
- Partial Success is a first-class operation result, not a generic failure.
- Errors should clearly state what failed, whether anything changed, and what the technician should do next.
- Workflows should finish in one of these states: Success, Partial Success, Failed, or Cancelled.
- RTM should provide an Operation Summary page after workflows showing tenant, operation, duration, processed objects, successes, warnings, failures, artifacts, change history, export option, and revert option when available.
## ADR-015: Permission Philosophy
- RTM will keep the permission model simple for v1.
- There are two primary user types: Admin and Technician.
- Admins have complete control over RTM, including tenants, users, technician permissions, settings, reports, exports, changes, and audit visibility.
- Technicians do not receive broad role-based access by default.
- Technician access is assigned by admins through explicit permissions.
- Technician permissions should be assignable by tenant, module, workflow/action, and export capability.
- Backend permission checks are mandatory for every tenant-scoped request, workflow, job, export, and change.
- The database should still support flexible/custom permissions internally so the model can grow later without redesign.
- Future role templates may be added, but v1 should avoid unnecessary role complexity.
## ADR-016: Logging and Audit Philosophy
- RTM will separate application logging from audit logging.
- Application logs are for troubleshooting, diagnostics, performance, Microsoft API failures, database issues, and River job issues.
- Audit logs are for security, accountability, client review, and operational history.
- Audit logging is a core RTM engine, not a secondary feature.
- Nothing important should happen in RTM without an audit trail.
- Audit records should answer: who did what, when, where, to what object, in which tenant, what changed, and what happened.
- Audit logs should be searchable and support timeline-style views.
- Audit retention should be configurable and longer than application log retention.
- Application logs should avoid sensitive data and should never include tokens or secrets.
## ADR-017: Deployment and Configuration Philosophy
- RTM is designed for self-hosted Linux deployments using Docker Compose.
- Docker Compose is the primary and foreseeable deployment model.
- The architecture should remain portable but should not require Kubernetes or managed cloud services.
- Configuration follows a three-layer model:
  1. System Configuration (environment variables)
  2. RTM Configuration (database-backed application settings)
  3. Tenant Configuration (per-tenant settings and preferences)
- Sensitive values such as secrets, signing keys, and connection credentials should remain outside normal application configuration and be sourced from environment variables or a future secrets manager.
- All configuration should be validated during application startup with clear error reporting.
## ADR-018: Core Development Stack
- Backend: Go
- HTTP Router: chi
- Database: PostgreSQL
- Database Driver: pgx
- SQL Code Generation: sqlc
- Database Migrations: Goose
- Background Jobs: River
- Frontend: React + Vite + TypeScript
- UI: Tailwind CSS + shadcn/ui
- Deployment: Self-hosted Docker Compose on Linux
- Reverse Proxy: HTTPS reverse proxy
- Configuration: Layered configuration (System, RTM, Tenant)
## ADR-019: Definition of Done
Every feature must include:
- Backend implementation
- Frontend implementation
- API documentation
- Permission checks
- Audit logging
- Unit tests
- Integration tests where appropriate
- What If support for write operations
- Revert support where applicable
- Documentation updates
