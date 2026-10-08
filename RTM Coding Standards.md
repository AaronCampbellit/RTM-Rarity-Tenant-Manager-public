# RTM Coding Standards
## Purpose
Define coding patterns and conventions for RTM - Rarity Tenant Manager.
## General Principles
- Security-first implementation.
- Backend-enforced permissions.
- Tenant isolation on every tenant-scoped operation.
- Clear separation between API, worker, data access, and Microsoft integration layers.
- Explicit errors instead of silent failures.
- Audit sensitive actions.
- Prefer boring, maintainable code over clever abstractions.
## Repository Layout
Suggested structure:
```text
/backend
  /cmd
    /api
    /worker
  /internal
    /auth
    /config
    /db
    /graph
    /exchange
    /sharepoint
    /jobs
    /audit
    /tenants
    /users
    /groups
    /workingsets
    /changes
    /reports
  /migrations
/frontend
  /src
    /api
    /auth
    /components
    /features
    /layouts
    /routes
    /types
    /utils
/docker
/docs
```
## Go Standards
- Use context.Context for API and job operations.
- Pass tenant context explicitly.
- Do not trust tenant_id from frontend without authorization checks.
- Keep Microsoft API clients server-side only.
- Use structured logging.
- Return consistent error types.
- Capture correlation IDs.
- Use database transactions for change execution and audit records where appropriate.
## Go Layering
Recommended backend layers:
- HTTP handlers
- Service layer
- Authorization layer
- Job enqueue layer
- Worker job handlers
- Repository/data layer
- Microsoft Graph integration layer
Handlers should not directly call Microsoft APIs for long-running work. They should validate, authorize, and enqueue jobs.
## React Standards
- Use TypeScript everywhere.
- Keep API models typed.
- Separate page components from reusable UI components.
- Centralize API client logic.
- Never store Microsoft tokens in frontend state.
- Always display current tenant context.
- Use clear loading, empty, error, and success states.
## API Standards
- Version APIs under /api/v1.
- Use RESTful route names.
- Use consistent pagination.
- Use consistent filter/query patterns.
- Use consistent error response shape.
- Require authentication on all app routes except health and auth callbacks.
- Log denied authorization attempts.
## Error Response Shape
Example:
```json
{
  "error": {
    "code": "TENANT_ACCESS_DENIED",
    "message": "You do not have access to this tenant.",
    "correlation_id": "..."
  }
}
```
## Database Standards
- Use UUID primary keys.
- Include created_at and updated_at.
- Include tenant_id on tenant-scoped tables.
- Add indexes for tenant_id and common filters.
- Use migrations.
- Avoid storing unnecessary long-term tenant data.
- Encrypt sensitive fields.
## Job Standards
- Use River for background jobs.
- Jobs must be idempotent where possible.
- Jobs must store status and errors.
- Jobs must include tenant_id where tenant-scoped.
- Jobs must audit sensitive activity.
- Jobs must capture Microsoft request IDs where available.
## Audit Standards
Audit records should include:
- User
- Tenant
- Action
- Target
- Result
- Timestamp
- Correlation ID
- Before/after state where applicable
## Testing Standards
Minimum tests:
- Tenant access checks
- RBAC checks
- What If calculations
- Revert calculations
- API validation
- Job execution logic
- Database repository behavior
## Naming Standards
Use consistent names:
- Working Set
- What If Preview
- Change Record
- Revert Job
- Global Report
- Tenant Connector
## Documentation Standards
Every major module should include:
- Purpose
- Security considerations
- Required Microsoft permissions
- Expected inputs/outputs
- Error cases
## Production Rules
Before production use:
- No hardcoded secrets.
- HTTPS required.
- Audit logging enabled.
- Backups configured.
- Tenant isolation tests passing.
- Role permission tests passing.
- Microsoft permissions documented.
- Revert limitations documented.
## River Job Standards
- Use River for background jobs.
- Small reads may be handled synchronously.
- Reports, global reports, exports, sync refreshes, What If previews, writes, and reverts should be implemented as jobs when they may take noticeable time.
- Jobs must include tenant_id when tenant-scoped.
- Jobs must include created_by when user-triggered.
- Jobs must support correlation IDs.
- Jobs should store result references instead of large result blobs when practical.
- Jobs should report progress for multi-step operations.
- Jobs should support cancellation where technically safe.
- Read-only jobs may retry automatically with backoff.
- Write jobs must be idempotent and state-aware.
- Write jobs must check current Microsoft 365 state before executing.
- Revert jobs must detect conflicts before applying changes.
- Jobs must capture Microsoft request IDs when available.
- Jobs must write audit records for sensitive operations.
## Finalized Engineering Stack
### Backend
- Go
- chi
- pgx
- sqlc
- Goose
- River
- PostgreSQL
### Frontend
- React
- Vite
- TypeScript
- Tailwind CSS
- shadcn/ui
### Development Standards
- SQL-first development
- No ORM in v1
- Goose manages all schema changes
- sqlc generates typed data access
- Feature-based frontend organization
- Reusable UI components
- Shared Object Card and table components
- Environment-driven configuration
