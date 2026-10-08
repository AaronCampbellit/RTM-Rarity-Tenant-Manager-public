# RTM Security Specification
## Purpose
Define the security model for RTM - Rarity Tenant Manager.
## Security Principles
- Tenant isolation is mandatory.
- Least privilege by default.
- Microsoft tokens never reach the frontend.
- Every sensitive action is audited.
- Every write action requires What If preview and approval. Preview approvals are server-issued, actor-bound, single-use tokens that expire after five minutes; direct or replayed writes are rejected.
- Global reporting is read-only.
- Microsoft security evidence is read on demand, minimized at the provider
  boundary, and never exposed through a raw Graph proxy.
- Secrets must not be stored in plain text. Tenant integration secrets are encrypted at rest with `RTM_FIELD_ENCRYPTION_KEY`.
## Authentication
RTM v1 uses local operator accounts; Microsoft Entra ID / OIDC remains the
planned external identity provider.
Requirements:
- MFA required.
- Short-lived access tokens.
- Refresh token rotation where supported.
- Secure session handling. Admins select a bounded access-token lifetime of
  30 minutes, 1 hour, 4 hours, 8 hours, 12 hours, or 24 hours; 30 minutes is
  the default and unsupported values fail closed to that default.
- Logout invalidates local session.
- Local passwords are stored only as adaptive hashes and must be at least 12
  characters. A password change or administrator reset increments a persisted
  credential version and revokes refresh state, so every older access and
  refresh token fails immediately. Existing tokens remain valid across the
  schema migration until that account's credential changes.
- Administrators may reset another local RTM account only with the
  `technicians.manage` capability. Reset issues a random one-time password,
  forces rotation at the next sign-in, is rate limited, and is audited without
  recording the temporary password. Self-service changes require the current
  password; administrator self-reset is refused.
## Authorization
Layered authorization model:
1. User is authenticated.
2. User has active RTM account.
3. User has role permission.
4. User has access to tenant.
5. User has permission for requested action.
6. Action satisfies approval and What If requirements.
## Roles
- Global Admin
- MSP Admin
- Engineer
- Approver
- Read-Only
- Auditor
- Global Reporting Admin
## Tenant Isolation
Every tenant-scoped table must include tenant_id.
Backend must verify tenant access on every tenant-scoped request.
No frontend value should be trusted for tenant access decisions.
Global reports must keep tenant results separated and clearly labeled.
## Token Handling
- Store Microsoft Graph tokens server-side only.
- Never log tokens.
- Never return Microsoft tokens to the frontend.
- Encrypt sensitive token material.
- Prefer secrets manager for production.
- Track token usage metadata without storing token values.
- Exchange RBAC bootstrap accepts a temporary confidential client's ID and
  secret only through the admin GUI for one attempt; there is no deployment
  bootstrap credential. The secret is kept only in process memory and is
  cleared after callback or ten-minute expiry. Before redirect, RTM requires an
  actor-bound, five-minute, single-use What-If approval for exactly the built-in
  Recipient Management role at tenant scope. The authorization code flow uses
  PKCE plus a random ten-minute, one-use state bound to the RTM actor, managed
  tenant, Microsoft directory, and current runtime app. It requests delegated
  `RoleManagement.ReadWrite.Exchange` without `offline_access`; the access token
  and authorization code are never logged, returned to the UI, or persisted.
  Microsoft returns the code with `response_mode=form_post`, keeping it out of
  callback URLs, browser history, and ordinary proxy query logs.
  Before assignment, RTM independently obtains a runtime app token and verifies
  its `tid`, client ID, and `oid`. Only an exact enabled built-in role match is
  accepted, an existing assignment is a no-op, and every start/completion is
  audited. The Graph beta dependency is fail-closed.
## Secrets Management
Prototype:
- Environment variables or encrypted database fields.
Production:
- Azure Key Vault, HashiCorp Vault, 1Password Secrets Automation, or equivalent.
## API Security
- HTTPS only.
- Strict CORS.
- CSRF protection if cookies are used.
- Request validation.
- Rate limiting.
- Correlation IDs.
- Structured logging.
- No raw Graph proxy endpoint exposed to frontend.
- No unredacted audit-provider proxy. Event detail resolves one retained event,
  recursively redacts token/secret/password/cookie/authorization/assertion/
  session-key fields (including sensitive name/value parameter pairs), caps the
  response at 256 KiB, and audits every view.
## Audit Events
Audit:
- Login
- Logout
- Failed login
- Tenant viewed
- Report generated
- Export downloaded
- What If preview generated
- Change approved
- Change executed
- Revert preview generated
- Revert executed
- Permission denied
- Token failure
- Global report executed
- Security Operations snapshot viewed
- Security incident evidence viewed
- Security incident triage changed
- Security incident bulk triage changed (aggregate count and Success, Partial,
  or Failed result; no provider evidence in the audit resource label)
- Microsoft 365 audit ingestion completed or partially failed (aggregate only)
- Security event search and redacted raw-event detail viewed
- Detection rule previewed, created, updated, or restored
- Detection-rule condition choices viewed (normalized metadata only; no raw
  evidence values)
- Admin setting changed
## Write Action Guardrail
No tenant-changing action can execute unless:
1. User is authenticated.
2. User has tenant access.
3. User has action permission.
4. What If preview was generated.
5. Approval was confirmed.
6. Audit record is created.

RTM-local Security Operations assignment/status is workflow metadata, not a
tenant or Microsoft Defender mutation. It is audited as
`security.incident.triage` (or `security.incident.bulk_triage` for a bounded
batch) but intentionally does not pass through the M365
What-If gate. Any future Defender write-back, containment, session revocation,
or tenant remediation remains a write and must use the normal permission,
preview, approval, change, and revert rules.

Management Activity content URLs are provider-controlled input. RTM accepts
only HTTPS Microsoft management hosts (or the exact configured test origin),
preventing those URLs from becoming an SSRF primitive. Raw audit JSON is
retained only in PostgreSQL and never written to app logs. Only a recursively
redacted, size-bounded projection may leave the authenticated event-detail
endpoint; list/search responses remain normalized.
Ingestion is app-only/read-only and therefore does not use What-If.
Country, IP, user-agent, and session identifiers used by anomaly rules come
only from normalized Microsoft audit records. RTM does not claim a stolen
session or impossible-travel verdict: these are confidence-labeled
investigation leads, and absent evidence suppresses the rule rather than being
guessed.

Detection-rule reads follow the v1 all-tenants operator model. Mutation is
Admin-only and never writes Microsoft 365, but enabled configuration changes
still require an exact short-lived preview approval. Built-in matching logic is
immutable at runtime; the database stores only allowed overrides. Optimistic
revisions prevent stale-editor overwrites and retain every state for restore.

## Revert Security
- Reverts require permission.
- Reverts require What If Revert preview.
- Reverts must be logged as new changes.
- Revert must never silently overwrite a newer conflicting state.
## Export Security
- Exports require explicit permission.
- All exports are audited.
- Export files should expire.
- Exports should include tenant, technician, and timestamp metadata.
## Future Security Enhancements
- Conditional Access integration
- IP allowlists
- Device compliance requirements
- Just-in-time approval elevation
- Security review dashboard
- SIEM forwarding
## Permission Model Decision
RTM v1 uses a simplified permission model.
### User Types
- Admin
- Technician
### Admin
Admins have complete control over RTM:
- Manage tenants
- Manage RTM users
- Manage technician permissions
- View audit logs
- Run reports
- Run global reports
- Export data
- Execute changes
- Revert changes
- Manage system settings
### Technician
Technicians receive read access across all managed tenants plus only the
elevated capabilities assigned to the persisted Technician role. Admins edit
that policy in Admin Settings. v1 capabilities cover tenant management,
technician management, role management, application settings, tenant write
execution, detection-rule management, and ThreatLocker management. The Admin
role description is editable but all Admin capabilities are locked as the
platform recovery floor.
### Enforcement Rules
- Backend authorization is required on every protected route.
- Persisted role permissions are resolved on every authenticated request so a
  grant or revocation does not wait for the bearer token to expire.
- Tenant access must be verified server-side.
- UI visibility is not a security boundary.
- Jobs must validate permission before execution.
- Exports must validate permission before generation.
- Changes and reverts must validate permission before execution.
## Logging and Audit Decision
RTM separates application logs from audit logs.
### Application Logs
Purpose:
- Debugging
- Performance diagnostics
- Exceptions
- River job troubleshooting
- Microsoft API diagnostics
- Database errors
Application logs should not contain tokens, secrets, or unnecessary sensitive client data.
Security connector logs may contain tenant identity, Microsoft HTTP status,
and correlation metadata, but not raw incident/evidence bodies.
### Audit Engine
Purpose:
- Security accountability
- Client review
- Change tracking
- Compliance support
- Operational history
Audit events should include:
- Login/logout
- Failed login
- Tenant access
- Report generation
- Global report generation
- Working Set creation/use/deletion
- What If preview
- Change execution
- Revert execution
- Export generation/download
- Permission changes
- Technician creation/disablement
- Local account password reset (never the password value)
- Tenant add/remove
- Microsoft connection changes
- Sync started/completed
- Security Operations snapshot/detail views and local triage
- Job failed/cancelled
- Settings changes
Audit records should support searchable history and timeline views.
