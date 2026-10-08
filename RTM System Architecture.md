# RTM System Architecture
## Services
- React Frontend
- Go API
- Go Worker
- PostgreSQL
- Microsoft security provider + Security Operations service
- Microsoft 365 Management Activity provider + detection engine
## Request Flow
Technician -> Frontend -> API -> PostgreSQL / Microsoft Graph
Long-running tasks:
Frontend -> API -> River Job -> Worker -> Microsoft 365 -> PostgreSQL -> Frontend.

Security monitoring reads use a separate bounded fan-out path:
Frontend -> API -> Security Operations service -> per-tenant Graph provider ->
Microsoft Defender XDR. The response overlays small RTM-local triage rows from
PostgreSQL; incident evidence itself is not persisted in Phase 1.

Durable audit monitoring uses the worker path:
River periodic job -> per-tenant Office 365 Management API token -> activity
subscriptions/content -> normalized immutable events -> versioned detections
-> PostgreSQL. The API merges those detections with on-demand Defender
incidents and local triage. Event-list responses expose normalized fields;
single-event investigation may return only a recursively redacted, 256 KiB-
capped raw projection. Rule evaluation resolves locked built-ins plus persisted
global/tenant overrides and custom rules before each ingestion run.
## Security Layers
- OIDC authentication
- RBAC
- Tenant isolation
- API authorization
- Audit logging
- Change approval
## Core Engines
- Tenant Manager
- Working Sets
- What If Engine
- Approval Engine
- Change Engine
- Revert Engine
- Reporting Engine
- Global Reporting Engine
- Security Operations Engine
- Audit Engine
