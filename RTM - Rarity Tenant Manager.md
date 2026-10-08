# RTM - Rarity Tenant Manager
## Vision
A secure, enterprise-grade MSP web platform for managing Microsoft 365 tenants using Microsoft Graph, Exchange Online, and SharePoint APIs. The platform prioritizes security, tenant isolation, auditing, approvals, and scalable automation over PowerShell wrappers.
## Technology Stack
- React + Vite + TypeScript
- Go API
- Go Worker
- PostgreSQL
- River job queue
- Docker
## Core Architecture
- Frontend communicates only with Go API.
- Go API authenticates users, validates permissions, creates jobs, and communicates with Microsoft APIs.
- Go Worker processes background jobs from River.
- PostgreSQL stores application data, audit logs, change history, working sets, cached reports, and River jobs.
## Security Decisions
- Complete tenant isolation.
- Tenant ID required throughout the data model.
- Entra ID/OIDC authentication.
- Short-lived bearer tokens.
- RBAC.
- App-only Microsoft Graph tokens remain server-side.
- All write actions require What If preview and approval.
- Full audit logging.
## Core Features
- Tenant management
- User, Group, Licensing, Exchange, and SharePoint tools
- Working Sets
- What If preview engine
- Change approval engine
- Change history
- Revert engine
- Global read-only reporting
## Global Reporting
Authorized admins may run read-only reports across all tenants with tenant-separated results. No write operations are permitted through global reporting.
## Initial MVP
1. Tenant connections
2. User inventory
3. Group inventory
4. Group members
5. Working Sets
6. What If preview
7. Group membership changes
8. Change history
9. Revert
10. Global user reporting
## Long-Term Direction
Build a Microsoft 365 operations platform focused on safe automation, reporting, auditing, and enterprise-grade change management for MSP environments.
## Future Platform Direction
RTM should be designed with long-term platform extensibility in mind, but the active build scope remains focused on Microsoft 365.
Long-term, RTM may evolve into a broader MSP operations platform where Microsoft 365 is the first module suite rather than the only capability.
Potential future expansion areas:
- Intune
- Microsoft Defender
- Purview
- Teams Administration
- Azure Resources
- UniFi
- Datto RMM / Kaseya
- Halo PSA
- Hudu
- ThreatLocker
- SentinelOne
- Custom MSP tools
Future concepts to preserve architecturally:
- Connector framework
- Module framework
- Shared authentication and secrets management
- Shared job engine
- Shared audit engine
- Common object model for users, devices, tenants, permissions, and assets
Current priority:
- Build the Microsoft 365 module suite first.
- Focus on Entra ID, Microsoft Graph, Exchange Online, SharePoint Online, licensing, reporting, Working Sets, What If previews, change history, and revert functionality before expanding beyond Microsoft.
