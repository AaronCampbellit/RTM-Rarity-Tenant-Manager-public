# RTM setup and implementation guide

Start with the [README](../README.md) for the product tour and local mock demo.
This guide distinguishes the frontend demonstration from authenticated sample
providers and persistent/live deployments.

## Development modes

| Mode | Data and authentication | Requirements |
|---|---|---|
| Frontend mock | Browser-memory fixtures; automatic sample administrator; reload resets data. | Node.js 24+ and npm. |
| Go API with sample providers | Real RTM login and permissions; memory store unless a database is set. | Go 1.26.8+ and the frontend toolchain. |
| Persistent stack | PostgreSQL, migrations, API, and a separate River worker; providers may still serve sample data. | Docker Compose or equivalent infrastructure, signing/encryption secrets, and frontend/API origins. |
| Live providers | Configured Microsoft or ThreatLocker accounts and permissions. | Backend infrastructure plus provider app credentials and consent. |

`VITE_USE_MOCK=false` routes the frontend to the API; it does not configure
Microsoft credentials or make sample tenants live.

## Standalone frontend

```bash
cd frontend
npm ci
VITE_USE_MOCK=true npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173`. Authentication is bypassed only in frontend mock
mode. Follow the [sample walkthrough](../README.md#try-it-locally) to inspect
hybrid identity labels, the What-If gate, and synthetic security storylines.

## Authenticated API without a database

In a separate shell, from the repository root:

```bash
cd backend
RTM_ENV=development RTM_DATABASE_URL= RTM_HTTP_ADDR=127.0.0.1:8080 make run
```

Leave external provider credentials unset to use sample data. An empty database
URL selects temporary memory state. In another shell from the repository root:

```bash
cd frontend
npm ci
VITE_USE_MOCK=false npm run dev -- --host 127.0.0.1
```

Vite proxies `/api` to `localhost:8080`. The local bootstrap account is
**`admin@rtm.local` / `ChangeMe!2026`**; choose a new password of at least
12 characters at first login. This is a committed development bootstrap, not a
credential for any deployed system. The API restricts the account to password
rotation until that step is complete. Do not expose development mode or reuse its
defaults in a deployment.

Tenant routes require bearer authentication. An unauthenticated
`curl /api/v1/tenants` request does not exercise the normal operator flow.

## Persistent stack configuration

The root Compose file supplies PostgreSQL, API, worker, and frontend services.
It needs an override for the required production signing/encryption keys and the
real-API frontend build. Configure the secrets outside version control and
create a local `compose.local.yml` override (Compose 2.24.4+ supports the
`!override` port lists):

```yaml
services:
  db:
    ports: !override
      - "127.0.0.1:5432:5432"
  api:
    ports: !override
      - "127.0.0.1:8080:8080"
    environment:
      RTM_JWT_SIGNING_KEY: "${RTM_JWT_SIGNING_KEY:?set a random high-entropy signing key}"
      RTM_FIELD_ENCRYPTION_KEY: "${RTM_FIELD_ENCRYPTION_KEY:?set a base64-encoded random 32-byte key}"
  worker:
    environment:
      RTM_JWT_SIGNING_KEY: "${RTM_JWT_SIGNING_KEY:?set a random high-entropy signing key}"
      RTM_FIELD_ENCRYPTION_KEY: "${RTM_FIELD_ENCRYPTION_KEY:?set a base64-encoded random 32-byte key}"
  web:
    ports: !override
      - "127.0.0.1:8088:80"
    build:
      args:
        VITE_USE_MOCK: "false"
```

Use identical signing and field-encryption secrets for API and worker. Supply
them through environment variables or an untracked local `.env`; keep the local
override and all secrets outside version control. Validate without printing
resolved secret values, then launch:

```bash
docker compose -f docker-compose.yml -f compose.local.yml config --quiet
docker compose -f docker-compose.yml -f compose.local.yml up --build
```

The override binds web `:8088`, API `:8080`, and PostgreSQL `:5432` to loopback.
The database still uses the root template's development credentials. This is a local topology example. Deployed
instances need private database networking, deployment-specific database
credentials, HTTPS, the correct CORS origin, and restricted service exposure.
`docker-compose.demo.yml` is a separate environment-specific template; review
origins, mounts, networking, and ports before adapting it to another host.

The worker requires `RTM_DATABASE_URL`; memory-mode writes execute inline in
the API. Goose migrations and River's schema support persistent state. sqlc is
configured, but the pgx store currently uses hand-written queries.

## Provider configuration and limits

### Microsoft Graph

Set `RTM_ENTRA_CLIENT_ID`, `RTM_ENTRA_CLIENT_SECRET`, and
`RTM_ENTRA_TENANT_ID` for the global app, or connect a tenant with its own
app credentials in the GUI. Without a global app, tenants with credentials use
live Graph while credential-less tenants use the sample provider. Client secrets
are write-only and never included in tenant API responses.

Permissions depend on the feature. Read-permission preflight does not prove all
write permissions or replace admin consent. Refer to the
[Graph integration guide](<../RTM Microsoft Graph Integration Guide.md>) and the
app's **Documentation** workspace for setup.

Inspect configuration without printing credentials:

```bash
cd backend
go run ./cmd/readiness
go run ./cmd/readiness --require=graph,sharepoint
```

The default check permits sample mode. Requiring an unavailable or invalid
integration exits nonzero.

### Exchange and SharePoint

Microsoft Graph cannot supply every administrative operation. Exchange-only
groups, dynamic distribution-list details, and litigation-hold fields need
Exchange Online. Send on Behalf uses the Exchange Online Admin API preview;
Full Access and Send As require controlled Exchange Online PowerShell. Concealed
Microsoft 365 report identities are explicitly not collected.

For central SharePoint administration, configure all three of
`RTM_SHAREPOINT_CLIENT_ID`, `RTM_SHAREPOINT_CERTIFICATE_PATH`, and
`RTM_SHAREPOINT_PRIVATE_KEY_PATH`. Keep the private key in a secret store,
mount it read-only, grant the required app permissions in each tenant, and supply
the tenant's SharePoint admin URL. See
[`scripts/setup-sharepoint-app.sh`](../scripts/setup-sharepoint-app.sh).

The optional Exchange role-setup flow uses temporary bootstrap app credentials
for one authorization attempt, with one-use state, PKCE, a ten-minute expiry,
and audit records. It requests no refresh token. Its Microsoft Graph beta
role-management endpoint requires revalidation when provider behavior changes.

Selected Exchange/SharePoint administration and MFA-reset operations remain off
the live write surface; unsupported operations return `NOT_IMPLEMENTED`.
A working sample dialog does not establish live provider support.

### Security Operations

Graph identity polling needs `AuditLog.Read.All`; Defender incidents need
`SecurityIncident.Read.All`. Microsoft 365 Management Activity backfill
separately needs **Office 365 Management APIs** application permission
`ActivityFeed.Read`, admin consent, and unified audit logging. A similarly
named Graph permission does not authorize that resource.

The feeds keep independent checkpoints, normalized evidence, provider IDs,
lifecycle timing, and explicit source coverage. The versioned pack spans direct
changes, thresholds, correlation, and confidence-labeled heuristics. Attack
storylines connect evidence with explanations and weak-evidence caveats.
Entra ID Protection risk ingestion remains planned.

Offline Investigations reuse analysis for encrypted uploaded evidence in separate
case workspaces. Case data stays separate from live events and incidents;
analysis is read-only. Monitoring and playbooks do not automatically execute
tenant remediation.

### ThreatLocker

Configure the MSP parent connection through Admin Settings or deployment
fallbacks `RTM_THREATLOCKER_INSTANCE`, `RTM_THREATLOCKER_TOKEN`, and
`RTM_THREATLOCKER_PARENT_ORG_ID`. This global workspace is independent of the
active Microsoft tenant. The backend has no sample ThreatLocker provider;
missing configuration returns `NOT_CONNECTED`, even though the standalone
frontend includes illustrative fixtures.

Supported portal writes use the reviewed-change workflow. Operations absent
from the public API, including selected lockdown, isolation, and tamper toggles,
return unsupported results. Application cleanup verifies portal outcomes and
addresses policies through their owning organization. See the
[ThreatLocker reference](<../RTM ThreatLocker Module.md>).

## Access and write semantics

Current roles permit authenticated operators to read all managed tenants.
Elevated permissions control administration, settings, and writes. This is not
a per-technician tenant-grant model; tenant-scoped provider credentials and
source-of-authority checks are separate concerns.

Supported writes require a current-state preview and approval validation. Jobs
record per-target results and can finish Completed, Partial, or Failed. Revert
requires a supported prior-state snapshot. Password reset, session revocation,
and other irreversible actions cannot be undone. Sensitive password outputs are
returned once rather than persisted.

App logs and the audit trail are separate. Correlation IDs and standard error
envelopes trace failures. Global reports are read-only and use bounded fan-out
with per-tenant failure handling.

## Checks and remaining work

From the repository root, in separate shells:

```bash
cd frontend
npm run build
npm test
```

```bash
cd backend
make vet test build
```

Provider clients are exercised against fake services. Local tests do not replace
live tenant permission/behavior verification. Dockerized pgx integration coverage,
shared multi-instance rate limiting, sqlc query generation, richer hybrid
reports, and an on-prem connector remain deferred.

See the [API specification](<../RTM API Specification.md>),
[security specification](<../RTM Security Specification.md>),
[database design](<../RTM Database Design.md>), and
[architecture decisions](<../RTM Architecture Decision Records.md>).
Some older references describe earlier access models or planned features;
consult the implementation and current role behavior before deploying.
