# Backlog Closure Design

## Purpose

Close the repository-maintenance and audit gaps found during the 2026-08-18
worktree review without pretending that external Microsoft or ThreatLocker
credentials are available. The result must leave a clean, testable branch and
make the boundary between completed software, deployment prerequisites, and
future product work unambiguous.

## Scope

This change has four independently verifiable parts:

1. Remove every currently reported frontend dependency advisory.
2. Require a successful server-side audit record before any browser CSV
   download starts.
3. Add a non-secret live-integration readiness command for operators and CI.
4. Reconcile historical implementation plans and current-status docs with the
   code that is actually present.

The previously merged application is already published on `origin/main`. The
obsolete `agent/preserve-imported-work` remote branch has been removed.

## Dependency remediation

Upgrade `react-router-dom` to the first current non-vulnerable release in the
7.18 line and refresh the lockfile so patched `nanoid` and `postcss` transitive
versions are selected. Do not use a forced, unconstrained audit rewrite.

Compatibility is proven through the existing route-driven application build,
the frontend tests, and a zero-finding `npm audit`. No application route API is
intentionally changed.

## Audited CSV export

### Server contract

Add authenticated `POST /api/v1/exports/generate`. It records the export before
the client receives permission to download. The request is:

```json
{
  "kind": "users",
  "filename": "users.csv",
  "rowCount": 42,
  "tenantId": "ten_1"
}
```

`kind` must be one of the eight export surfaces currently implemented:
`users`, `group-members`, `mailboxes`, `change-history`, `global-report`,
`share-detective`, `threatlocker-applications`, or `threatlocker-devices`.
Filenames must be plain `.csv` basenames of at most 128 characters, row counts
must be between zero and one million, and a supplied tenant ID must resolve to
an existing managed tenant.

The audit event uses action `exports.generate`, actor identity from the
authenticated server context, the request correlation ID, and a normalized
resource summary containing kind, scope, filename, and row count. Client input
never supplies the actor, result, timestamp, or correlation ID.

Malformed requests and unknown tenants fail through the standard error
envelope and do not create a success audit entry. Store failures fail closed:
the endpoint returns an error and does not authorize a download.

### Client behavior

The CSV utility becomes an audit-first orchestration boundary. Callers provide
the export metadata and the existing API client's audit function. The utility
awaits audit success, then invokes the existing local CSV generator. If audit
fails, no Blob or download link is created and the operator receives a concise
error message.

Every existing CSV button supplies its kind, filename, visible row count, and
tenant ID when tenant-scoped. Global reports and the global ThreatLocker views
omit tenant ID. The mock API records the same audit event shape so mock and live
modes stay behaviorally aligned.

This endpoint is synchronous because the rows are already materialized in the
browser and current exports are small. Server-generated expiring artifacts are
a separate future architecture change for exports that exceed the interactive
threshold.

## Live-integration readiness

Add `config.IntegrationReadiness()` and a `cmd/readiness` executable. The output
contains only integration names, modes, missing variable names, and certificate
file validation; it never includes secret values.

The checks classify:

- Microsoft Graph as `live` only when client ID, client secret, and tenant ID
  are all configured; otherwise it reports `sample` and the missing names.
- SharePoint as `live` only when the three central certificate settings are
  configured and both certificate files are readable; otherwise it reports
  `not_configured` or `invalid`.
- ThreatLocker as `live` only when instance, token, and parent organization ID
  are all configured; otherwise it reports `not_configured` and the missing
  names.

`go run ./cmd/readiness` prints JSON and exits zero when configuration can be
loaded. `--require=graph,sharepoint,threatlocker` makes selected non-live checks
exit nonzero, enabling deployment gates without making local sample mode fail.

## Documentation reconciliation

Historical Superpowers plans retain unchecked execution boxes even though most
of their code shipped. Add a dated status block to each affected plan that
identifies the implementing commit or current code evidence and names only the
remaining external validation, if any. Do not rewrite history by marking live
deployment checks complete when they are not rerun in this task.

README material must distinguish:

- operational prerequisites that require credentials/admin consent;
- implemented features with explicit provider limitations; and
- deferred roadmap investments such as Redis, sqlc, broader Exchange REST,
  additional hybrid reports, and an on-prem connector.

## Testing

- Backend route tests cover authenticated success, tenant-scoped audit content,
  validation rejection, unknown tenant rejection, and missing authentication.
- CSV utility tests prove audit happens before download and audit failure blocks
  the download.
- Readiness tests cover fully configured, missing, partial, and unreadable-file
  states without asserting secret values.
- Full backend vet/tests/build, frontend tests/build, both Compose config checks,
  and full `npm audit` must pass before publication.

## Non-goals

- No shared demo deployment or tenant administration.
- No credentials, certificates, tokens, or generated private keys are committed.
- No claim that Exchange Online, SharePoint Online, Entra, or ThreatLocker live
  acceptance passed without the corresponding external tenant access.
- No bundled implementation of deferred Redis, sqlc, Exchange REST, MFA reset,
  hybrid reporting, or on-prem connector projects; each changes architecture
  and requires its own design and acceptance environment.
