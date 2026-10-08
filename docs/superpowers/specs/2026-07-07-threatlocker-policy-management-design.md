# ThreatLocker Policy Management Design

## Goal

Move ThreatLocker policies from read-only inventory to RTM-managed policy
operations: per-org edit first, plus global/template workflows for promoting,
merging, and pushing policies across connected organizations.

## Scope

- Add policy detail reads from ThreatLocker `Policy/PolicyGetById`.
- Add per-org policy editing for a conservative editable field set:
  `name`, `description`, `comments`, `isEnabled`, `policyActionId`, `monitorMode`,
  `orderBy`, `neverExpires`, `endDate`, `logAction`, `notifyOnMatch`,
  `notifyOnRequest`, `killRunningProcesses`, `applicationIdList`, and
  `applicationSelection`.
- Add RTM API affordances for template/global operations:
  promote to template, merge into template, deploy template to selected/all
  connected orgs.
- Keep global/template persistence in RTM data structures in this first slice;
  live ThreatLocker global promotion/deploy endpoints are not confirmed by the
  public Swagger, so live provider calls fail clearly with `NOT_IMPLEMENTED`
  unless an implemented endpoint is available.
- Every write path remains What-If/job/audit aligned where it mutates
  ThreatLocker. No raw UI save that bypasses RTM guardrails.

## Architecture

ThreatLocker provider gains policy detail/update/create methods. Server adds
tenant-scoped REST endpoints under `/tenants/{tenantId}/threatlocker/policies`
for detail and edit, plus policy-template endpoints for cross-org workflows.
Frontend converts the Policies tab into an actionable table with edit and
template actions.

Per-org edits use `Policy/PolicyUpdateById` with a detail payload loaded by
`PolicyGetById`, patched by RTM, then posted back. New template pushes use
`Policy/PolicyInsert` for target orgs where possible.

## Error Handling

- ThreatLocker 401/403/429/errors continue through the existing
  `THREATLOCKER_FAILED` envelope.
- Unknown live policy operations return `NOT_IMPLEMENTED` with plain-English
  text, not `INTERNAL_ERROR`.
- Template deploys are partial-failure tolerant per org.

## Testing

- Fake ThreatLocker portal tests for policy detail, update, insert, and
  unsupported deploy.
- Server tests for admin-only policy edit/template endpoints and error mapping.
- Frontend build must pass after UI changes.
