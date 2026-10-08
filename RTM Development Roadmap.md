# RTM Development Roadmap
## Purpose
Define the build order for RTM - Rarity Tenant Manager.
## Build Principle
Build the platform engine first, then add tools.
Do not start by building every Microsoft 365 tool. Start by proving the secure tenant workflow, job workflow, What If engine, change history, and revert model.
## MVP Scope
- Tenant connections
- Technician login
- Tenant access (RBAC)
- Pull users
- Pull groups
- Pull group members
- Create Working Sets
- Add Working Set users to another group
- Run What If preview
- Execute change
- Change history
- Revert group membership change
- Global read-only user report

## Post-v1 Security Operations

- Phase 1 (built): cross-tenant Defender XDR incident queue, evidence detail,
  connector/tenant coverage honesty, permission preflight, and audited
  RTM-local owner/status triage.
- Phase 2 (built): durable Microsoft 365 Management Activity ingestion with
  subscriptions, checkpoints, overlap/replay dedupe, normalized/raw event
  storage, 180-day retention, connector health, and a versioned detection pack
  spanning direct administrative changes, volume thresholds, cross-event and
  cross-tenant correlation, login sequences, and confidence-labeled anomaly
  heuristics.
- Phase 3: Entra risk correlation, MITRE mapping, tenant-specific rule/
  threshold controls, analyst suppression, and false-positive feedback.
- Phase 4: notification routing, analyst SLAs/comments, evidence export, and
  optional approved Microsoft write-back/remediation.

See `RTM Security Operations Module.md` for the architecture and safety
boundaries.
