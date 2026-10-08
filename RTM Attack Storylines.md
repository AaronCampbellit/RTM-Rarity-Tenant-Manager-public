# RTM Attack Storylines

## Purpose

Attack Storylines are RTM's explainable correlation layer above raw Microsoft
365 evidence and individual detections:

`raw events -> detections -> entity and sequence correlation -> storyline -> analyst workflow`

The feature is deliberately deterministic. Every score, stage, and relationship
must be reproducible from retained evidence; RTM never presents an opaque model
judgement as proof of compromise.

## Persisted evidence model

- Every native detection retains all supporting audit-event IDs, not only an
  anchor event.
- Detection-to-event and detection-to-normalized-entity relationships are
  stored explicitly and indexed.
- A storyline has a stable correlation key, pack, entities, tenants, stages,
  detections, events, score, confidence, explanatory reasons, weak evidence,
  recommended actions, owner, and workflow status.
- Replaying an ingestion window is idempotent. Late evidence updates the same
  storyline and preserves analyst ownership and status.
- Detection history is time-bounded by the correlation lookback and no longer
  silently truncated by a global 500-row limit.

## Correlation packs

### Account takeover / business email compromise

Correlates independent sign-in compromise signals with persistence or abuse,
including failed attempts followed by success, unusual/impossible travel,
session anomalies, inbox rules, external forwarding, mailbox delegation, and
mail-flow changes.

### Privilege escalation and persistence

Connects application creation, credentials and consent grants, directory role
changes, privileged group changes, guest escalation, and related identity
changes for the same normalized principal/resource.

### Data theft

Connects suspicious sign-in context to bulk SharePoint/OneDrive access,
download, sharing, deletion, or permission changes involving the same account
or resource.

### Defense evasion

Connects audit configuration changes, evidence searches, repeated
administrative failures, connector or transport changes, and other activity
that reduces monitoring or control visibility.

### MSP administrator compromise

Connects independent suspicious administrative actions performed by the same
normalized administrator across multiple managed tenants. RTM must never build
this storyline from a shared client IP alone; MSP offices and egress gateways
make IP-only correlation unsafe.

## Deterministic score

Risk is a bounded 0–100 score composed from the highest signal severity,
confidence, number of independent rule families, attack-stage breadth,
workload breadth, affected tenants, time proximity, and novelty. Severity is
derived from the score. The exact contributing facts are stored in `reasons`;
uncorroborated or missing context is stored separately as `weakEvidence`.

A storyline requires at least two independent detections. One noisy event or
many duplicates of the same rule do not create a storyline.

## Analyst and safety contract

Analysts can accept/assign a storyline and move it through New, In Progress,
Resolved, or Dismissed. Viewing and triage are audited. Correlation is
read-only: recommended containment actions are guidance and must use RTM's
existing What-If preview, approval, execution, and audit controls.

Future analyst controls should add explicit signal unlinking, storyline merge
and split, and scoped suppression without weakening the immutable evidence
trail.

## Optional visual timeline

The Attack storylines section defaults to its existing list and offers a
Timeline view using the same search, tenant, severity, and status filters.
Each storyline appears once at its latest activity time (`lastSeen`); its card
also shows first seen, tenants, stages, severity, risk, and status. Timeline
ordering is chronological, so list sorting is disabled while it is selected.
Selecting a storyline opens the existing audited detail view.

The complete evidence chain also offers List / Timeline. The timeline groups
retained signals by `occurredAt`, local date, and hour, and retains the full
signal cards and supporting event summaries. Stage labels describe evidence;
they do not reorder it or establish causation. Counts reflect the supplied
snapshot or detail response, not new global event searches. Dates without
activity are omitted and explicitly described as such. Invalid timestamps are
counted separately and remain accessible in List. View switches are read-only
and do not change correlation, workflow state, or approval requirements.
