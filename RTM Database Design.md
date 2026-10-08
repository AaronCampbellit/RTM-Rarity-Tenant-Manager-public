# RTM Database Design
Core tables:
- tenants
- technicians
- roles
- tenant_access
- working_sets
- jobs
- audit_logs
- change_history
- change_previews
- revert_jobs
- cached_reports
- app_settings
- sharepoint_scans
- sharepoint_inventory_nodes
- security_incident_states
- security_audit_checkpoints
- security_audit_events
- security_native_detections
- security_detection_rules
- security_detection_rule_revisions
- security_history_imports
- tenant_preflight_snapshots
- offline_investigations
- offline_investigation_files
- offline_investigation_events
- offline_investigation_detections
- offline_investigation_storylines
Design principles:
- tenant_id on tenant-scoped data
- UUID primary keys
- Foreign key enforcement
- Soft deletes where appropriate
- Encryption for sensitive values
- Index tenant_id, timestamps, frequently searched fields.

`working_sets` stores the owning `tenant_id`, an optional description, and the
exact selected object IDs (`user_ids`) in addition to its display count and
creator. The tenant foreign key cascades on tenant removal. Working Set
creation is synchronous and durable; PostgreSQL is the source of truth after
page reloads and service restarts.
Future:
- Reporting cache
- Scheduled jobs
- Notification tables.

SharePoint snapshots are durable tenant-scoped records. `sharepoint_scans`
stores trigger, status, coverage, totals, warnings, and timestamps;
`sharepoint_inventory_nodes` stores the latest site/OneDrive hierarchy for a
scope and references its scan. A partial scan remains visible and never
silently replaces its coverage state with `complete`.

`security_incident_states` is the Security Operations
overlay. Its composite primary key is `(tenant_id, incident_id)` and it stores
RTM's durable first-received timestamp plus local triage status, local owner,
last actor, and workflow update timestamp.
The tenant foreign key cascades on deletion and the status is constrained to
`New`, `In Progress`, `Resolved`, or `Dismissed`. Microsoft Defender remains
the incident/evidence system of record; raw alerts and evidence are not copied
into PostgreSQL.

`security_audit_checkpoints` stores one durable cursor/health row per tenant
and Management Activity or Graph fast-identity content type.
`security_audit_events` stores immutable normalized fields plus server-only raw
JSON, first-observed availability, ingestion time, and all contributing source
names. Uniqueness on `(tenant_id, provider_record_id)` merges Graph fast-lane
records with their later unified-audit backfill instead of duplicating them.
`security_native_detections` stores
deterministic, versioned rule matches, detection type/confidence, and a
reference to the source event. `security_detection_replays` records completion
of bounded historical direct-rule replays by pack version. The tenant-scoped
tables cascade on tenant removal; event time and operation indexes support the
cross-tenant queue and replay. The worker prunes source events older than 180
days, cascading their detections.

`security_detection_rules` stores custom rules and scoped built-in overrides;
locked built-in baselines remain in the versioned application catalog. A
unique `(rule_id, scope, tenant_id)` key prevents ambiguous precedence.
Definitions/exclusions are JSONB and mutations use an integer optimistic
revision. `security_detection_rule_revisions` records the complete snapshot,
actor, and timestamp for every create, update, and restore. Restore appends a
new current revision instead of rewriting history.

`security_history_imports` stores one onboarding backfill policy/status per
tenant: requested window, historical incident mode, persistent incident
cutoff, River job ID, progress, source-window coverage, retained-event totals,
and detection totals. Imported raw evidence remains only in
`security_audit_events`; the status row contains no credentials or evidence.

`tenant_preflight_snapshots` stores the last permission diagnostic per tenant
as a timestamped mode plus categorized JSONB checks. The tenant foreign key
cascades on deletion. Reading Tenant Detail uses this snapshot and never
contacts Microsoft; only the explicit POST diagnostic replaces it.

Offline investigation tables form a separate evidence namespace with no
foreign key to `tenants` and no relationship to live `security_audit_events`.
`offline_investigations` stores case identity, progress, bounded counts,
analysis window, and a JSONB coverage manifest. Source content in
`offline_investigation_files` is immutable, SHA-256 identified, and sealed with
RTM field encryption; `(investigation_id, sha256)` prevents duplicate upload.
Case events, detections, and storylines store normalized/derived JSONB rows and
cascade with the case. Re-analysis transactionally replaces only those derived
rows. Application and audit logs never contain source payloads.
