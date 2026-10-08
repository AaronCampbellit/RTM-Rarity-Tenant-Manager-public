import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertOctagon,
  ArrowRight,
  Braces,
  Cable,
  CheckCircle2,
  CircleAlert,
  Clock3,
  Loader2,
  RefreshCw,
  ShieldAlert,
  UserRoundCheck,
} from "lucide-react";
import { api } from "@/api/client";
import { useRefreshingAsync } from "@/api/hooks";
import { DataTable, type Column } from "@/components/common/DataTable";
import { PageToolbar, SectionLabel } from "@/components/common/PageToolbar";
import { Badge, TONE } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { SearchInput } from "@/components/ui/input";
import { useSetPageTitle } from "@/store/page";
import type {
  SecurityIncident,
  SecurityIncidentDetail,
  SecurityBulkTriageRequest,
  SecurityHistoryImport,
  SecurityOperationsSnapshot,
  SecurityStoryline,
  SecurityTriageStatus,
  StatusTone,
} from "@/types";
import { IncidentDetailDrawer } from "./IncidentDetailDrawer";
import { AttackStorylinesSection } from "./AttackStorylinesSection";
import { StorylineDetailDrawer } from "./StorylineDetailDrawer";
import {
  connectorStatusLabel,
  chunkSecurityIncidentReferences,
  DEFAULT_SECURITY_INCIDENT_STATUS,
  filterSecurityIncidents,
  relativeSecurityTime,
  securityIncidentContext,
  securityIncidentReceivedAt,
  securityConnectorTone,
  securityIncidentKey,
  securitySeverityTone,
  securityTriageTone,
  summarizeConnectorHealth,
} from "./securityOperations";

const SELECT_CLASS =
  "h-9 rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[12.5px] text-body outline-none focus:border-[var(--ac)]/50";

const SEVERITY_COLOR: Record<string, string> = {
  Critical: "var(--color-danger)",
  High: "var(--color-accent-text)",
  Medium: "var(--color-warning)",
  Low: "var(--color-info)",
  Informational: "var(--color-neutral)",
  Unknown: "var(--color-faint)",
};

const TRIAGE_STAGES: SecurityTriageStatus[] = ["New", "In Progress", "Resolved", "Dismissed"];
type BulkTriageAction =
  | { action: "accept" }
  | { action: "set_status"; status: SecurityTriageStatus };

export function SecurityOperationsPage() {
  useSetPageTitle("Security Operations");
  const snapshot = useRefreshingAsync(() => api.security.operations(), [], {
    cacheKey: "security:operations",
  });
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState<string>(DEFAULT_SECURITY_INCIDENT_STATUS);
  const [tenant, setTenant] = useState("all");
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident>();
  const [selectedStoryline, setSelectedStoryline] = useState<SecurityStoryline>();
  const [selectedIncidentKeys, setSelectedIncidentKeys] = useState<Set<string>>(() => new Set());
  const [bulkStage, setBulkStage] = useState<SecurityTriageStatus>("In Progress");
  const [bulkSaving, setBulkSaving] = useState(false);
  const [bulkNotice, setBulkNotice] = useState<{ message: string; error?: boolean }>();

  const tenantOptions = useMemo(() => {
    const unique = new Map<string, string>();
    snapshot.data?.coverage?.forEach((row) => unique.set(row.tenantId, row.tenantName));
    snapshot.data?.incidents?.forEach((row) => unique.set(row.tenantId, row.tenantName));
    snapshot.data?.storylines?.forEach((storyline) => storyline.tenantIds.forEach((id, index) => unique.set(id, storyline.tenantNames[index] ?? id)));
    return [...unique.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  }, [snapshot.data]);

  const rows = useMemo(
    () =>
      filterSecurityIncidents(snapshot.data?.incidents ?? [], {
        query,
        severity,
        status,
        tenant,
      }),
    [query, severity, snapshot.data?.incidents, status, tenant],
  );

  const selectedRows = rows.filter((incident) => selectedIncidentKeys.has(securityIncidentKey(incident)));
  const allChecked = rows.length > 0 && rows.every((incident) => selectedIncidentKeys.has(securityIncidentKey(incident)));
  const someChecked = rows.some((incident) => selectedIncidentKeys.has(securityIncidentKey(incident)));

  function clearBulkSelection() {
    setSelectedIncidentKeys(new Set());
  }

  function changeFilter(update: () => void) {
    update();
    clearBulkSelection();
    setBulkNotice(undefined);
  }

  function toggleIncident(incident: SecurityIncident) {
    setBulkNotice(undefined);
    setSelectedIncidentKeys((current) => {
      const next = new Set(current);
      const key = securityIncidentKey(incident);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function toggleAllIncidents() {
    setBulkNotice(undefined);
    setSelectedIncidentKeys((current) => {
      const next = new Set(current);
      if (allChecked) rows.forEach((incident) => next.delete(securityIncidentKey(incident)));
      else rows.forEach((incident) => next.add(securityIncidentKey(incident)));
      return next;
    });
  }

  async function runBulkTriage(request: BulkTriageAction) {
    if (!selectedRows.length) return;
    setBulkSaving(true);
    setBulkNotice(undefined);
    try {
      const references = selectedRows.map((incident) => ({
        tenantId: incident.tenantId,
        incidentId: incident.id,
      }));
      let updated = 0;
      const failures: Array<{ tenantId: string; incidentId: string }> = [];
      for (const incidents of chunkSecurityIncidentReferences(references)) {
        const body: SecurityBulkTriageRequest = request.action === "accept"
          ? { action: "accept", incidents }
          : { action: "set_status", status: request.status, incidents };
        const result = await api.security.bulkTriage(body);
        updated += result.updated;
        failures.push(...result.failures);
      }
      const failed = new Set(failures.map((item) => `${item.tenantId}\u0000${item.incidentId}`));
      setSelectedIncidentKeys(failed);
      if (failures.length) {
        setBulkNotice({
          error: true,
          message: `${updated} updated; ${failures.length} could not be updated and remain selected.`,
        });
      } else {
        setBulkNotice({
          message: request.action === "accept"
            ? `${updated} incident${updated === 1 ? "" : "s"} accepted and assigned to you.`
            : `${updated} incident${updated === 1 ? "" : "s"} moved to ${request.status}.`,
        });
      }
      snapshot.refresh();
    } catch (error) {
      setBulkNotice({
        error: true,
        message: error instanceof Error ? error.message : "The bulk incident update failed.",
      });
    } finally {
      setBulkSaving(false);
    }
  }

  const columns: Column<SecurityIncident>[] = [
    {
      key: "selection",
      header: (
        <Checkbox
          checked={allChecked}
          indeterminate={!allChecked && someChecked}
          onChange={toggleAllIncidents}
          aria-label="Select all visible incidents"
        />
      ),
      width: "40px",
      cell: (incident) => (
        <Checkbox
          checked={selectedIncidentKeys.has(securityIncidentKey(incident))}
          onChange={() => toggleIncident(incident)}
          aria-label={`Select ${incident.title} for bulk action`}
        />
      ),
    },
    {
      key: "severity",
      header: "Severity",
      width: "88px",
      className: "hidden sm:table-cell",
      cell: (incident) => (
        <Badge tone={securitySeverityTone(incident.severity)}>{incident.severity}</Badge>
      ),
    },
    {
      key: "incident",
      header: "Incident",
      width: "34%",
      cell: (incident) => {
        const context = securityIncidentContext(incident);
        return (
          <div className="min-w-0 py-0.5">
            <div className="flex min-w-0 flex-wrap items-center gap-1.5">
              <span
                className="w-full min-w-0 truncate font-semibold text-fg sm:w-auto sm:flex-1"
                title={incident.title}
              >
                {incident.title}
              </span>
              {incident.sample && (
                <span className="shrink-0 rounded bg-white/[.06] px-1.5 py-0.5 text-[9.5px] font-bold uppercase tracking-wide text-faint">
                  Sample
                </span>
              )}
              {incident.confidence && (
                <span className="shrink-0 rounded bg-white/[.06] px-1.5 py-0.5 text-[9.5px] font-bold uppercase tracking-wide text-faint">
                  {incident.confidence} confidence
                </span>
              )}
              {incident.alertCount > 1 && (
                <span className="shrink-0 rounded bg-white/[.06] px-1.5 py-0.5 text-[9.5px] font-bold uppercase tracking-wide text-faint">
                  {incident.alertCount} alerts
                </span>
              )}
            </div>
            <p className="mt-0.5 truncate text-[11.5px] text-muted">
              {context.subject}
            </p>
            {context.activity && (
              <p className="mt-0.5 truncate text-[10.5px] text-faint" title={context.activity}>
                {context.activity}
              </p>
            )}
          </div>
        );
      },
    },
    {
      key: "tenant",
      header: "Tenant",
      width: "15%",
      className: "hidden md:table-cell",
      cell: (incident) => (
        <span className="block truncate font-medium text-body" title={incident.tenantName}>
          {incident.tenantName}
        </span>
      ),
    },
    {
      key: "source",
      header: "Source",
      width: "90px",
      className: "hidden xl:table-cell",
      cell: (incident) => (
        <span className="block truncate text-secondary" title={incident.source}>{incident.source}</span>
      ),
    },
    {
      key: "owner",
      header: "Owner",
      width: "120px",
      className: "hidden 2xl:table-cell",
      cell: (incident) => (
        <span
          className={`block truncate ${incident.owner ? "text-body" : "italic text-faint"}`}
          title={incident.owner || "Unassigned"}
        >
          {incident.owner || "Unassigned"}
        </span>
      ),
    },
    {
      key: "status",
      header: "RTM status",
      width: "98px",
      cell: (incident) => (
        <Badge tone={securityTriageTone(incident.status)}>{incident.status}</Badge>
      ),
    },
    {
      key: "created",
      header: "Incident time",
      align: "right",
      width: "88px",
      className: "hidden xl:table-cell",
      cell: (incident) => {
        const receivedAt = securityIncidentReceivedAt(incident);
        return (
          <span
            className="tabular whitespace-nowrap text-secondary"
            title={receivedAt ? new Date(receivedAt).toLocaleString() : undefined}
          >
            {relativeSecurityTime(receivedAt)}
          </span>
        );
      },
    },
  ];

  function incidentChanged(updated: SecurityIncidentDetail) {
    setSelectedIncident(updated);
    snapshot.refresh();
  }

  function storylineChanged(updated: SecurityStoryline) {
    setSelectedStoryline(updated);
    snapshot.refresh();
  }

  return (
    <div className="space-y-4">
      <SecurityIntro snapshot={snapshot.data} />

      <div className="grid grid-cols-2 gap-3.5 md:grid-cols-3 xl:grid-cols-5">
        {snapshot.loading
          ? Array.from({ length: 5 }, (_, index) => <MetricSkeleton key={index} />)
          : <SecurityMetrics data={snapshot.data} />}
      </div>

      <div className="grid gap-3.5 lg:grid-cols-[minmax(0,1fr)_minmax(360px,.9fr)]">
        <SeverityDistribution data={snapshot.data} loading={snapshot.loading} />
        <ConnectorHealth data={snapshot.data} loading={snapshot.loading} />
      </div>

      <AttackStorylinesSection
        storylines={snapshot.data?.storylines ?? []}
        loading={snapshot.loading}
        refreshing={Boolean(snapshot.refreshing)}
        onRefresh={snapshot.refresh}
        onSelect={setSelectedStoryline}
      />

      <section>
        <SectionLabel>Incident queue</SectionLabel>
        <PageToolbar
          count={
            <span>
              <strong className="font-semibold text-fg">{rows.length}</strong> of{" "}
              {snapshot.data?.incidents?.length ?? 0} incidents · select a row to inspect evidence
            </span>
          }
        >
          <SearchInput
            aria-label="Search security incidents"
            placeholder="Search incident, tenant, entity…"
            className="w-full sm:w-[260px]"
            value={query}
            onChange={(event) => changeFilter(() => setQuery(event.target.value))}
          />
          <select
            aria-label="Filter by tenant"
            className={SELECT_CLASS}
            value={tenant}
            onChange={(event) => changeFilter(() => setTenant(event.target.value))}
          >
            <option value="all">All tenants</option>
            {tenantOptions.map(([id, name]) => (
              <option key={id} value={id}>{name}</option>
            ))}
          </select>
          <select
            aria-label="Filter by severity"
            className={SELECT_CLASS}
            value={severity}
            onChange={(event) => changeFilter(() => setSeverity(event.target.value))}
          >
            <option value="all">All severities</option>
            {snapshot.data?.severity?.map((item) => (
              <option key={item.severity} value={item.severity}>{item.severity}</option>
            ))}
          </select>
          <select
            aria-label="Filter by RTM status"
            className={SELECT_CLASS}
            value={status}
            onChange={(event) => changeFilter(() => setStatus(event.target.value))}
          >
            <option value="all">All statuses</option>
            <option>New</option>
            <option>In Progress</option>
            <option>Resolved</option>
            <option>Dismissed</option>
          </select>
          <Button
            onClick={() => {
              clearBulkSelection();
              setBulkNotice(undefined);
              snapshot.refresh();
            }}
            disabled={snapshot.loading || snapshot.refreshing}
            aria-label="Refresh security monitoring snapshot"
          >
            <RefreshCw className={snapshot.refreshing ? "animate-spin" : ""} />
            Refresh
          </Button>
          <span
            aria-hidden="true"
            className="ml-2 hidden h-6 w-px bg-[var(--border-strong)] sm:block"
          />
          <Link
            to="/security-events"
            className={buttonVariants({ variant: "default", className: "ml-auto" })}
          >
            <Braces />
            Raw event explorer
          </Link>
        </PageToolbar>
        {selectedRows.length > 0 && (
          <div
            role="region"
            aria-label="Bulk incident actions"
            className="mb-3 flex flex-col gap-3 rounded-[10px] border border-[var(--border-strong)] bg-raised px-3.5 py-3 lg:flex-row lg:items-center lg:justify-between"
          >
            <div>
              <p className="text-[13px] font-semibold text-fg">
                {selectedRows.length} incident{selectedRows.length === 1 ? "" : "s"} selected
              </p>
              <p className="mt-0.5 text-[11.5px] text-muted">
                Accept assigns them to you and advances New incidents to In Progress. These RTM workflow updates are audited and do not change Microsoft.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="accent"
                disabled={bulkSaving}
                onClick={() => void runBulkTriage({ action: "accept" })}
              >
                {bulkSaving ? <Loader2 className="animate-spin" /> : <UserRoundCheck />}
                Accept selected
              </Button>
              <select
                aria-label="Move selected incidents to stage"
                className={SELECT_CLASS}
                value={bulkStage}
                disabled={bulkSaving}
                onChange={(event) => setBulkStage(event.target.value as SecurityTriageStatus)}
              >
                {TRIAGE_STAGES.map((stage) => <option key={stage}>{stage}</option>)}
              </select>
              <Button
                disabled={bulkSaving}
                onClick={() => void runBulkTriage({ action: "set_status", status: bulkStage })}
              >
                <ArrowRight />
                Move selected
              </Button>
              <Button variant="ghost" disabled={bulkSaving} onClick={clearBulkSelection}>
                Clear
              </Button>
            </div>
          </div>
        )}
        {bulkNotice && (
          <div
            role={bulkNotice.error ? "alert" : "status"}
            className={`mb-3 flex items-center gap-2 rounded-[9px] border px-3.5 py-2.5 text-[12px] ${
              bulkNotice.error
                ? "border-danger/25 bg-[var(--bg-danger)] text-danger"
                : "border-success/25 bg-[var(--bg-success)] text-success"
            }`}
          >
            {!bulkNotice.error && <CheckCircle2 className="size-4 shrink-0" />}
            {bulkNotice.message}
          </div>
        )}
        <DataTable
          columns={columns}
          rows={rows}
          density="compact"
          fixedLayout
          loading={snapshot.loading}
          error={snapshot.error}
          emptyTitle={status === DEFAULT_SECURITY_INCIDENT_STATUS ? "No new incidents" : "No incidents match these filters"}
          emptyHint={status === DEFAULT_SECURITY_INCIDENT_STATUS
            ? "The new incident queue is clear. RTM will surface new detections here as they arrive."
            : "Clear a filter or refresh the monitoring snapshot."}
          getRowId={(incident) => `${incident.tenantId}-${incident.id}`}
          onRowClick={setSelectedIncident}
          isRowActive={(incident) =>
            incident.id === selectedIncident?.id && incident.tenantId === selectedIncident.tenantId
          }
        />
      </section>

      {selectedIncident && (
        <IncidentDetailDrawer
          incident={selectedIncident}
          onClose={() => setSelectedIncident(undefined)}
          onChanged={incidentChanged}
        />
      )}
      {selectedStoryline && (
        <StorylineDetailDrawer
          storyline={selectedStoryline}
          onClose={() => setSelectedStoryline(undefined)}
          onChanged={storylineChanged}
        />
      )}
    </div>
  );
}

function SecurityIntro({ snapshot }: { snapshot?: SecurityOperationsSnapshot }) {
  return (
    <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
      <div>
        <div className="flex items-center gap-2">
          <ShieldAlert className="size-5 text-danger" />
          <h2 className="text-[18px] font-bold text-fg-strong">Microsoft 365 security monitoring</h2>
        </div>
        <p className="mt-1 max-w-3xl text-[12.5px] leading-5 text-muted">
          Cross-tenant Defender incidents plus RTM-native detections from one-minute Graph identity monitoring and Microsoft 365 audit backfill. Monitoring is read-only against customer tenants.
        </p>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-3">
        {snapshot?.generatedAt && (
          <span className="inline-flex items-center gap-1.5 text-[11.5px] text-muted">
            <Clock3 className="size-3.5" /> Snapshot {relativeSecurityTime(snapshot.generatedAt)}
          </span>
        )}
      </div>
    </div>
  );
}

function SecurityMetrics({ data }: { data?: SecurityOperationsSnapshot }) {
  const connectorHealth = summarizeConnectorHealth(data?.connectors ?? []);
  const metrics: Array<{
    label: string;
    value: string;
    detail: string;
    tone: StatusTone;
    icon: typeof ShieldAlert;
  }> = [
    {
      label: "Open incidents",
      value: String(data?.summary.open ?? 0),
      detail: "New + in progress",
      tone: "info",
      icon: ShieldAlert,
    },
    {
      label: "Critical",
      value: String(data?.summary.critical ?? 0),
      detail: "Immediate review",
      tone: "danger",
      icon: AlertOctagon,
    },
    {
      label: "High severity",
      value: String(data?.summary.high ?? 0),
      detail: "Open across tenants",
      tone: "warning",
      icon: CircleAlert,
    },
    {
      label: "Connector health",
      ...connectorHealth,
      icon: Cable,
    },
    {
      label: "Ingestion health",
      value: `${data?.summary.ingestionHealth ?? 0}%`,
      detail: "Latest tenant fan-out",
      tone: (data?.summary.ingestionHealth ?? 0) === 100 ? "success" : "warning",
      icon: Activity,
    },
  ];
  return <>{metrics.map((metric) => <MetricCard key={metric.label} {...metric} />)}</>;
}

function MetricCard({
  label,
  value,
  detail,
  tone,
  icon: Icon,
}: {
  label: string;
  value: string;
  detail: string;
  tone: StatusTone;
  icon: typeof ShieldAlert;
}) {
  return (
    <Card className="p-4">
      <div className="flex items-start justify-between gap-2">
        <span className="text-[12px] font-medium text-secondary">{label}</span>
        <Icon className="size-4" style={{ color: TONE[tone].color }} />
      </div>
      <p className="mt-2 text-[27px] font-bold leading-none tracking-[-.5px] text-fg-strong">{value}</p>
      <p className="mt-2 text-[11.5px] text-muted">{detail}</p>
    </Card>
  );
}

function MetricSkeleton() {
  return (
    <Card className="p-4">
      <div className="h-3 w-24 animate-pulse rounded bg-white/5" />
      <div className="mt-3 h-7 w-12 animate-pulse rounded bg-white/5" />
      <div className="mt-3 h-3 w-28 animate-pulse rounded bg-white/5" />
    </Card>
  );
}

function SeverityDistribution({
  data,
  loading,
}: {
  data?: SecurityOperationsSnapshot;
  loading: boolean;
}) {
  const maximum = Math.max(1, ...(data?.severity.map((item) => item.count) ?? [1]));
  return (
    <Card>
      <div className="flex items-center justify-between border-b border-[var(--border-card)] px-4 py-3">
        <h3 className="text-[13.5px] font-semibold text-fg">Open severity distribution</h3>
        <span className="text-[11px] text-muted">Unresolved only</span>
      </div>
      <div className="space-y-3.5 p-4">
        {loading
          ? Array.from({ length: 5 }, (_, index) => (
              <div key={index} className="h-4 animate-pulse rounded bg-white/5" />
            ))
          : data?.severity.slice(0, 5).map((item) => (
              <div key={item.severity} className="grid grid-cols-[90px_1fr_24px] items-center gap-3">
                <span className="text-[11.5px] font-medium text-secondary">{item.severity}</span>
                <div className="h-2 overflow-hidden rounded-full bg-white/[.055]">
                  <div
                    className="h-full min-w-[2px] rounded-full transition-[width]"
                    style={{
                      width: `${(item.count / maximum) * 100}%`,
                      background: SEVERITY_COLOR[item.severity] ?? SEVERITY_COLOR.Unknown,
                      opacity: item.count ? 1 : 0.25,
                    }}
                  />
                </div>
                <span className="tabular text-right text-[12px] font-semibold text-body">{item.count}</span>
              </div>
            ))}
      </div>
    </Card>
  );
}

function ConnectorHealth({
  data,
  loading,
}: {
  data?: SecurityOperationsSnapshot;
  loading: boolean;
}) {
  return (
    <Card>
      <div className="flex items-center justify-between border-b border-[var(--border-card)] px-4 py-3">
        <h3 className="text-[13.5px] font-semibold text-fg">Connector health</h3>
        <span className="text-[11px] text-muted">Honest source coverage</span>
      </div>
      <div>
        {loading
          ? Array.from({ length: 3 }, (_, index) => (
              <div key={index} className="border-b border-[var(--border-card)] p-4 last:border-0">
                <div className="h-4 animate-pulse rounded bg-white/5" />
              </div>
            ))
          : data?.connectors.map((connector) => (
              <div
                key={connector.key}
                className="flex items-center gap-3 border-b border-[var(--border-card)] px-4 py-3 last:border-0"
              >
                <span
                  className="grid size-8 shrink-0 place-items-center rounded-[8px]"
                  style={{ background: TONE[securityConnectorTone(connector.status)].bg }}
                >
                  <Activity
                    className="size-4"
                    style={{ color: TONE[securityConnectorTone(connector.status)].color }}
                  />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[12.5px] font-semibold text-fg">{connector.name}</p>
                  <p className="mt-0.5 truncate text-[10.5px] text-muted">
                    {connector.status === "planned"
                      ? `Roadmap · ${connector.requiredPermission ?? "permission TBD"}`
                      : `${connector.healthyTenants} live · ${connector.sampleTenants} sample · ${connector.attentionTenants} attention`}
                  </p>
                </div>
                <Badge tone={securityConnectorTone(connector.status)} dot={connector.status !== "planned"}>
                  {connectorStatusLabel(connector.status)}
                </Badge>
              </div>
            ))}
        {!loading && <HistoryImportRows histories={data?.historyImports ?? []} />}
      </div>
    </Card>
  );
}

function HistoryImportRows({ histories }: { histories: SecurityHistoryImport[] }) {
  if (histories.length === 0) return null;
  return (
    <div className="border-t border-[var(--border-card)]">
      <div className="flex items-center justify-between px-4 pb-1 pt-3">
        <p className="text-[10px] font-bold uppercase tracking-[.12em] text-faint">
          Historical evidence
        </p>
        <span className="text-[10px] text-muted">Onboarding backfill</span>
      </div>
      {histories.map((history) => {
        const active = history.status === "queued" || history.status === "running";
        const tone: StatusTone =
          history.status === "completed"
            ? "success"
            : history.status === "failed"
              ? "danger"
              : "warning";
        const statusLabel =
          history.status === "partial"
            ? "Partial"
            : history.status.charAt(0).toUpperCase() + history.status.slice(1);
        return (
          <div key={history.tenantId} className="px-4 py-3">
            <div className="flex items-center gap-3">
              <span className="grid size-8 shrink-0 place-items-center rounded-[8px] bg-raised">
                <Clock3 className="size-4 text-info" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-2">
                  <p className="truncate text-[12px] font-semibold text-fg">
                    {history.tenantName || history.tenantId}
                  </p>
                  <Badge tone={tone} dot>
                    {statusLabel}
                  </Badge>
                </div>
                <p className="mt-0.5 truncate text-[10.5px] text-muted" title={history.detail}>
                  {history.detail}
                </p>
              </div>
            </div>
            {active && (
              <div
                className="ml-11 mt-2 h-1.5 overflow-hidden rounded-full bg-white/[.06]"
                aria-label={`History import ${history.progress}% complete`}
              >
                <div
                  className="h-full rounded-full bg-info transition-[width]"
                  style={{ width: `${history.progress}%` }}
                />
              </div>
            )}
            <p className="ml-11 mt-1.5 text-[10px] text-faint">
              {active
                ? `${history.progress}% · ${history.feedsCompleted} of ${history.feedsTotal || "calculating"} source windows`
                : `${history.eventsInserted.toLocaleString()} events retained · ${history.detectionsCreated.toLocaleString()} detections`}
            </p>
          </div>
        );
      })}
    </div>
  );
}
