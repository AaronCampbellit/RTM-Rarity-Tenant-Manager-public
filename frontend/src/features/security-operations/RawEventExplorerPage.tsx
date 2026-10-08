import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Braces, CheckCircle2, ChevronLeft, ChevronRight, Loader2, Search } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { DataTable, type Column } from "@/components/common/DataTable";
import { PageToolbar } from "@/components/common/PageToolbar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, SearchInput } from "@/components/ui/input";
import { useSetPageTitle } from "@/store/page";
import { useTenant } from "@/store/tenant";
import type { SecurityAuditEvent, SecurityAuditEventSearch } from "@/types";
import { EventTimeline } from "./EventTimeline";
import { EventDetailDrawer } from "./EventDetailDrawer";
import { normalizeEventSearch } from "./eventSearch";
import { SELECT_CLASS } from "./securityRules";

function initialSearch(): SecurityAuditEventSearch {
  const to = new Date(), from = new Date(to.getTime() - 7 * 24 * 60 * 60 * 1000);
  return { from: from.toISOString(), to: to.toISOString(), limit: 50, offset: 0 };
}

function localDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

function latencyLabel(from: string, to: string) {
  const milliseconds = Math.max(0, new Date(to).getTime() - new Date(from).getTime());
  if (milliseconds < 60_000) return `${Math.round(milliseconds / 1000)}s`;
  if (milliseconds < 3_600_000) return `${Math.round(milliseconds / 60_000)}m`;
  return `${(milliseconds / 3_600_000).toFixed(1)}h`;
}

function sourceLabel(sources: string[]) {
	const prefix = sources.includes("historical_backfill") ? "Historical · " : "";
	if (sources.includes("entra_graph") && sources.includes("m365_audit")) return `${prefix}Graph + audit`;
	return `${prefix}${sources.includes("entra_graph") ? "Graph fast" : "M365 audit"}`;
}

export function RawEventExplorerPage() {
  useSetPageTitle("Raw Event Explorer");
  const { tenants } = useTenant();
  const [draft, setDraft] = useState<SecurityAuditEventSearch>(() => initialSearch());
  const [applied, setApplied] = useState<SecurityAuditEventSearch>(() => initialSearch());
  const [runSequence, setRunSequence] = useState(0);
  const [formError, setFormError] = useState<string>();
  const [completedAt, setCompletedAt] = useState<Date>();
  const [view, setView] = useState<"table" | "timeline">("table");
  const [selected, setSelected] = useState<SecurityAuditEvent>();
  const key = JSON.stringify(applied);
  const query = useAsync(() => api.security.events(applied), [key, runSequence]);

  useEffect(() => {
    if (!query.loading && (query.data || query.error)) setCompletedAt(new Date());
  }, [query.data, query.error, query.loading]);

  const columns = useMemo<Column<SecurityAuditEvent>[]>(() => [
    { key: "time", header: "Occurred", width: "160px", cell: (event) => <span className="tabular text-secondary">{new Date(event.occurredAt).toLocaleString()}</span> },
    { key: "tenant", header: "Tenant", cell: (event) => <span className="font-medium text-fg">{event.tenantName}</span> },
    { key: "source", header: "Source", cell: (event) => <Badge tone={event.historicalImport ? "warning" : event.sources.includes("entra_graph") ? "success" : "info"}>{sourceLabel(event.sources)}</Badge> },
    { key: "workload", header: "Workload", cell: (event) => <Badge tone="info">{event.workload}</Badge> },
    { key: "operation", header: "Operation", width: "24%", cell: (event) => <div><p className="font-semibold text-fg">{event.operation}</p><p className="mono mt-1 max-w-[280px] truncate text-[10.5px] text-muted">{event.objectId || event.providerRecordId}</p></div> },
    { key: "actor", header: "Actor", cell: (event) => <span>{event.actor || "—"}</span> },
    { key: "ip", header: "Client IP", cell: (event) => <span className="mono text-[11px]">{event.clientIp || "—"}</span> },
    { key: "latency", header: "Observed", align: "right", cell: (event) => <span className="tabular text-secondary">+{latencyLabel(event.occurredAt, event.availableAt)}</span> },
    { key: "result", header: "Result", align: "right", cell: (event) => <Badge tone={/fail|error/i.test(event.resultStatus || "") ? "danger" : "success"}>{event.resultStatus || "Unknown"}</Badge> },
  ], []);

  function apply(offset = 0) {
    try {
      setFormError(undefined);
      setCompletedAt(undefined);
      setApplied(normalizeEventSearch(draft, offset));
      setRunSequence((current) => current + 1);
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "The search filters are invalid.");
    }
  }
  function move(offset: number) { const next = { ...applied, offset }; setApplied(next); setDraft(next); }

  return <div className="mx-auto max-w-[1600px] px-4 py-5 sm:px-6 lg:px-8">
    <div className="mb-5"><div className="flex items-center gap-2"><Braces className="size-5 text-[var(--ac)]" /><h2 className="text-[20px] font-bold text-fg-strong">Raw event explorer</h2></div><p className="mt-1 text-[12.5px] text-muted">Bounded, audited search across fast Graph identity events and authoritative Microsoft 365 audit evidence for all managed tenants.</p></div>
    <form className="mb-4 rounded-[12px] border border-[var(--border-card)] bg-card p-4" onSubmit={(event) => { event.preventDefault(); apply(); }}>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4"><label className="xl:col-span-2"><Label>Search all normalized fields</Label><SearchInput placeholder="Operation, actor, IP, object, result…" value={draft.query ?? ""} onChange={(event) => setDraft({ ...draft, query: event.target.value })} /></label><label><Label>Tenant</Label><select className={SELECT_CLASS} value={draft.tenantId ?? ""} onChange={(event) => setDraft({ ...draft, tenantId: event.target.value })}><option value="">All managed tenants</option>{tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}</select></label><label><Label>Workload</Label><Input placeholder="Exchange" value={draft.workload ?? ""} onChange={(event) => setDraft({ ...draft, workload: event.target.value })} /></label><label><Label>Operation</Label><Input placeholder="Set-Mailbox" value={draft.operation ?? ""} onChange={(event) => setDraft({ ...draft, operation: event.target.value })} /></label><label><Label>Actor</Label><Input placeholder="admin@domain.com" value={draft.actor ?? ""} onChange={(event) => setDraft({ ...draft, actor: event.target.value })} /></label><label><Label>Client IP</Label><Input placeholder="203.0.113.42" value={draft.clientIp ?? ""} onChange={(event) => setDraft({ ...draft, clientIp: event.target.value })} /></label><label><Label>Result</Label><Input placeholder="Failed" value={draft.result ?? ""} onChange={(event) => setDraft({ ...draft, result: event.target.value })} /></label><label><Label>From</Label><Input required type="datetime-local" value={localDate(draft.from)} onChange={(event) => setDraft({ ...draft, from: event.target.value })} /></label><label><Label>To</Label><Input required type="datetime-local" value={localDate(draft.to)} onChange={(event) => setDraft({ ...draft, to: event.target.value })} /></label><div className="flex items-end"><Button disabled={query.loading} variant="accent" className="w-full" type="submit">{query.loading ? <Loader2 className="animate-spin" /> : <Search />}{query.loading ? "Searching…" : "Run search"}</Button></div></div>
      {formError && <p role="alert" className="mt-3 flex items-center gap-2 rounded-[8px] border border-danger/25 bg-[var(--bg-danger)] px-3 py-2 text-[12px] text-danger"><AlertTriangle className="size-4" />{formError}</p>}
    </form>
    {view === "table" && <PageToolbar count={query.loading ? "Searching retained evidence…" : query.data ? `${query.data.events.length} events · ${query.data.windowDays}-day window` : "Search unavailable"}><span aria-live="polite" className="inline-flex items-center gap-1.5 text-[11.5px] text-muted">{query.loading ? <><Loader2 className="size-3.5 animate-spin" />Query in progress</> : completedAt && !query.error ? <><CheckCircle2 className="size-3.5 text-success" />Search completed at {completedAt.toLocaleTimeString()}</> : "Results are capped at 100 rows per page and a 180-day query window."}</span></PageToolbar>}
    <div role="group" aria-label="Event view" className="mb-3 flex gap-2"><Button aria-pressed={view === "table"} variant={view === "table" ? "accent" : "default"} onClick={() => setView("table")}>Table</Button><Button aria-pressed={view === "timeline"} variant={view === "timeline" ? "accent" : "default"} onClick={() => setView("timeline")}>Timeline</Button></div>
    {view === "timeline" ? <EventTimeline key={`${key}:${runSequence}`} search={applied} onSelect={setSelected} /> : <>
    <DataTable columns={columns} rows={query.data?.events} loading={query.loading} error={query.error} getRowId={(event) => `${event.tenantId}:${event.id}`} onRowClick={setSelected} emptyTitle="Search completed — no events found" emptyHint="No retained events matched these filters. If every search is empty, verify Office 365 Management APIs ActivityFeed.Read ingestion coverage." />
    <div className="mt-3 flex justify-end gap-2"><Button disabled={!applied.offset} onClick={() => move(Math.max(0, (applied.offset ?? 0) - (applied.limit ?? 50)))}><ChevronLeft />Previous</Button><Button disabled={query.data?.nextOffset == null} onClick={() => query.data?.nextOffset != null && move(query.data.nextOffset)}>Next<ChevronRight /></Button></div>
    </>}
    {selected && <EventDetailDrawer event={selected} onClose={() => setSelected(undefined)} />}
  </div>;
}

function Label({ children }: { children: React.ReactNode }) { return <span className="mb-1.5 block text-[11px] font-semibold text-secondary">{children}</span>; }
