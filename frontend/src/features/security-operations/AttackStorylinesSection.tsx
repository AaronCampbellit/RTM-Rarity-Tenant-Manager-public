import { StorylineTimeline } from "./StorylineTimeline";
import { useMemo, useState } from "react";
import {
  ArrowRight,
  Building2,
  Clock3,
  GitBranch,
  RefreshCw,
  ShieldAlert,
  UserRound,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { SearchInput } from "@/components/ui/input";
import type { SecurityStoryline } from "@/types";
import {
  filterSecurityStorylines,
  type StorylineSort,
  type StorylineStatusFilter,
} from "./attackStorylines";
import {
  relativeSecurityTime,
  securitySeverityTone,
  securityTriageTone,
} from "./securityOperations";

const SELECT_CLASS =
  "h-9 min-w-0 rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[12.5px] text-body outline-none focus:border-[var(--ac)]/50";
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"];

export function AttackStorylinesSection({
  storylines,
  loading,
  refreshing,
  onRefresh,
  onSelect,
}: {
  storylines: SecurityStoryline[];
  loading: boolean;
  refreshing: boolean;
  onRefresh: () => void;
  onSelect: (storyline: SecurityStoryline) => void;
}) {
  const [view, setView] = useState<"list" | "timeline">("list");
  const [query, setQuery] = useState("");
  const [tenant, setTenant] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState<StorylineStatusFilter>("active");
  const [sort, setSort] = useState<StorylineSort>("risk_desc");

  const tenantOptions = useMemo(() => {
    const unique = new Map<string, string>();
    for (const storyline of storylines) {
      storyline.tenantIds.forEach((id, index) => unique.set(id, storyline.tenantNames[index] ?? id));
    }
    return [...unique.entries()].sort((left, right) => left[1].localeCompare(right[1]));
  }, [storylines]);

  const severityOptions = useMemo(() => {
    const unique = new Set(storylines.map((storyline) => storyline.severity));
    return [...unique].sort((left, right) => {
      const leftIndex = SEVERITY_ORDER.indexOf(left);
      const rightIndex = SEVERITY_ORDER.indexOf(right);
      if (leftIndex === -1 && rightIndex === -1) return left.localeCompare(right);
      if (leftIndex === -1) return 1;
      if (rightIndex === -1) return -1;
      return leftIndex - rightIndex;
    });
  }, [storylines]);

  const rows = useMemo(
    () => filterSecurityStorylines(storylines, { query, tenant, severity, status, sort }),
    [query, severity, sort, status, storylines, tenant],
  );
  const activeCount = storylines.filter(
    (storyline) => storyline.status === "New" || storyline.status === "In Progress",
  ).length;

  return (
    <section aria-labelledby="attack-storylines-heading">
      <Card className="overflow-hidden">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[var(--border-card)] px-4 py-3">
        <div>
          <h3 id="attack-storylines-heading" className="text-[13.5px] font-semibold text-fg">
            Attack storylines
          </h3>
          <p className="mt-0.5 text-[10.5px] text-muted">
            Correlated attack sequences · select a row to inspect the complete evidence chain
          </p>
        </div>
        {!loading ? (
          <span className="text-[11px] text-muted">{activeCount} active · {storylines.length} total</span>
        ) : null}
      </div>

      <div className="border-b border-[var(--border-card)] p-3.5">
        <div className="flex flex-col gap-2.5 2xl:flex-row 2xl:items-center 2xl:justify-between">
          <span className="shrink-0 text-[12px] text-secondary">
            <strong className="font-semibold text-fg">{rows.length}</strong> of {storylines.length} storylines
          </span>
          <div className="grid min-w-0 grid-cols-2 gap-2 lg:grid-cols-[minmax(240px,1.35fr)_minmax(145px,.75fr)_minmax(135px,.7fr)_minmax(135px,.7fr)_minmax(175px,.85fr)_auto] 2xl:w-[1040px]">
            <SearchInput
              aria-label="Search attack storylines"
              placeholder="Search storyline, tenant, entity…"
              className="col-span-2 lg:col-span-1"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <select
              aria-label="Filter storylines by tenant"
              className={SELECT_CLASS}
              value={tenant}
              onChange={(event) => setTenant(event.target.value)}
            >
              <option value="all">All tenants</option>
              {tenantOptions.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
            </select>
            <select
              aria-label="Filter storylines by severity"
              className={SELECT_CLASS}
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <option value="all">All severities</option>
              {severityOptions.map((option) => <option key={option}>{option}</option>)}
            </select>
            <select
              aria-label="Filter storylines by status"
              className={SELECT_CLASS}
              value={status}
              onChange={(event) => setStatus(event.target.value as StorylineStatusFilter)}
            >
              <option value="active">Active</option>
              <option value="all">All statuses</option>
              <option>New</option>
              <option>In Progress</option>
              <option>Resolved</option>
              <option>Dismissed</option>
            </select>
            <select
              aria-label="Sort attack storylines"
              disabled={view === "timeline"}
              title={view === "timeline" ? "Timeline is ordered chronologically" : undefined}
              className={`${SELECT_CLASS} col-span-2 lg:col-span-1`}
              value={sort}
              onChange={(event) => setSort(event.target.value as StorylineSort)}
            >
              <option value="risk_desc">Risk: highest first</option>
              <option value="activity_desc">Activity: newest first</option>
              <option value="activity_asc">Activity: oldest first</option>
              <option value="title_asc">Storyline: A–Z</option>
            </select>
            <Button
              className="col-span-2 lg:col-span-1"
              onClick={onRefresh}
              disabled={loading || refreshing}
              aria-label="Refresh attack storylines"
            >
              <RefreshCw className={refreshing ? "animate-spin" : ""} />
              Refresh
            </Button>
          </div>
        </div>
      </div>

      <div role="group" aria-label="Storyline view" className="flex gap-2 px-4 py-3">
        <Button size="sm" aria-pressed={view === "list"} variant={view === "list" ? "accent" : "default"} onClick={() => setView("list")}>List</Button>
        <Button size="sm" aria-pressed={view === "timeline"} variant={view === "timeline" ? "accent" : "default"} onClick={() => setView("timeline")}>Timeline</Button>
      </div>
      <div className={view === "list" ? "max-h-[360px] overflow-y-auto" : "min-w-0"}>
        {loading ? (
          <div className="divide-y divide-[var(--border-card)]">
            {[0, 1].map((item) => <div key={item} className="h-[78px] animate-pulse bg-white/[.018]" />)}
          </div>
        ) : rows.length === 0 ? (
          <div className="grid min-h-32 place-items-center px-5 py-7 text-center">
            <div>
              <ShieldAlert className="mx-auto size-5 text-success" />
              <p className="mt-2 text-[12.5px] font-semibold text-fg">
                {status === "active" ? "No active multi-signal storylines" : "No storylines match these filters"}
              </p>
              <p className="mt-1 text-[11px] text-muted">
                {status === "active"
                  ? "Resolved and dismissed storylines remain available from the status filter."
                  : "Clear a filter or refresh the monitoring snapshot."}
              </p>
            </div>
          </div>
        ) : view === "timeline" ? (
          <StorylineTimeline items={rows} occurredAt={storylineActivity} getKey={storylineKey} label="Storyline activity timeline" unit="storylines"
            description="Each storyline appears once at its latest activity time. Select a storyline to inspect its full signal sequence."
            renderItem={(storyline) => <button type="button" aria-label={`Open storyline: ${storyline.title}`} onClick={() => onSelect(storyline)} className="w-full rounded-lg border border-[var(--border-card)] bg-control p-3 text-left hover:border-[var(--ac)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--ac)]">
              <div className="flex flex-wrap items-center gap-2"><Badge tone={securitySeverityTone(storyline.severity)}>{storyline.severity}</Badge><Badge tone={securityTriageTone(storyline.status)}>{storyline.status}</Badge><span className="text-xs text-secondary">{storyline.riskScore} risk · {storyline.signalCount} signals</span>{storyline.sample && <Badge tone="warning">Sample</Badge>}</div>
              <p className="mt-2 break-words text-sm font-semibold text-fg">{storyline.title}</p>
              <p className="mt-1 break-words text-xs text-muted">{storyline.tenantNames.join(" · ")} · {storyline.stages.join(" → ")}</p>
              <p className="mt-2 text-xs text-secondary">First seen {new Date(storyline.firstSeen).toLocaleString()} · Latest activity {new Date(storyline.lastSeen).toLocaleString()}</p>
            </button>} />
        ) : (
          <div className="divide-y divide-[var(--border-card)]">
            {rows.map((storyline) => (
              <button
                key={storyline.id}
                type="button"
                aria-label={`Open storyline: ${storyline.title}`}
                onClick={() => onSelect(storyline)}
                className="group grid w-full gap-3 px-4 py-3 text-left transition-colors hover:bg-[var(--row-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--ac)]/50 md:grid-cols-[minmax(280px,1.6fr)_minmax(170px,.8fr)_110px_78px_125px_20px] md:items-center"
              >
                <div className="min-w-0">
                  <div className="flex min-w-0 items-center gap-2">
                    <Badge tone={securitySeverityTone(storyline.severity)}>{storyline.severity}</Badge>
                    <span className="truncate text-[12.5px] font-semibold text-fg">{storyline.title}</span>
                    {storyline.sample ? <Badge tone="warning" dot={false}>Sample</Badge> : null}
                  </div>
                  <p className="mt-1 truncate text-[10.5px] text-muted" title={storyline.summary}>
                    {storyline.stages.join(" → ")} · {storyline.summary}
                  </p>
                </div>
                <div className="min-w-0 space-y-1 text-[10.5px] text-muted">
                  <StoryFact icon={Building2} value={storyline.tenantNames.join(", ")} />
                  <StoryFact
                    icon={UserRound}
                    value={storyline.entities.find((entity) => entity.primary)?.label ?? "Multiple entities"}
                  />
                </div>
                <div><Badge tone={securityTriageTone(storyline.status)}>{storyline.status}</Badge></div>
                <div>
                  <p className="tabular text-[15px] font-bold text-fg-strong">{storyline.riskScore}</p>
                  <p className="text-[9.5px] uppercase tracking-wide text-faint">Risk</p>
                </div>
                <div className="space-y-1 text-[10.5px] text-muted">
                  <StoryFact icon={GitBranch} value={`${storyline.signalCount} signals`} />
                  <StoryFact icon={Clock3} value={relativeSecurityTime(storyline.lastSeen)} />
                </div>
                <ArrowRight className="hidden size-4 text-faint transition-transform group-hover:translate-x-0.5 group-hover:text-fg md:block" />
              </button>
            ))}
          </div>
        )}
      </div>
      </Card>
    </section>
  );
}

function StoryFact({ icon: Icon, value }: { icon: typeof Building2; value: string }) {
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      <Icon className="size-3.5 shrink-0 text-faint" />
      <span className="truncate" title={value}>{value}</span>
    </span>
  );
}

function storylineActivity(storyline: SecurityStoryline) { return storyline.lastSeen; }
function storylineKey(storyline: SecurityStoryline) { return storyline.id; }
