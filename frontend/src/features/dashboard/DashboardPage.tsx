import { Link, useNavigate } from "react-router-dom";
import {
  AlertOctagon,
  Building2,
  CircleAlert,
  ListChecks,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Layers,
  ArrowRight,
} from "lucide-react";
import { api } from "@/api/client";
import { useAsync, useRefreshingAsync } from "@/api/hooks";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataTable, type Column } from "@/components/common/DataTable";
import { SectionLabel } from "@/components/common/PageToolbar";
import { changeTone, jobTone } from "@/components/common/status";
import { TONE } from "@/components/ui/badge";
import type {
  Approval,
  ChangeRecord,
  DashboardStat,
  SecurityOperationsSnapshot,
  StatusTone,
} from "@/types";
import { dashboardAttentionJobs } from "./dashboard";

const STAT_ICON = [Building2, ListChecks, ShieldCheck, Clock, Layers];
const RISK_TONE: Record<string, StatusTone> = {
  Low: "success",
  Medium: "warning",
  High: "danger",
};

export function DashboardPage() {
  useSetPageTitle("Dashboard");
  const navigate = useNavigate();
  const { version: syncVersion } = useSync();

  const stats = useAsync(() => api.dashboard.stats(), [syncVersion]);
  const approvals = useAsync(() => api.dashboard.approvals(), [syncVersion]);
  const jobs = useAsync(() => api.jobs.list(), [syncVersion]);
  const changes = useAsync(() => api.changes.list(), [syncVersion]);
  const security = useRefreshingAsync(() => api.security.operations(), [syncVersion], {
    cacheKey: "security:operations",
  });
  const attentionJobs = dashboardAttentionJobs(jobs.data ?? []);

  const changeColumns: Column<ChangeRecord>[] = [
    { key: "ts", header: "Time", width: "150px", cell: (c) => <span className="tabular text-secondary">{c.timestamp}</span> },
    { key: "tech", header: "Technician", cell: (c) => <span className="text-body">{c.technician}</span> },
    { key: "action", header: "Action", cell: (c) => <span className="font-semibold text-fg">{c.action}</span> },
    { key: "target", header: "Target", cell: (c) => <span className="text-secondary">{c.target}</span> },
    { key: "status", header: "Status", width: "110px", cell: (c) => <Badge tone={changeTone(c.status)}>{c.status}</Badge> },
  ];

  const quickReports = [
    "MFA Status",
    "License Usage",
    "Inactive Users",
    "Guest Accounts",
    "All Users",
    "Group Membership",
  ];

  return (
    <div className="space-y-4">
      {/* stat cards */}
      <div className="grid grid-cols-2 gap-3.5 md:grid-cols-3 xl:grid-cols-5">
        {stats.loading
          ? STAT_ICON.map((_, i) => <StatSkeleton key={i} />)
          : stats.data?.map((s, i) => <StatCard key={s.label} stat={s} icon={i} />)}
      </div>

      <SecurityOverview
        snapshot={security.data}
        loading={security.loading}
        unavailable={Boolean(security.error)}
      />

      {/* approvals + jobs that still need operator attention */}
      <div className="grid grid-cols-1 gap-3.5 lg:grid-cols-[minmax(0,1fr)_minmax(340px,.72fr)]">
        <Card>
          <div className="flex items-center justify-between border-b border-[var(--border-card)] px-4 py-3">
            <h3 className="text-[13.5px] font-semibold text-fg">Pending Approvals</h3>
            <Badge tone={(approvals.data?.length ?? 0) > 0 ? "warning" : "neutral"} dot={false}>
              {approvals.data?.length ?? 0} waiting
            </Badge>
          </div>
          <div>
            {approvals.data?.length === 0 && (
                <p className="px-4 py-6 text-center text-[12.5px] text-muted">
                No approvals waiting — changes execute directly after the
                What-If gate until the approval workflow is enabled.
                </p>
            )}
            {approvals.data?.map((a) => (
              <ApprovalRow key={a.id} a={a} />
            ))}
          </div>
        </Card>

        <Card>
          <div className="flex items-center justify-between border-b border-[var(--border-card)] px-4 py-3">
            <div className="flex items-center gap-2">
              <h3 className="text-[13.5px] font-semibold text-fg">Active &amp; Failed Jobs</h3>
              <Badge tone={attentionJobs.length > 0 ? "warning" : "success"} dot={false}>
                {attentionJobs.length}
              </Badge>
            </div>
            <Link
              to="/jobs"
              className="inline-flex items-center gap-1 text-[12px] text-secondary hover:text-fg"
            >
              View all <ArrowRight className="size-3.5" />
            </Link>
          </div>
          <div>
            {jobs.loading
              ? Array.from({ length: 3 }, (_, index) => (
                  <div key={index} className="border-b border-[var(--border-card)] px-4 py-3 last:border-0">
                    <div className="h-4 animate-pulse rounded bg-white/5" />
                  </div>
                ))
              : jobs.error ? (
                  <p className="px-4 py-6 text-center text-[12.5px] text-danger">
                    Job status is temporarily unavailable.
                  </p>
                )
              : attentionJobs.length === 0 ? (
                  <p className="px-4 py-6 text-center text-[12.5px] text-muted">
                    No active or failed jobs need attention.
                  </p>
                )
              : attentionJobs.map((j) => (
                  <div
                    key={j.id}
                    className="flex items-center justify-between gap-3 border-b border-[var(--border-card)] px-4 py-3 last:border-0"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-[13px] font-semibold text-fg">{j.type}</p>
                      <p className="truncate text-[12px] text-muted">{j.tenant}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge tone={jobTone(j.status)}>{j.status}</Badge>
                      <span className="w-8 text-right text-[12px] text-muted">
                        {j.status === "Running" ? "now" : j.duration === "—" ? "—" : j.started}
                      </span>
                    </div>
                  </div>
                ))}
          </div>
        </Card>
      </div>

      {/* recent changes */}
      <div>
        <SectionLabel>Recent Changes</SectionLabel>
        <DataTable
          columns={changeColumns}
          rows={changes.data?.slice(0, 5)}
          loading={changes.loading}
          error={changes.error}
          getRowId={(c) => c.id}
          onRowClick={(c) => navigate(`/changes/${c.id}`)}
        />
      </div>

      {/* quick reports */}
      <div>
        <SectionLabel>Quick Reports</SectionLabel>
        <div className="flex flex-wrap gap-2">
          {quickReports.map((q) => (
            <button
              key={q}
              onClick={() => navigate("/global-reports")}
              className="rounded-[20px] border border-[var(--border-strong)] bg-control px-3.5 py-1.5 text-[12.5px] font-medium text-body transition-colors hover:bg-[#2b2b32] hover:text-fg"
            >
              {q}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function SecurityOverview({
  snapshot,
  loading,
  unavailable,
}: {
  snapshot?: SecurityOperationsSnapshot;
  loading: boolean;
  unavailable: boolean;
}) {
  const metrics: Array<{
    label: string;
    value: string;
    detail: string;
    tone: StatusTone;
    icon: typeof ShieldAlert;
  }> = [
    {
      label: "Open incidents",
      value: unavailable ? "—" : String(snapshot?.summary.open ?? 0),
      detail: unavailable ? "Security snapshot unavailable" : "New + in progress",
      tone: unavailable ? "neutral" : "info",
      icon: ShieldAlert,
    },
    {
      label: "Critical",
      value: unavailable ? "—" : String(snapshot?.summary.critical ?? 0),
      detail: unavailable ? "Security snapshot unavailable" : "Immediate review",
      tone: unavailable ? "neutral" : "danger",
      icon: AlertOctagon,
    },
    {
      label: "High severity",
      value: unavailable ? "—" : String(snapshot?.summary.high ?? 0),
      detail: unavailable ? "Security snapshot unavailable" : "Open across tenants",
      tone: unavailable ? "neutral" : "warning",
      icon: CircleAlert,
    },
  ];

  return (
    <section>
      <div className="mb-2 flex items-center justify-between gap-3 [&>p]:mb-0">
        <SectionLabel>Security Operations</SectionLabel>
        <Link to="/security" className="inline-flex items-center gap-1 text-[12px] text-secondary hover:text-fg">
          View incidents <ArrowRight className="size-3.5" />
        </Link>
      </div>
      <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-3">
        {loading
          ? Array.from({ length: 3 }, (_, index) => <StatSkeleton key={index} />)
          : metrics.map((metric) => {
              const Icon = metric.icon;
              return (
                <Link
                  key={metric.label}
                  to="/security"
                  aria-label={`View Security Operations: ${metric.label}`}
                  className="group rounded-[12px] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ac)]"
                >
                  <Card className="h-full p-4 transition-colors group-hover:border-[var(--border-strong)] group-hover:bg-[#202025]">
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-[12px] font-medium text-secondary">{metric.label}</span>
                      <Icon className="size-4" style={{ color: TONE[metric.tone].color }} />
                    </div>
                    <p className="mt-2 text-[27px] font-bold leading-none tracking-[-.5px] text-fg-strong">
                      {metric.value}
                    </p>
                    <p className="mt-2 text-[12px] font-medium" style={{ color: TONE[metric.tone].color }}>
                      {metric.detail}
                    </p>
                  </Card>
                </Link>
              );
            })}
      </div>
    </section>
  );
}

function StatCard({ stat, icon }: { stat: DashboardStat; icon: number }) {
  const Icon = STAT_ICON[icon];
  return (
    <Card className="p-4">
      <div className="flex items-start justify-between">
        <span className="text-[12px] font-medium text-secondary">{stat.label}</span>
        <Icon className="size-4" style={{ color: TONE[stat.tone].color }} />
      </div>
      <div className="mt-2 text-[27px] font-bold leading-none tracking-[-.5px] text-fg-strong">
        {stat.value}
      </div>
      <div className="mt-2 text-[12px] font-medium" style={{ color: TONE[stat.tone].color }}>
        {stat.delta}
      </div>
    </Card>
  );
}

function StatSkeleton() {
  return (
    <Card className="p-4">
      <div className="h-3 w-20 rounded bg-white/5" />
      <div className="mt-3 h-7 w-10 rounded bg-white/5" />
      <div className="mt-3 h-3 w-24 rounded bg-white/5" />
    </Card>
  );
}

function ApprovalRow({ a }: { a: Approval }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-[var(--border-card)] px-4 py-3 last:border-0">
      <div className="min-w-0">
        <p className="truncate text-[13px] font-semibold text-fg">{a.action}</p>
        <p className="truncate text-[12px] text-muted">
          {a.tenant} · by {a.by}
        </p>
      </div>
      <Badge tone={RISK_TONE[a.risk]}>{a.risk}</Badge>
    </div>
  );
}
