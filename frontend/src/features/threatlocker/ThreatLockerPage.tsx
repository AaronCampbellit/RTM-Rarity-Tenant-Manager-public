import { useState } from "react";
import { Download, Edit3, GitMerge, Globe2, Play, ShieldCheck, UploadCloud, X } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { type RefreshingAsyncState, useRefreshingAsync } from "@/api/hooks";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { SearchInput } from "@/components/ui/input";
import { PillTabs } from "@/components/ui/tabs";
import { PageToolbar } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { downloadAuditedCsv } from "@/lib/csv";
import { DeviceActionDialog } from "./DeviceActionDialog";
import { DeviceDetailModal } from "./DeviceDetailModal";
import { ApprovalDetailModal } from "./ApprovalDetailModal";
import { PolicyEditModal } from "./PolicyEditModal";
import { AppCleanupDialog } from "./AppCleanupDialog";
import { AppRenameModal } from "./AppRenameModal";
import { CleanupTab } from "./CleanupTab";
import { deviceModeLabel, deviceModeTone } from "./mode";
import { threatLockerQueryKeys } from "./preload";
import type { ApprovalRequest, Device, TLApplication, TLPolicy } from "@/types";

const TABS = [
  { key: "devices", label: "Devices" },
  { key: "approvals", label: "Approval Requests" },
  { key: "apps", label: "Apps" },
  { key: "policies", label: "Policies" },
  { key: "cleanup", label: "Clean up" },
];
const CONNECTOR_FAILURE_BACKOFF_MS = 15 * 60_000;

/**
 * ThreatLocker module screen. This is parent-organization scoped so it stays
 * stable when the active RTM tenant changes.
 */
export function ThreatLockerPage() {
  useSetPageTitle("ThreatLocker");
  const { version: syncVersion } = useSync();
  const [tab, setTab] = useState("devices");

  const devices = useRefreshingAsync(
    () => api.threatlocker.devices(),
    [syncVersion],
    { cacheKey: threatLockerQueryKeys.devices, enabled: tab === "devices", failureTtlMs: CONNECTOR_FAILURE_BACKOFF_MS },
  );
  const approvals = useRefreshingAsync(
    () => api.threatlocker.approvalRequests(undefined, "pending"),
    [syncVersion],
    { cacheKey: threatLockerQueryKeys.approvals, enabled: tab === "approvals", failureTtlMs: CONNECTOR_FAILURE_BACKOFF_MS },
  );
  const policies = useRefreshingAsync(
    () => api.threatlocker.policies(),
    [syncVersion],
    { cacheKey: threatLockerQueryKeys.policies, enabled: tab === "policies" || tab === "apps", failureTtlMs: CONNECTOR_FAILURE_BACKOFF_MS },
  );
  const apps = useRefreshingAsync(
    () => api.threatlocker.apps(undefined, "", { refresh: true }),
    [syncVersion],
    { cacheKey: threatLockerQueryKeys.apps, enabled: tab === "apps" || tab === "cleanup", failureTtlMs: CONNECTOR_FAILURE_BACKOFF_MS },
  );

  const activeError = tab === "devices" ? devices.error : tab === "approvals" ? approvals.error : tab === "policies" ? policies.error : apps.error;
  if (activeError instanceof RtmApiError && activeError.code === "NOT_CONNECTED") {
    return <NotConnectedPanel />;
  }

  return (
    <div className="space-y-4 pb-16">
      <PillTabs tabs={TABS} value={tab} onChange={setTab} />
      {tab === "devices" && <DevicesTab devices={devices} />}
      {tab === "approvals" && <ApprovalsTab approvals={approvals} />}
      {tab === "apps" && <AppsTab apps={apps} policies={policies} />}
      {tab === "policies" && <PoliciesTab policies={policies} />}
      {tab === "cleanup" && <CleanupTab apps={apps} />}
    </div>
  );
}

function policyActionTone(a: string) {
  return a === "permit" ? "success" : a === "deny" ? "danger" : "warning";
}

function compactPolicyDate(value: string) {
  if (!value) return "Never";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function AppsTab({
  apps,
  policies,
  tenantId,
}: {
  apps: RefreshingAsyncState<TLApplication[]>;
  policies: RefreshingAsyncState<TLPolicy[]>;
  tenantId?: string;
}) {
  const { data, loading, error, refresh } = apps;
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [q, setQ] = useState("");
  const [renaming, setRenaming] = useState<TLApplication | null>(null);
  const [cleanupOpen, setCleanupOpen] = useState(false);

  const rows = (data ?? []).filter((app) => {
    const haystack = [app.name, app.description, app.organization, app.source].join(" ").toLowerCase();
    return haystack.includes(q.toLowerCase());
  });
  const selectedIds = Array.from(selected);
  const allChecked = rows.length > 0 && rows.every((app) => selected.has(app.id));
  const someChecked = rows.some((app) => selected.has(app.id));

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  const toggleAll = () =>
    setSelected(allChecked ? new Set() : new Set(rows.map((app) => app.id)));

  const exportCsv = () =>
    void downloadAuditedCsv(
      {
        kind: "threatlocker-applications",
        filename: "threatlocker-applications.csv",
        rowCount: rows.length,
        headers: ["Name", "Source", "Organization", "OS", "Files", "Policies", "Status"],
        rows: rows.map((app) => [
          app.name, app.source, app.organization, app.os,
          app.fileCount ? String(app.fileCount) : "", String(app.policyCount ?? 0), app.status,
        ]),
      },
      api.exports.generate,
    );

  const columns: Column<TLApplication>[] = [
    {
      key: "sel",
      header: (
        <Checkbox
          checked={allChecked}
          indeterminate={!allChecked && someChecked}
          onChange={toggleAll}
          aria-label="Select all"
        />
      ),
      width: "44px",
      cell: (app) => (
        <span onClick={(e) => e.stopPropagation()}>
          <Checkbox
            checked={selected.has(app.id)}
            onChange={() => toggle(app.id)}
            aria-label={`Select ${app.name}`}
          />
        </span>
      ),
    },
    {
      key: "name",
      header: "Application",
      cell: (app) => (
        <div className="min-w-[220px]">
          <p className="font-semibold text-fg">{app.name}</p>
          <p className="line-clamp-1 text-[11.5px] text-muted">{app.description || app.id}</p>
        </div>
      ),
    },
    {
      key: "source",
      header: "Source",
      width: "94px",
      cell: (app) => (
        <Badge tone={app.source === "parent" ? "info" : "neutral"} dot={false}>
          <span className="capitalize">{app.source}</span>
        </Badge>
      ),
    },
    {
      key: "org",
      header: "Organization",
      cell: (app) => <span className="text-secondary">{app.organization || "—"}</span>,
    },
    { key: "os", header: "OS", width: "90px", cell: (app) => app.os || "—" },
    {
      key: "files",
      header: "Files",
      align: "right",
      width: "66px",
      // ThreatLocker's application-list API doesn't return a file-rule count;
      // it's only available per app, so show it when known (detail) and a dash
      // otherwise rather than a misleading 0. Open an app to see its file rules.
      cell: (app) => (
        <span className="tabular text-secondary" title={app.fileCount ? undefined : "Open the app to view its file rules"}>
          {app.fileCount ? app.fileCount : "—"}
        </span>
      ),
    },
    {
      key: "policies",
      header: "Policies",
      align: "right",
      width: "78px",
      cell: (app) => <span className="tabular text-secondary">{app.policyCount ?? 0}</span>,
    },
    {
      key: "status",
      header: "Status",
      width: "92px",
      cell: (app) => (
        <Badge tone={app.status === "Enabled" ? "success" : "neutral"}>
          {app.status || "—"}
        </Badge>
      ),
    },
    {
      key: "actions",
      header: "",
      align: "right",
      width: "54px",
      cell: (app) => (
        <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" variant="outline" className="w-8 px-0" aria-label={`Rename ${app.name}`} title="Rename" onClick={() => setRenaming(app)}>
            <Edit3 />
          </Button>
        </div>
      ),
    },
  ];

  function refreshAfterCleanup() {
    refresh();
    policies.refresh();
  }

  function closeCleanup() {
    setCleanupOpen(false);
    setSelected(new Set());
  }

  return (
    <>
      <PageToolbar count={`${data?.length ?? 0} apps`}>
        <SearchInput
          placeholder="Search apps…"
          className="w-[220px]"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <Button variant="default" onClick={exportCsv} disabled={loading || rows.length === 0}>
          <Download className="size-4" />
          Export CSV
        </Button>
        <Button variant="accent" onClick={() => setCleanupOpen(true)} disabled={selected.size < 2}>
          <GitMerge className="size-4" />
          Clean up
        </Button>
      </PageToolbar>

      <DataTable
        columns={columns}
        rows={rows}
        loading={loading}
        error={error}
        getRowId={(app) => app.id}
        isRowActive={(app) => selected.has(app.id)}
        onRowClick={(app) => toggle(app.id)}
        emptyTitle="No applications match"
      />

      {selected.size > 0 && (
        <div className="fixed bottom-6 left-[calc(250px+50%-125px)] z-30 -translate-x-1/2 animate-pop">
          <div className="flex items-center gap-2 rounded-[12px] border border-[var(--border-strong)] bg-raised px-3 py-2 shadow-[0_14px_40px_rgba(0,0,0,.55)]">
            <span className="px-1.5 text-[13px] font-semibold text-fg">
              {selected.size} selected
            </span>
            <span className="h-5 w-px bg-white/10" />
            <Button variant="accent" size="sm" onClick={() => setCleanupOpen(true)} disabled={selected.size < 2}>
              <GitMerge className="size-3.5" />
              Clean up
            </Button>
            <Button variant="ghost" size="icon" aria-label="Clear" onClick={() => setSelected(new Set())}>
              <X className="size-4" />
            </Button>
          </div>
        </div>
      )}

      <AppRenameModal
        tenantId={tenantId}
        app={renaming}
        onClose={() => setRenaming(null)}
        onSaved={refresh}
      />
      <AppCleanupDialog
        open={cleanupOpen}
        tenantId={tenantId}
        apps={data ?? []}
        selectedIds={selectedIds}
        onClose={closeCleanup}
        onDone={refreshAfterCleanup}
      />
    </>
  );
}

function PoliciesTab({ policies, tenantId }: { policies: RefreshingAsyncState<TLPolicy[]>; tenantId?: string }) {
  const { data, loading, error, refresh } = policies;
  const [q, setQ] = useState("");
  const [editing, setEditing] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState("");

  const rows = (data ?? []).filter((p) =>
    p.name.toLowerCase().includes(q.toLowerCase()),
  );

  const columns: Column<TLPolicy>[] = [
    {
      key: "name",
      header: "Policy",
      cell: (p) => <span className="font-semibold text-fg">{p.name}</span>,
    },
    {
      key: "action",
      header: "Action",
      width: "106px",
      cell: (p) => (
        <Badge tone={policyActionTone(p.action)} dot={false}>
          <span className="capitalize">
            {p.action || "—"} {p.policyActionId ? `#${p.policyActionId}` : ""}
          </span>
        </Badge>
      ),
    },
    { key: "applies", header: "Applies to", cell: (p) => <span className="text-secondary">{p.appliesTo || "—"}</span> },
    {
      key: "apps",
      header: "Apps",
      align: "right",
      width: "56px",
      cell: (p) => <span className="tabular text-secondary">{p.applicationCount ?? 0}</span>,
    },
    {
      key: "users",
      header: "Users",
      align: "right",
      width: "60px",
      cell: (p) => <span className="tabular text-secondary">{p.allUsers ? "All" : (p.userCount ?? 0)}</span>,
    },
    {
      key: "matched",
      header: "Last matched",
      width: "108px",
      cell: (p) => <span className="text-secondary">{compactPolicyDate(p.lastMatchedAt)}</span>,
    },
    {
      key: "status",
      header: "Status",
      width: "92px",
      cell: (p) => (
        <Badge tone={p.status === "Enabled" ? "success" : "neutral"}>
          {p.status || "—"}
        </Badge>
      ),
    },
    {
      key: "actions",
      header: "",
      align: "right",
      width: "158px",
      cell: (p) => (
        <div className="flex justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" variant="outline" className="w-8 px-0" aria-label={`Edit ${p.name}`} title="Edit" onClick={() => setEditing(p.id)}>
            <Edit3 />
          </Button>
          <Button size="sm" variant="outline" className="w-8 px-0" aria-label={`Promote ${p.name}`} title="Promote" disabled={busy === p.id} onClick={() => policyAction(p.id, "promote")}>
            <Globe2 />
          </Button>
          <Button size="sm" variant="outline" className="w-8 px-0" aria-label={`Merge ${p.name}`} title="Merge" disabled={busy === p.id} onClick={() => policyAction(p.id, "merge")}>
            <GitMerge />
          </Button>
          <Button size="sm" variant="outline" className="w-8 px-0" aria-label={`Deploy ${p.name}`} title="Deploy" disabled={busy === p.id} onClick={() => policyAction(p.id, "deploy")}>
            <UploadCloud />
          </Button>
        </div>
      ),
    },
  ];

  async function policyAction(policyId: string, action: "promote" | "merge" | "deploy") {
    setBusy(policyId);
    setNotice("");
    try {
      if (action === "promote") {
        const preview = await api.threatlocker.previewPolicyPromotion(tenantId, policyId);
        if (!window.confirm(`${preview.summary}. Apply this change?`)) return;
        const result = await api.threatlocker.promotePolicyGlobal(tenantId, policyId, preview.approvalToken);
        setNotice(`Promoted “${result.name}” to global. Merged ${result.mergedPolicyIds.length}; disabled ${result.disabledPolicyIds.length}.`);
      } else if (action === "merge") {
        const preview = await api.threatlocker.previewPolicyPromotion(tenantId, policyId);
        if (!window.confirm(`${preview.summary}. Apply this change?`)) return;
        const result = await api.threatlocker.promotePolicyGlobal(tenantId, policyId, preview.approvalToken);
        setNotice(`Merged ${result.mergedPolicyIds.length} matching policies into “${result.name}”. Disabled ${result.disabledPolicyIds.length}.`);
      } else {
        if (!tenantId) {
          setNotice("Template deployment still requires selecting a tenant-scoped workflow.");
          return;
        }
        const tpl = await api.threatlocker.promotePolicy({ tenantId, policyId });
        const preview = await api.threatlocker.previewTemplateDeploy(tpl.id, { all: true });
        if (!window.confirm(`${preview.summary} to all connected tenants. Apply this change?`)) return;
        const result = await api.threatlocker.deployTemplate(tpl.id, { all: true, approvalToken: preview.approvalToken });
        setNotice(`Deploy ${result.status.toLowerCase()}: ${(result.succeeded ?? []).length} succeeded, ${(result.failed ?? []).length} failed.`);
      }
      refresh();
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "Policy action failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <PageToolbar count={`${data?.length ?? 0} policies`}>
        <SearchInput
          placeholder="Search policies…"
          className="w-[220px]"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </PageToolbar>
      {notice && (
        <div className="mb-3 rounded-[8px] border border-[var(--border-card)] bg-raised/50 px-3 py-2 text-[12.5px] text-secondary">
          {notice}
        </div>
      )}
      <DataTable
        columns={columns}
        rows={rows}
        loading={loading}
        error={error}
        getRowId={(p) => p.id}
        emptyTitle="No policies match"
      />
      <PolicyEditModal
        tenantId={tenantId}
        policyId={editing}
        onClose={() => setEditing(null)}
        onSaved={refresh}
      />
    </>
  );
}

function NotConnectedPanel() {
  return (
    <div className="grid place-items-center rounded-[12px] border border-[var(--border-card)] bg-raised/40 px-6 py-16 text-center">
      <div className="grid size-12 place-items-center rounded-full bg-raised">
        <ShieldCheck className="size-6 text-muted" />
      </div>
      <h2 className="mt-4 text-[15px] font-bold text-fg-strong">
        Global ThreatLocker workspace is not configured
      </h2>
      <p className="mt-1.5 max-w-[440px] text-[12.5px] leading-relaxed text-muted">
        This workspace uses the MSP parent organization, not an individual
        tenant connection. Configure the global portal instance, API token, and
        parent organization ID on the server. A tenant can show “Organization
        configured” without enabling this global workspace.
      </p>
    </div>
  );
}

function DevicesTab({
  devices,
  tenantId,
}: {
  devices: RefreshingAsyncState<Device[]>;
  tenantId?: string;
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [q, setQ] = useState("");
  const [actionOpen, setActionOpen] = useState(false);
  const [detail, setDetail] = useState<Device | null>(null);

  const rows = (devices.data ?? []).filter(
    (d) =>
      d.hostname.toLowerCase().includes(q.toLowerCase()) ||
      d.group.toLowerCase().includes(q.toLowerCase()),
  );

  const exportCsv = () =>
    void downloadAuditedCsv(
      {
        kind: "threatlocker-devices",
        filename: "devices.csv",
        rowCount: rows.length,
        headers: ["Hostname", "Group", "OS", "Agent", "Mode", "Tamper Protection", "Last Check-in", "Online"],
        rows: rows.map((d) => [
          d.hostname, d.group, d.os, d.agentVersion, deviceModeLabel(d.mode),
          d.tamperProtection ? "On" : "Off", d.lastCheckIn, d.online ? "Yes" : "No",
        ]),
      },
      api.exports.generate,
    );

  const allChecked = rows.length > 0 && rows.every((d) => selected.has(d.id));
  const someChecked = rows.some((d) => selected.has(d.id));

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const toggleAll = () =>
    setSelected(allChecked ? new Set() : new Set(rows.map((d) => d.id)));

  const columns: Column<Device>[] = [
    {
      key: "sel",
      header: (
        <Checkbox
          checked={allChecked}
          indeterminate={!allChecked && someChecked}
          onChange={toggleAll}
          aria-label="Select all"
        />
      ),
      width: "44px",
      cell: (d) => (
        <span onClick={(e) => e.stopPropagation()}>
          <Checkbox
            checked={selected.has(d.id)}
            onChange={() => toggle(d.id)}
            aria-label={`Select ${d.hostname}`}
          />
        </span>
      ),
    },
    {
      key: "hostname",
      header: "Device",
      cell: (d) => (
        <div>
          <p className="font-semibold text-fg">{d.hostname}</p>
          <p className="text-[11.5px] text-muted">{d.group}</p>
        </div>
      ),
    },
    { key: "os", header: "OS", width: "90px", cell: (d) => <span className="capitalize">{d.os}</span> },
    { key: "agent", header: "Agent", width: "90px", cell: (d) => d.agentVersion },
    {
      key: "mode",
      header: "Mode",
      width: "140px",
      cell: (d) => <Badge tone={deviceModeTone(d.mode)}>{deviceModeLabel(d.mode)}</Badge>,
    },
    {
      key: "tamper",
      header: "Tamper Protection",
      width: "150px",
      cell: (d) => (
        <Badge tone={d.tamperProtection ? "success" : "danger"} dot={false}>
          {d.tamperProtection ? "On" : "Off"}
        </Badge>
      ),
    },
    {
      key: "checkin",
      header: "Last Check-in",
      width: "130px",
      cell: (d) => (
        <span className={d.online ? "text-secondary" : "text-muted"}>
          {d.online ? d.lastCheckIn : `${d.lastCheckIn} · offline`}
        </span>
      ),
    },
  ];

  return (
    <>
      <PageToolbar count={`${devices.data?.length ?? 0} devices`}>
        <SearchInput
          placeholder="Search devices…"
          className="w-[220px]"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <Button
          variant="default"
          onClick={exportCsv}
          disabled={devices.loading || rows.length === 0}
        >
          <Download className="size-4" />
          Export CSV
        </Button>
      </PageToolbar>

      <DataTable
        columns={columns}
        rows={rows}
        loading={devices.loading}
        error={devices.error}
        getRowId={(d) => d.id}
        isRowActive={(d) => selected.has(d.id)}
        onRowClick={(d) => setDetail(d)}
        emptyTitle="No devices match"
      />

      {selected.size > 0 && (
        <div className="fixed bottom-6 left-[calc(250px+50%-125px)] z-30 -translate-x-1/2 animate-pop">
          <div className="flex items-center gap-2 rounded-[12px] border border-[var(--border-strong)] bg-raised px-3 py-2 shadow-[0_14px_40px_rgba(0,0,0,.55)]">
            <span className="px-1.5 text-[13px] font-semibold text-fg">
              {selected.size} selected
            </span>
            <span className="h-5 w-px bg-white/10" />
            <Button
              variant="accent"
              size="sm"
              onClick={() => setActionOpen(true)}
              title="Run What If"
            >
              <Play className="size-3.5" />
              Run What If
            </Button>
            <Button variant="ghost" size="icon" aria-label="Clear" onClick={() => setSelected(new Set())}>
              <X className="size-4" />
            </Button>
          </div>
        </div>
      )}

      <DeviceActionDialog
        open={actionOpen}
        tenantId={tenantId}
        deviceIds={Array.from(selected)}
        onClose={() => setActionOpen(false)}
      />

      <DeviceDetailModal device={detail} onClose={() => setDetail(null)} />
    </>
  );
}

function requestTypeTone(t: ApprovalRequest["requestType"]) {
  return t === "elevation" ? "warning" : t === "storage" ? "info" : "neutral";
}

function ApprovalsTab({ approvals, tenantId }: { approvals: RefreshingAsyncState<ApprovalRequest[]>; tenantId?: string }) {
  const { data, loading, error } = approvals;
  const [detail, setDetail] = useState<ApprovalRequest | null>(null);

  const columns: Column<ApprovalRequest>[] = [
    {
      key: "app",
      header: "Application",
      cell: (r) => (
        <div>
          <p className="font-semibold text-fg">{r.application}</p>
          <p className="mono text-[11px] text-muted">{r.path}</p>
        </div>
      ),
    },
    {
      key: "type",
      header: "Type",
      width: "110px",
      cell: (r) => (
        <Badge tone={requestTypeTone(r.requestType)} dot={false}>
          <span className="capitalize">{r.requestType}</span>
        </Badge>
      ),
    },
    { key: "device", header: "Device", width: "140px", cell: (r) => r.deviceName },
    { key: "requester", header: "Requested by", cell: (r) => r.requester },
    { key: "at", header: "Requested", width: "140px", cell: (r) => r.requestedAt },
  ];

  return (
    <>
      <PageToolbar count={`${data?.length ?? 0} pending requests`} />
      <DataTable
        columns={columns}
        rows={data ?? []}
        loading={loading}
        error={error}
        getRowId={(r) => r.id}
        onRowClick={(r) => setDetail(r)}
        emptyTitle="No pending approval requests"
      />
      <ApprovalDetailModal
        request={detail}
        tenantId={tenantId}
        onClose={() => setDetail(null)}
      />
    </>
  );
}
