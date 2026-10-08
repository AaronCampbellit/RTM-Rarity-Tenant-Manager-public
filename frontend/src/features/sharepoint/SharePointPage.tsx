import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  File,
  Folder,
  HardDrive,
  Library,
  Loader2,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useRefreshingAsync } from "@/api/hooks";
import { useTenant } from "@/store/tenant";
import { useSetPageTitle } from "@/store/page";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { UnderlineTabs } from "@/components/ui/tabs";
import { DataTable, type Column } from "@/components/common/DataTable";
import { ShareDetectivePage } from "@/features/share-detective/ShareDetectivePage";
import { ScopePermissionsModal } from "./ScopePermissionsModal";
import type {
  SharePointInventoryNode,
  SharePointInventoryScope,
  SharePointScan,
  StatusTone,
} from "@/types";

const TABS = [
  { key: "sites", label: "Sites" },
  { key: "onedrive", label: "OneDrive" },
  { key: "investigations", label: "Access Investigations" },
  { key: "history", label: "Scan History" },
];

type WorkspaceTab = (typeof TABS)[number]["key"];

export function SharePointPage() {
  useSetPageTitle("SharePoint");
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab") as WorkspaceTab | null;
  const tab = TABS.some((item) => item.key === requested) ? requested! : "sites";
  const { activeTenant, loading: tenantLoading } = useTenant();
  const tenantId = activeTenant?.id ?? "";

  function changeTab(next: string) {
    setParams(next === "sites" ? {} : { tab: next });
  }

  if (tenantLoading || !tenantId) {
    return <div className="grid min-h-64 place-items-center"><Loader2 className="size-5 animate-spin text-muted" aria-label="Loading tenant context" /></div>;
  }

  return (
    <div className="pb-16">
      <div className="mb-4 rounded-[12px] border border-[var(--border-card)] bg-card px-4 pt-2">
        <div className="flex items-center justify-between gap-4 py-2">
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">SharePoint administration</h2>
            <p className="text-[12px] text-muted">
              Persistent inventory, effective access, permission management, and offboarding investigations.
            </p>
          </div>
          <Badge tone="info" dot={false}>Graph + SharePoint REST</Badge>
        </div>
        <UnderlineTabs tabs={TABS} value={tab} onChange={changeTab} />
      </div>

      {tab === "sites" && <InventoryPanel tenantId={tenantId} scope="sites" />}
      {tab === "onedrive" && <InventoryPanel tenantId={tenantId} scope="onedrive" />}
      {tab === "investigations" && <ShareDetectivePage embedded />}
      {tab === "history" && <ScanHistory tenantId={tenantId} />}
    </div>
  );
}

function InventoryPanel({ tenantId, scope }: { tenantId: string; scope: "sites" | "onedrive" }) {
  const inventory = useRefreshingAsync(
    () => api.sharepoint.inventory(tenantId, scope),
    [tenantId, scope],
    { cacheKey: `sharepoint-inventory:${tenantId}:${scope}`, enabled: Boolean(tenantId) },
  );
  const scans = useRefreshingAsync(
    () => api.sharepoint.scans(tenantId),
    [tenantId],
    { intervalMs: 1500, cacheKey: `sharepoint-scans:${tenantId}`, enabled: Boolean(tenantId) },
  );
  const [selected, setSelected] = useState<SharePointInventoryNode | null>(null);
  const [starting, setStarting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const latest = scans.data?.find((scan) => scan.scope === scope);

  useEffect(() => {
    if (latest?.status === "completed" || latest?.status === "partial") {
      inventory.refresh();
    }
  }, [latest?.id, latest?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  async function startScan() {
    setStarting(true);
    setNotice(null);
    try {
      await api.sharepoint.startScan(tenantId, { scope });
      scans.refresh();
      setNotice("Inventory scan started. This view will refresh when the snapshot completes.");
    } catch (err) {
      setNotice(err instanceof RtmApiError ? err.message : "Could not start the inventory scan.");
    } finally {
      setStarting(false);
    }
  }

  async function scanFiles(node: SharePointInventoryNode) {
    setStarting(true);
    setNotice(null);
    try {
      await api.sharepoint.startScan(tenantId, {
        scope: "file_permissions",
        siteId: node.siteId ?? node.id,
        nodeId: node.id,
      });
      scans.refresh();
      setNotice(`File-permission scan started for ${node.name}. Track it in Scan History.`);
    } catch (err) {
      setNotice(err instanceof RtmApiError ? err.message : "Could not start the file-permission scan.");
    } finally {
      setStarting(false);
    }
  }

  const nodes = useMemo(
    () => [...(inventory.data?.nodes ?? [])].sort((a, b) => {
      const site = (a.siteId ?? a.id).localeCompare(b.siteId ?? b.id);
      if (site !== 0) return site;
      const rank = { site: 0, library: 1, folder: 2, file: 3 };
      return rank[a.kind] - rank[b.kind] || a.path.localeCompare(b.path);
    }),
    [inventory.data?.nodes],
  );

  const columns: Column<SharePointInventoryNode>[] = [
    {
      key: "name",
      header: scope === "onedrive" ? "OneDrive / Library / Folder" : "Site / Library / Folder",
      cell: (node) => <NodeName node={node} />,
    },
    {
      key: "permissions",
      header: "Permissions",
      width: "150px",
      cell: (node) => node.hasUniquePermissions
        ? <Badge tone="warning" dot={false}>Unique</Badge>
        : <Badge tone="neutral" dot={false}>Inherited</Badge>,
    },
    {
      key: "size",
      header: "Size",
      align: "right",
      width: "110px",
      cell: (node) => formatBytes(node.sizeBytes),
    },
    {
      key: "files",
      header: "Files",
      align: "right",
      width: "100px",
      cell: (node) => node.fileCount.toLocaleString(),
    },
    {
      key: "scanned",
      header: "Last Scanned",
      width: "150px",
      cell: (node) => formatDate(node.lastScannedAt),
    },
  ];

  if (inventory.loading && !inventory.data) {
    return <LoadingCard label={`Loading ${scope === "sites" ? "site" : "OneDrive"} inventory…`} />;
  }

  const noSnapshot = inventory.error instanceof RtmApiError && inventory.error.status === 404;
  if (noSnapshot) {
    return (
      <Card className="grid min-h-[280px] place-items-center p-8 text-center">
        <div>
          <Database className="mx-auto size-8 text-faint" />
          <h3 className="mt-3 text-[14px] font-semibold text-fg">No persisted snapshot yet</h3>
          <p className="mt-1 max-w-md text-[12.5px] text-muted">
            Start the first {scope === "sites" ? "SharePoint site" : "OneDrive"} inventory scan.
          </p>
          <Button variant="accent" className="mt-4" disabled={starting} onClick={() => void startScan()}>
            {starting ? <Loader2 className="animate-spin" /> : <RefreshCw />} Start Scan
          </Button>
        </div>
      </Card>
    );
  }

  if (inventory.error && !inventory.data) {
    return <ErrorCard error={inventory.error.message} />;
  }

  const scan = inventory.data?.scan;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Metric label={scope === "sites" ? "Sites" : "OneDrives"} value={scan?.siteCount ?? 0} />
        <Metric label="Libraries" value={scan?.libraryCount ?? 0} />
        <Metric label="Folders" value={scan?.folderCount ?? 0} />
        <Metric label="Files" value={scan?.fileCount ?? 0} />
        <Metric label="Total size" value={formatBytes(scan?.totalBytes ?? 0)} />
        <Metric label="Unique scopes" value={scan?.uniquePermissionCount ?? 0} tone={(scan?.uniquePermissionCount ?? 0) > 0 ? "warning" : undefined} />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-[12px] text-muted">
          {scan?.coverage === "complete" ? <CheckCircle2 className="size-4 text-[#65c98a]" /> : <ShieldAlert className="size-4 text-[#e3b341]" />}
          Snapshot {formatDate(scan?.completedAt ?? scan?.startedAt ?? "")}
          {scan && <Badge tone={scanTone(scan.status)}>{scan.status}</Badge>}
        </div>
        <Button variant="default" disabled={starting || latest?.status === "queued" || latest?.status === "running"} onClick={() => void startScan()}>
          {starting || latest?.status === "running" ? <Loader2 className="animate-spin" /> : <RefreshCw />}
          Rescan
        </Button>
      </div>

      {(scan?.warnings ?? []).map((warning) => (
        <div key={warning} className="flex items-start gap-2 rounded-[10px] border border-[rgba(210,161,6,.35)] bg-[rgba(210,161,6,.08)] px-3.5 py-2.5 text-[12.5px] text-[#e3b341]">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" /> {warning}
        </div>
      ))}
      {notice && <div className="rounded-[10px] border border-[var(--border-card)] bg-card px-3.5 py-2.5 text-[12.5px] text-secondary">{notice}</div>}

      <DataTable
        columns={columns}
        rows={nodes}
        loading={inventory.refreshing}
        getRowId={(node) => node.id}
        onRowClick={setSelected}
        isRowActive={(node) => node.id === selected?.id}
        emptyTitle="The completed scan returned no inventory"
        emptyHint="Review scan warnings and the tenant permission preflight."
      />

      <ScopePermissionsModal
        node={selected}
        tenantId={tenantId}
        onClose={() => setSelected(null)}
        onScanFiles={scanFiles}
      />
    </div>
  );
}

function ScanHistory({ tenantId }: { tenantId: string }) {
  const scans = useRefreshingAsync(
    () => api.sharepoint.scans(tenantId),
    [tenantId],
    { intervalMs: 1500, cacheKey: `sharepoint-scans:${tenantId}`, enabled: Boolean(tenantId) },
  );
  const columns: Column<SharePointScan>[] = [
    {
      key: "scope",
      header: "Scope",
      cell: (scan) => (
        <div>
          <p className="font-semibold text-fg">{scopeLabel(scan.scope)}</p>
          <p className="text-[11px] text-muted">{scan.siteId || "Tenant-wide"} · {scan.trigger}</p>
        </div>
      ),
    },
    { key: "status", header: "Status", width: "120px", cell: (scan) => <Badge tone={scanTone(scan.status)}>{scan.status}</Badge> },
    { key: "started", header: "Started", width: "170px", cell: (scan) => formatDate(scan.startedAt) },
    { key: "by", header: "Started By", width: "140px", cell: (scan) => scan.startedBy },
    { key: "coverage", header: "Coverage", width: "120px", cell: (scan) => scan.coverage },
    {
      key: "objects",
      header: "Objects",
      align: "right",
      width: "120px",
      cell: (scan) => (scan.siteCount + scan.libraryCount + scan.folderCount + scan.fileCount).toLocaleString(),
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={scans.data}
      loading={scans.loading || scans.refreshing}
      error={scans.error}
      getRowId={(scan) => scan.id}
      emptyTitle="No SharePoint scans have run"
    />
  );
}

function NodeName({ node }: { node: SharePointInventoryNode }) {
  const Icon = node.kind === "site" ? HardDrive : node.kind === "library" ? Library : node.kind === "folder" ? Folder : File;
  const indent = node.kind === "site" ? 0 : node.kind === "library" ? 18 : node.kind === "folder" ? 36 : 54;
  return (
    <div className="flex items-center gap-2.5" style={{ paddingLeft: indent }}>
      <Icon className="size-4 shrink-0 text-muted" />
      <div className="min-w-0">
        <p className="truncate font-semibold text-fg">{node.name}</p>
        <p className="truncate text-[11px] text-muted">{node.kind} · {node.path}</p>
      </div>
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: string | number; tone?: StatusTone }) {
  return (
    <Card className="p-4">
      <p className="text-[10.5px] font-bold uppercase tracking-[.5px] text-faint">{label}</p>
      <p className={`mt-1 text-[18px] font-bold ${tone === "warning" ? "text-[#e3b341]" : "text-fg-strong"}`}>{value}</p>
    </Card>
  );
}

function LoadingCard({ label }: { label: string }) {
  return <Card className="flex min-h-[240px] items-center justify-center gap-2 text-[13px] text-muted"><Loader2 className="size-5 animate-spin" /> {label}</Card>;
}

function ErrorCard({ error }: { error: string }) {
  return <Card className="flex min-h-[220px] items-center justify-center gap-2 p-6 text-[13px] text-[#f7868a]"><AlertTriangle className="size-5" /> {error}</Card>;
}

function scanTone(status: SharePointScan["status"]): StatusTone {
  if (status === "completed") return "success";
  if (status === "partial") return "warning";
  if (status === "failed") return "danger";
  return "info";
}

function scopeLabel(scope: SharePointInventoryScope) {
  if (scope === "onedrive") return "OneDrive inventory";
  if (scope === "file_permissions") return "File permission scan";
  return "SharePoint sites";
}

function formatBytes(bytes: number) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index > 2 ? 1 : 0)} ${units[index]}`;
}

function formatDate(value: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}
