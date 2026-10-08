import { useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress, utilColor } from "@/components/ui/progress";
import { PillTabs } from "@/components/ui/tabs";
import { PageToolbar } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { jobTone } from "@/components/common/status";
import type { Job } from "@/types";

const FILTERS = [
  { key: "all", label: "All" },
  { key: "Running", label: "Running" },
  { key: "Queued", label: "Queued" },
  { key: "Completed", label: "Completed" },
  { key: "Failed", label: "Failed" },
];

export function JobsPage() {
  useSetPageTitle("Jobs");
  const { version: syncVersion, requestSync } = useSync();
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, loading, error } = useAsync(() => api.jobs.list(), [syncVersion, refreshKey]);
  const [filter, setFilter] = useState("all");
  const [acking, setAcking] = useState<string | null>(null);

  const rows = data?.filter((j) => filter === "all" || j.status === filter);
  const needsAck = (j: Job) => ["Failed", "Partial"].includes(j.status) && !j.acknowledged;

  async function acknowledge(jobId: string) {
    setAcking(jobId);
    try {
      await api.jobs.acknowledge(jobId);
      setRefreshKey((x) => x + 1);
      requestSync();
    } finally {
      setAcking(null);
    }
  }

  const columns: Column<Job>[] = [
    { key: "id", header: "Job ID", width: "120px", cell: (j) => <span className="mono text-[11.5px] text-secondary">{j.id}</span> },
    { key: "type", header: "Type", cell: (j) => <span className="font-semibold text-fg">{j.type}</span> },
    { key: "tenant", header: "Tenant", cell: (j) => <span className="text-secondary">{j.tenant}</span> },
    { key: "status", header: "Status", width: "120px", cell: (j) => <Badge tone={jobTone(j.status)}>{j.status}</Badge> },
    {
      key: "progress",
      header: "Progress",
      width: "160px",
      cell: (j) => (
        <div className="flex items-center gap-2">
          <Progress
            value={j.progress}
            color={j.status === "Failed" ? "#f7868a" : j.status === "Partial" ? "#e3b341" : utilColor(0)}
            className="w-[90px]"
          />
          <span className="tabular text-[12px] text-muted">{j.progress}%</span>
        </div>
      ),
    },
    { key: "started", header: "Started", width: "90px", cell: (j) => <span className="tabular text-secondary">{j.started}</span> },
    { key: "dur", header: "Duration", align: "right", width: "90px", cell: (j) => <span className="text-secondary">{j.duration}</span> },
    { key: "by", header: "Triggered By", width: "120px", cell: (j) => <span className="text-secondary">{j.triggeredBy}</span> },
    {
      key: "ack",
      header: "",
      align: "right",
      width: "126px",
      cell: (j) =>
        needsAck(j) ? (
          <Button size="sm" variant="outline" disabled={acking === j.id} onClick={() => acknowledge(j.id)}>
            <CheckCircle2 /> Acknowledge
          </Button>
        ) : j.acknowledged ? (
          <span className="text-[12px] text-muted">Acknowledged</span>
        ) : null,
    },
  ];

  return (
    <div>
      <PageToolbar count={`${data?.length ?? 0} jobs`}>
        <PillTabs tabs={FILTERS} value={filter} onChange={setFilter} />
      </PageToolbar>
      <DataTable columns={columns} rows={rows} loading={loading} error={error} getRowId={(j) => j.id} />
    </div>
  );
}
