import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Download } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SearchInput } from "@/components/ui/input";
import { PageToolbar } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { changeTone } from "@/components/common/status";
import { cn } from "@/lib/utils";
import { downloadAuditedCsv } from "@/lib/csv";
import type { ChangeRecord } from "@/types";

const revertClass = (r: string) =>
  r === "Reverted" ? "text-[#79a8ff]" : r === "Available" ? "text-[#a2a2ab]" : "text-faint";

export function ChangeHistoryPage() {
  useSetPageTitle("Change History");
  const navigate = useNavigate();
  const { version: syncVersion } = useSync();
  const { data, loading, error } = useAsync(() => api.changes.list(), [syncVersion]);
  const [q, setQ] = useState("");

  const rows = (data ?? []).filter(
    (c) =>
      c.technician.toLowerCase().includes(q.toLowerCase()) ||
      c.action.toLowerCase().includes(q.toLowerCase()),
  );

  const exportCsv = () =>
    void downloadAuditedCsv(
      {
        kind: "change-history",
        filename: "change-history.csv",
        rowCount: rows.length,
        headers: ["Timestamp", "Technician", "Action", "Target", "Status", "Revert"],
        rows: rows.map((c) => [c.timestamp, c.technician, c.action, c.target, c.status, c.revert]),
      },
      api.exports.generate,
    );

  const columns: Column<ChangeRecord>[] = [
    { key: "ts", header: "Timestamp", width: "150px", cell: (c) => <span className="tabular text-secondary">{c.timestamp}</span> },
    { key: "tech", header: "Technician", cell: (c) => <span className="text-body">{c.technician}</span> },
    { key: "action", header: "Action", cell: (c) => <span className="font-semibold text-fg">{c.action}</span> },
    { key: "target", header: "Target", cell: (c) => <span className="text-secondary">{c.target}</span> },
    { key: "status", header: "Status", width: "110px", cell: (c) => <Badge tone={changeTone(c.status)}>{c.status}</Badge> },
    {
      key: "revert",
      header: "Revert",
      width: "120px",
      cell: (c) => <span className={cn("text-[12px] font-medium", revertClass(c.revert))}>{c.revert}</span>,
    },
  ];

  return (
    <div>
      <PageToolbar count="Last 50 changes">
        <SearchInput
          placeholder="Filter by technician…"
          className="w-[220px]"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <Button variant="default" onClick={exportCsv} disabled={loading || rows.length === 0}>
          <Download className="size-4" />
          Export CSV
        </Button>
      </PageToolbar>
      <DataTable
        columns={columns}
        rows={rows}
        loading={loading}
        error={error}
        getRowId={(c) => c.id}
        onRowClick={(c) => navigate(`/changes/${c.id}`)}
      />
    </div>
  );
}
