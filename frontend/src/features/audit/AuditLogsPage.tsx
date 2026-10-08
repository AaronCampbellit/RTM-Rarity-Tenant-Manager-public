import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Badge } from "@/components/ui/badge";
import { SearchInput } from "@/components/ui/input";
import { PageToolbar } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { auditTone } from "@/components/common/status";
import type { AuditEntry } from "@/types";

export function AuditLogsPage() {
  useSetPageTitle("Audit Logs");
  const { version: syncVersion } = useSync();
  const { data, loading, error } = useAsync(() => api.audit.list(), [syncVersion]);
  const [q, setQ] = useState("");

  const rows = data?.filter((a) =>
    [a.actor, a.action, a.resource, a.result, a.correlationId].some((v) =>
      v.toLowerCase().includes(q.toLowerCase()),
    ),
  );

  const columns: Column<AuditEntry>[] = [
    { key: "ts", header: "Time", width: "90px", cell: (a) => <span className="tabular text-secondary">{a.timestamp}</span> },
    { key: "actor", header: "Actor", cell: (a) => <span className="text-body">{a.actor}</span> },
    { key: "action", header: "Action", cell: (a) => <span className="mono text-[12px] text-fg">{a.action}</span> },
    { key: "resource", header: "Resource", cell: (a) => <span className="text-secondary">{a.resource}</span> },
    { key: "result", header: "Result", width: "100px", cell: (a) => <Badge tone={auditTone(a.result)}>{a.result}</Badge> },
    { key: "corr", header: "Correlation ID", width: "130px", cell: (a) => <span className="mono text-[11.5px] text-muted">{a.correlationId}</span> },
  ];

  return (
    <div>
      <div className="mb-3.5 flex items-center gap-2 text-[12.5px] text-muted">
        <ShieldCheck className="size-4 text-[#79a8ff]" />
        Immutable audit trail — every sensitive action is recorded.
      </div>
      <PageToolbar count={`${data?.length ?? 0} events`}>
        <SearchInput
          placeholder="Search actor, action, resource…"
          className="w-[260px]"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </PageToolbar>
      <DataTable columns={columns} rows={rows} loading={loading} error={error} getRowId={(a) => a.id} />
    </div>
  );
}
