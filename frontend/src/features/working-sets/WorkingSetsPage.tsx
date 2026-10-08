import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronRight, Plus, Sparkles } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useSetPageTitle } from "@/store/page";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { PageToolbar } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import type { WorkingSet } from "@/types";
import { useTenant } from "@/store/tenant";
import { WorkingSetDetailDialog } from "./WorkingSetDetailDialog";

export function WorkingSetsPage() {
  useSetPageTitle("Working Sets");
  const navigate = useNavigate();
  const { setActiveTenant } = useTenant();
  const [refreshKey, setRefreshKey] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const { data, loading, error } = useAsync(() => api.workingSets.list(), [refreshKey]);

  const columns: Column<WorkingSet>[] = [
    {
      key: "name",
      header: "Name",
      cell: (w) => (
        <span className="flex min-w-0 flex-col">
          <span className="font-semibold text-fg">{w.name}</span>
          {w.description && <span className="truncate text-[12px] text-muted">{w.description}</span>}
        </span>
      ),
    },
    { key: "type", header: "Type", cell: (w) => <Badge tone="info" dot={false}>{w.type}</Badge> },
    { key: "items", header: "Items", align: "right", width: "80px", cell: (w) => w.items.toLocaleString() },
    { key: "tenant", header: "Tenant", cell: (w) => <span className="text-secondary">{w.tenant}</span> },
    { key: "by", header: "Created By", cell: (w) => <span className="text-secondary">{w.createdBy}</span> },
    { key: "used", header: "Last Used", width: "110px", cell: (w) => <span className="text-secondary">{w.lastUsed}</span> },
    { key: "open", header: "", width: "40px", cell: () => <ChevronRight className="size-4 text-faint" /> },
  ];

  return (
    <div>
      <PageToolbar count={`${data?.length ?? 0} working sets`}>
        <Button variant="accent" onClick={() => navigate("/users")}>
          <Plus className="size-4" />
          New Working Set
        </Button>
      </PageToolbar>
      <DataTable
        columns={columns}
        rows={data}
        loading={loading}
        error={error}
        getRowId={(w) => w.id}
        onRowClick={(workingSet) => setSelectedId(workingSet.id)}
        emptyTitle="No working sets yet"
        emptyHint="Select users from a report or search, then Save as Working Set."
      />
      <p className="mt-3 flex items-center gap-1.5 text-[12px] text-muted">
        <Sparkles className="size-3.5" />
        Working Sets retain the exact selected user IDs and tenant so the scope
        survives sign-out, reloads, and service restarts.
      </p>
      {selectedId && (
        <WorkingSetDetailDialog
          workingSetId={selectedId}
          onClose={() => setSelectedId(null)}
          onSaved={() => setRefreshKey((key) => key + 1)}
          onOpenUsers={(workingSet) => {
            setActiveTenant(workingSet.tenantId);
            setSelectedId(null);
            navigate(`/users?workingSet=${encodeURIComponent(workingSet.id)}`);
          }}
        />
      )}
    </div>
  );
}
