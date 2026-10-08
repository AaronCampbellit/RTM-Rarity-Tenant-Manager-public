import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronRight, Plus } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useTenant } from "@/store/tenant";
import { hasPermission, useAuth } from "@/store/auth";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SearchInput } from "@/components/ui/input";
import { PageToolbar } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { HybridNotice } from "@/components/common/HybridNotice";
import { sourceLabel, sourceTone } from "@/components/common/status";
import { CreateGroupModal } from "./CreateGroupModal";
import type { Group } from "@/types";

export function GroupsPage() {
  useSetPageTitle("Groups");
  const navigate = useNavigate();
  const { activeTenant, loading: tenantLoading } = useTenant();
  const { user } = useAuth();
  const { version: syncVersion } = useSync();
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, loading, error } = useAsync(
    () => api.groups.list(activeTenant?.id ?? ""),
    [activeTenant?.id, refreshKey, syncVersion],
    { enabled: Boolean(activeTenant?.id) },
  );
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(false);

  const rows = (data ?? []).filter((g) =>
    g.name.toLowerCase().includes(q.toLowerCase()),
  );

  const columns: Column<Group>[] = [
    {
      key: "name",
      header: "Group",
      cell: (g) => <span className="font-semibold text-fg">{g.name}</span>,
    },
    { key: "type", header: "Type", cell: (g) => <span className="text-secondary">{g.type}</span> },
    {
      key: "service",
      header: "Service",
      width: "100px",
      cell: (g) => (
        <Badge tone={g.service === "Exchange" ? "warning" : "info"} dot={false}>
          {g.service ?? "Graph"}
        </Badge>
      ),
    },
    {
      key: "membership",
      header: "Membership",
      cell: (g) => (
        <Badge tone={g.membership === "Dynamic" ? "info" : "neutral"} dot={false}>
          {g.membership}
        </Badge>
      ),
    },
    { key: "members", header: "Members", align: "right", width: "100px", cell: (g) => g.members.toLocaleString() },
    { key: "mail", header: "Mail", width: "70px", cell: (g) => <span className="text-secondary">{g.mail}</span> },
    {
      key: "source",
      header: "Source",
      width: "130px",
      cell: (g) => (
        <Badge tone={sourceTone(g.source)} dot={false}>
          {sourceLabel(g.source)}
        </Badge>
      ),
    },
    { key: "chev", header: "", width: "40px", cell: () => <ChevronRight className="size-4 text-faint" /> },
  ];

  const hasSynced = (data ?? []).some((g) => g.source === "On-prem sync");

  return (
    <div>
      <PageToolbar count={`${data?.length ?? 0} groups`}>
        <SearchInput
          placeholder="Search groups…"
          className="w-[220px]"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        {hasPermission(user, "changes.execute") && (
          <Button variant="accent" onClick={() => setCreating(true)}>
            <Plus className="size-4" />
            New Group
          </Button>
        )}
      </PageToolbar>
      {hasSynced && (
        <div className="mb-3">
          <HybridNotice mode="mixed" compact />
        </div>
      )}
      <DataTable
        columns={columns}
        rows={rows}
        loading={tenantLoading || loading}
        error={error}
        getRowId={(g) => g.id}
        onRowClick={(g) => navigate(`/groups/${g.id}/members`)}
        emptyTitle="No groups match"
      />
      <CreateGroupModal
        open={creating}
        tenantId={activeTenant?.id ?? ""}
        onClose={() => setCreating(false)}
        onCreated={() => {
          setCreating(false);
          setRefreshKey((k) => k + 1);
        }}
      />
    </div>
  );
}
