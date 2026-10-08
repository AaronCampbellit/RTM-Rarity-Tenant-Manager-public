import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronRight, Plus } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { hasPermission, useAuth } from "@/store/auth";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SearchInput } from "@/components/ui/input";
import { PageToolbar } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { tenantTone } from "@/components/common/status";
import { AddTenantModal } from "./AddTenantModal";
import type { Tenant } from "@/types";

export function TenantsPage() {
  useSetPageTitle("Tenants");
  const navigate = useNavigate();
  const { user } = useAuth();
  const { version: syncVersion } = useSync();
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, loading, error } = useAsync(() => api.tenants.list(), [refreshKey, syncVersion]);
  const [q, setQ] = useState("");
  const [adding, setAdding] = useState(false);

  const rows = data?.filter(
    (t) =>
      t.name.toLowerCase().includes(q.toLowerCase()) ||
      t.domain.toLowerCase().includes(q.toLowerCase()),
  );

  const columns: Column<Tenant>[] = [
    {
      key: "name",
      header: "Tenant",
      cell: (t) => (
        <div>
          <p className="font-semibold text-fg">{t.name}</p>
          <p className="text-[11.5px] text-muted">{t.domain}</p>
        </div>
      ),
    },
    {
      key: "mid",
      header: "Microsoft Tenant ID",
      cell: (t) => <span className="mono text-[11.5px] text-secondary">{t.microsoftTenantId}</span>,
    },
    {
      key: "status",
      header: "Status",
      cell: (t) => <Badge tone={tenantTone(t.status)}>{t.status}</Badge>,
    },
    {
      key: "users",
      header: "Users",
      align: "right",
      width: "90px",
      cell: (t) => t.users.toLocaleString(),
    },
    {
      key: "test",
      header: "Last Graph Test",
      width: "130px",
      cell: (t) => <span className="text-secondary">{t.lastGraphTest}</span>,
    },
    {
      key: "chev",
      header: "",
      width: "40px",
      cell: () => <ChevronRight className="size-4 text-faint" />,
    },
  ];

  return (
    <div>
      <PageToolbar count={`${data?.length ?? 0} tenants`}>
        <SearchInput
          placeholder="Filter tenants…"
          className="w-[220px]"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        {hasPermission(user, "tenants.manage") && (
          <Button variant="accent" onClick={() => setAdding(true)}>
            <Plus className="size-4" />
            Add Tenant
          </Button>
        )}
      </PageToolbar>
      <DataTable
        columns={columns}
        rows={rows}
        loading={loading}
        error={error}
        getRowId={(t) => t.id}
        onRowClick={(t) => navigate(`/tenants/${t.id}`)}
        emptyTitle="No tenants match"
      />
      <AddTenantModal
        open={adding}
        onClose={() => setAdding(false)}
        onCreated={() => setRefreshKey((k) => k + 1)}
      />
    </div>
  );
}
