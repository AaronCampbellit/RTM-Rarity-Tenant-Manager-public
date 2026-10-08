import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useTenant } from "@/store/tenant";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Badge } from "@/components/ui/badge";
import { Progress, utilColor } from "@/components/ui/progress";
import { SearchInput } from "@/components/ui/input";
import { PageToolbar } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { poolTone } from "@/components/common/status";
import type { License } from "@/types";

export function LicensingPage() {
  useSetPageTitle("Licensing");
  const { activeTenant, loading: tenantLoading } = useTenant();
  const { version: syncVersion } = useSync();
  const { data, loading, error } = useAsync(
    () => api.licenses.list(activeTenant?.id ?? ""),
    [activeTenant?.id, syncVersion],
    { enabled: Boolean(activeTenant?.id) },
  );

  const columns: Column<License>[] = [
    { key: "sku", header: "SKU", cell: (l) => <span className="mono text-[11.5px] text-secondary">{l.sku}</span> },
    { key: "product", header: "Product", cell: (l) => <span className="font-semibold text-fg">{l.product}</span> },
    { key: "assigned", header: "Assigned", align: "right", width: "90px", cell: (l) => l.assigned },
    { key: "available", header: "Available", align: "right", width: "90px", cell: (l) => l.available },
    {
      key: "util",
      header: "Utilization",
      width: "200px",
      cell: (l) => (
        <div className="flex items-center gap-2.5">
          <Progress value={l.utilization} color={utilColor(l.utilization)} className="w-[120px]" />
          <span className="tabular text-[12px] text-secondary">{l.utilization}%</span>
        </div>
      ),
    },
    { key: "pool", header: "Pool", width: "90px", cell: (l) => <Badge tone={poolTone(l.pool)}>{l.pool}</Badge> },
  ];

  return (
    <div>
      <PageToolbar count={`${data?.length ?? 0} SKUs`}>
        <SearchInput placeholder="Search licenses…" className="w-[220px]" />
      </PageToolbar>
      <DataTable columns={columns} rows={data} loading={tenantLoading || loading} error={error} getRowId={(l) => l.sku} />
    </div>
  );
}
