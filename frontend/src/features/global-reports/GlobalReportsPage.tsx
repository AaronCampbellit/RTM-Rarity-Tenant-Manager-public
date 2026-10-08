import { useState } from "react";
import { Download, ShieldCheck } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { PillTabs } from "@/components/ui/tabs";
import { DataTable, type Column } from "@/components/common/DataTable";
import { downloadAuditedCsv } from "@/lib/csv";
import type { GlobalReportCell } from "@/types";

const REPORTS = [
  { key: "mfa", label: "MFA Status" },
  { key: "license", label: "License Usage" },
  { key: "inactive", label: "Inactive Users" },
  { key: "guests", label: "Guest Accounts" },
  { key: "threatlocker", label: "ThreatLocker Posture" },
  // Entra readiness reviews — the pre-rollout / recertification checks.
  { key: "license-readiness", label: "License Readiness" },
  { key: "mfa-gaps", label: "MFA Gaps" },
  { key: "stale-guests", label: "Stale Guests" },
  { key: "privileged-roles", label: "Privileged Roles" },
  { key: "ca-exclusions", label: "CA Exclusions" },
  { key: "app-credentials", label: "App Credential Expiry" },
];

type Row = { cells: GlobalReportCell[]; _id: string };

export function GlobalReportsPage() {
  useSetPageTitle("Global Reports");
  const [report, setReport] = useState("mfa");
  const { version: syncVersion } = useSync();
  const { data, loading, error } = useAsync(
    () => api.globalReports.get(report),
    [report, syncVersion],
  );

  const columns: Column<Row>[] =
    data?.columns.map((c, ci) => ({
      key: `c${ci}`,
      header: c,
      // The first column is always Tenant (always visible per spec).
      cell: (row) => {
        const cell = row.cells[ci];
        if ("badge" in cell) return <Badge tone={cell.tone}>{cell.badge}</Badge>;
        return (
          <span className={ci === 0 ? "font-semibold text-fg" : "text-secondary"}>
            {cell.text}
          </span>
        );
      },
    })) ?? [];

  const rows: Row[] | undefined = data?.rows.map((cells, i) => ({
    cells,
    _id: `${report}-${i}`,
  }));

  const exportCsv = () => {
    if (!data) return;
    void downloadAuditedCsv(
      {
        kind: "global-report",
        filename: `report-${report}.csv`,
        rowCount: data.rows.length,
        headers: data.columns,
        rows: data.rows.map((cells) => cells.map((cell) => ("text" in cell ? cell.text : cell.badge))),
      },
      api.exports.generate,
    );
  };

  return (
    <div className="space-y-4">
      {/* READ-ONLY banner */}
      <div className="flex items-center justify-between gap-4 rounded-[12px] border border-[rgba(91,141,239,.3)] bg-[rgba(91,141,239,.1)] px-4 py-3">
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="size-5 text-[#79a8ff]" />
          <div>
            <p className="text-[13px] font-semibold text-fg-strong">
              Global Reporting · Read-only · Admin
            </p>
            <p className="text-[12px] text-secondary">
              Cross-tenant reports. No write actions are possible here. Exports are audited.
            </p>
          </div>
        </div>
        <span className="rounded-[6px] border border-[rgba(91,141,239,.4)] px-2.5 py-1 text-[11px] font-bold tracking-wide text-[#79a8ff]">
          READ-ONLY
        </span>
      </div>

      {/* report tabs + export */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <PillTabs tabs={REPORTS} value={report} onChange={setReport} />
        <Button variant="default" onClick={exportCsv} disabled={loading || !data}>
          <Download className="size-4" />
          Export (audited)
        </Button>
      </div>

      <DataTable
        columns={columns}
        rows={rows}
        loading={loading}
        error={error}
        getRowId={(r) => r._id}
      />
    </div>
  );
}
