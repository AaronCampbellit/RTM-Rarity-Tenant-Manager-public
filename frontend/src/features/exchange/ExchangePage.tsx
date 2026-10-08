import { useState } from "react";
import { AlertTriangle, Download, Play, X } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useTenant } from "@/store/tenant";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { SearchInput } from "@/components/ui/input";
import { PageToolbar } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { downloadAuditedCsv } from "@/lib/csv";
import { ExchangeActionDialog } from "./ExchangeActionDialog";
import { MailboxDetailModal } from "./MailboxDetailModal";
import type { Mailbox } from "@/types";

export function ExchangePage() {
  useSetPageTitle("Exchange");
  const { activeTenant, loading: tenantLoading } = useTenant();
  const { version: syncVersion } = useSync();
  const { data, loading, error } = useAsync(
    () => api.exchange.mailboxes(activeTenant?.id ?? ""),
    [activeTenant?.id, syncVersion],
    { enabled: Boolean(activeTenant?.id) },
  );

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [q, setQ] = useState("");
  const [actionOpen, setActionOpen] = useState(false);
  const [detail, setDetail] = useState<Mailbox | null>(null);

  const rows = (data ?? []).filter(
    (m) =>
      m.name.toLowerCase().includes(q.toLowerCase()) ||
      m.email.toLowerCase().includes(q.toLowerCase()),
  );
  const usageUnavailable = (data ?? []).filter((mailbox) => !mailbox.usageAvailable);
  const usageDetail = usageUnavailable[0]?.usageDetail;

  const exportCsv = () =>
    void downloadAuditedCsv(
      {
        kind: "mailboxes",
        filename: "mailboxes.csv",
        rowCount: rows.length,
        tenantId: activeTenant?.id,
        headers: ["Mailbox", "Email", "Type", "Size", "Items", "Archive", "Litigation Hold"],
        rows: rows.map((m) => [m.name, m.email, m.type, m.size, m.usageAvailable ? String(m.items) : "", m.archive, m.litigationHold]),
      },
      api.exports.generate,
    );

  const allChecked = rows.length > 0 && rows.every((m) => selected.has(m.id));
  const someChecked = rows.some((m) => selected.has(m.id));

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const toggleAll = () =>
    setSelected(allChecked ? new Set() : new Set(rows.map((m) => m.id)));

  const columns: Column<Mailbox>[] = [
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
      cell: (m) => (
        <span onClick={(e) => e.stopPropagation()}>
          <Checkbox
            checked={selected.has(m.id)}
            onChange={() => toggle(m.id)}
            aria-label={`Select ${m.name}`}
          />
        </span>
      ),
    },
    {
      key: "name",
      header: "Mailbox",
      cell: (m) => (
        <div>
          <p className="font-semibold text-fg">{m.name}</p>
          <p className="text-[11.5px] text-muted">{m.email}</p>
        </div>
      ),
    },
    {
      key: "type",
      header: "Type",
      cell: (m) => (
        <Badge tone={m.type === "User" ? "info" : "neutral"} dot={false}>
          {m.type === "Unknown" ? "Not collected" : m.type}
        </Badge>
      ),
    },
    { key: "size", header: "Size", align: "right", width: "110px", cell: (m) => m.usageAvailable ? m.size : <span className="text-muted">Not collected</span> },
    { key: "items", header: "Items", align: "right", width: "110px", cell: (m) => m.usageAvailable ? m.items.toLocaleString() : <span className="text-muted">Not collected</span> },
    {
      key: "archive",
      header: "Archive",
      width: "125px",
      cell: (m) => <Badge tone={m.archive === "On" ? "success" : "neutral"}>{m.archive === "—" ? "Not collected" : m.archive}</Badge>,
    },
    {
      key: "hold",
      header: "Litigation Hold",
      width: "130px",
      cell: (m) => (
        <Badge tone={m.litigationHold === "Yes" ? "warning" : "neutral"} dot={false}>
          {m.litigationHold === "—" ? "Not collected" : m.litigationHold}
        </Badge>
      ),
    },
  ];

  return (
    <div className="pb-16">
      <PageToolbar count={`${data?.length ?? 0} mailboxes`}>
        <SearchInput
          placeholder="Search mailboxes…"
          className="w-[220px]"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <Button variant="default" onClick={exportCsv} disabled={loading || rows.length === 0}>
          <Download className="size-4" />
          Export CSV
        </Button>
      </PageToolbar>

      {usageUnavailable.length > 0 && usageDetail && (
        <div className="mb-4 flex items-start gap-3 rounded-[10px] border border-[var(--border-strong)] bg-raised/40 px-4 py-3">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-[var(--color-warning)]" />
          <div>
            <p className="text-[12.5px] font-semibold text-fg">
              Mailbox usage coverage {usageUnavailable.length === (data?.length ?? 0) ? "unavailable" : "is partial"}
            </p>
            <p className="mt-1 text-[11.5px] leading-5 text-muted">{usageDetail}</p>
            <p className="mt-1 text-[11px] text-faint">
              Litigation hold is Exchange Online-only and remains not collected until that connector is enabled.
            </p>
          </div>
        </div>
      )}

      <DataTable
        columns={columns}
        rows={rows}
        loading={tenantLoading || loading}
        error={error}
        getRowId={(m) => m.id}
        isRowActive={(m) => selected.has(m.id)}
        onRowClick={(m) => setDetail(m)}
        emptyTitle="No mailboxes match"
      />

      {/* Floating action bar — appears when ≥1 mailbox selected */}
      {selected.size > 0 && (
        <div className="fixed bottom-6 left-[calc(250px+50%-125px)] z-30 -translate-x-1/2 animate-pop">
          <div className="flex items-center gap-2 rounded-[12px] border border-[var(--border-strong)] bg-raised px-3 py-2 shadow-[0_14px_40px_rgba(0,0,0,.55)]">
            <span className="px-1.5 text-[13px] font-semibold text-fg">
              {selected.size} selected
            </span>
            <span className="h-5 w-px bg-white/10" />
            <Button variant="accent" size="sm" onClick={() => setActionOpen(true)}>
              <Play className="size-3.5" />
              Run What If
            </Button>
            <Button variant="ghost" size="icon" aria-label="Clear" onClick={() => setSelected(new Set())}>
              <X className="size-4" />
            </Button>
          </div>
        </div>
      )}

      <ExchangeActionDialog
        open={actionOpen}
        tenantId={activeTenant?.id ?? ""}
        mailboxIds={Array.from(selected)}
        onClose={() => setActionOpen(false)}
      />

      <MailboxDetailModal
        mailbox={detail}
        tenantId={activeTenant?.id ?? ""}
        onClose={() => setDetail(null)}
      />
    </div>
  );
}
