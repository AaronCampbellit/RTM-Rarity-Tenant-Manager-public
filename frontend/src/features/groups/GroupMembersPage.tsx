import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { AlertTriangle, Download, UserMinus, UserPlus, X } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useTenant } from "@/store/tenant";
import { useModals } from "@/store/modals";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { hasPermission, useAuth } from "@/store/auth";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Avatar } from "@/components/common/Avatar";
import { BackLink } from "@/components/common/PageToolbar";
import { DataTable, type Column } from "@/components/common/DataTable";
import { downloadAuditedCsv } from "@/lib/csv";
import { AddGroupMembersDialog } from "./AddGroupMembersDialog";
import type { GroupMember } from "@/types";

export function GroupMembersPage() {
  useSetPageTitle("Group Members");
  const { id } = useParams();
  const navigate = useNavigate();
  const { activeTenant, loading: tenantLoading } = useTenant();
  const { version: syncVersion } = useSync();
  const { openWhatIf } = useModals();
  const { user } = useAuth();
  const { data, loading, error } = useAsync(
    () => api.groups.members(activeTenant?.id ?? "", id ?? ""),
    [activeTenant?.id, id, syncVersion],
    { enabled: Boolean(activeTenant?.id && id) },
  );
  // The group header comes from the same live source as the Groups page.
  const groups = useAsync(
    () => api.groups.list(activeTenant?.id ?? ""),
    [activeTenant?.id, syncVersion],
    { enabled: Boolean(activeTenant?.id) },
  );
  const group = groups.data?.find((g) => g.id === id);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const rows = data ?? [];
  const membershipEditable = group?.membership === "Assigned" && group?.service !== "Exchange";

  const exportCsv = () =>
    void downloadAuditedCsv(
      {
        kind: "group-members",
        filename: "group-members.csv",
        rowCount: rows.length,
        tenantId: activeTenant?.id,
        headers: ["Member", "UPN", "Role", "Added"],
        rows: rows.map((m) => [m.name, m.upn, m.role, m.added]),
      },
      api.exports.generate,
    );

  const allChecked = rows.length > 0 && rows.every((m) => selected.has(m.id));
  const someChecked = rows.some((m) => selected.has(m.id));

  const toggle = (memberId: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(memberId) ? next.delete(memberId) : next.add(memberId);
      return next;
    });

  const toggleAll = () =>
    setSelected(allChecked ? new Set() : new Set(rows.map((m) => m.id)));

  async function removeSelected() {
    setBusy(true);
    setRemoveError(null);
    const body = {
      action: "remove_from_group" as const,
      tenantId: activeTenant?.id ?? "",
      groupId: id ?? "",
      userIds: Array.from(selected),
    };
    try {
      const preview = await api.changes.preview(body);
      setBusy(false);
      setSelected(new Set());
      openWhatIf({ preview, execute: () => api.changes.execute(body, preview.approvalToken) });
    } catch (err) {
      setBusy(false);
      setRemoveError(
        err instanceof RtmApiError
          ? err.message
          : "Could not generate the preview. Please try again.",
      );
    }
  }

  const columns: Column<GroupMember>[] = [
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
        <Checkbox checked={selected.has(m.id)} onChange={() => toggle(m.id)} aria-label={`Select ${m.name}`} />
      ),
    },
    {
      key: "name",
      header: "Member",
      cell: (m) => (
        <div className="flex items-center gap-2.5">
          <Avatar name={m.name} />
          <span className="font-semibold text-fg">{m.name}</span>
        </div>
      ),
    },
    { key: "upn", header: "UPN", cell: (m) => <span className="text-secondary">{m.upn}</span> },
    {
      key: "role",
      header: "Role",
      width: "100px",
      cell: (m) => (
        <Badge tone={m.role === "Owner" ? "info" : "neutral"} dot={false}>
          {m.role}
        </Badge>
      ),
    },
    { key: "added", header: "Added", width: "120px", cell: (m) => <span className="tabular text-secondary">{m.added}</span> },
  ];

  return (
    <div className="pb-16">
      <BackLink onClick={() => navigate("/groups")}>Groups</BackLink>

      <div className="mb-4 flex items-center justify-between gap-4">
        <div>
          <h2 className="text-[18px] font-bold text-fg-strong">{group?.name ?? "…"}</h2>
          <p className="text-[12.5px] text-muted">
            {group ? `${group.type} group` : ""}
            {data ? ` · ${data.length} members` : ""}
          </p>
        </div>
        <div className="flex gap-2">
          {hasPermission(user, "changes.execute") && membershipEditable && (
            <Button variant="accent" onClick={() => setAdding(true)}>
              <UserPlus className="size-4" />
              Add users
            </Button>
          )}
          <Button variant="default" onClick={exportCsv} disabled={loading || rows.length === 0}>
            <Download className="size-4" />
            Export CSV
          </Button>
        </div>
      </div>

      <DataTable
        columns={columns}
        rows={data}
        loading={tenantLoading || loading}
        error={error}
        getRowId={(m) => m.id}
        isRowActive={(m) => selected.has(m.id)}
      />
      {group && !membershipEditable && (
        <p className="mt-3 text-[12px] text-muted">
          {group.membership === "Dynamic"
            ? "Dynamic membership is controlled by the group rule and cannot be edited manually."
            : "Exchange-managed group membership must be changed through Exchange Online."}
        </p>
      )}

      {removeError && (
        <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>{removeError}</span>
        </div>
      )}

      {/* Floating action bar — appears when ≥1 member selected */}
      {selected.size > 0 && (
        <div className="fixed bottom-6 left-[calc(250px+50%-125px)] z-30 -translate-x-1/2 animate-pop">
          <div className="flex items-center gap-2 rounded-[12px] border border-[var(--border-strong)] bg-raised px-3 py-2 shadow-[0_14px_40px_rgba(0,0,0,.55)]">
            <span className="px-1.5 text-[13px] font-semibold text-fg">
              {selected.size} selected
            </span>
            <span className="h-5 w-px bg-white/10" />
            <Button variant="accent" size="sm" onClick={removeSelected} disabled={busy}>
              <UserMinus className="size-3.5" />
              Remove from group
            </Button>
            <Button variant="ghost" size="icon" aria-label="Clear" onClick={() => setSelected(new Set())}>
              <X className="size-4" />
            </Button>
          </div>
        </div>
      )}

      {adding && group && (
        <AddGroupMembersDialog
          tenantId={activeTenant?.id ?? ""}
          groupId={group.id}
          groupName={group.name}
          existingMemberIds={rows.map((member) => member.id)}
          onClose={() => setAdding(false)}
        />
      )}
    </div>
  );
}
