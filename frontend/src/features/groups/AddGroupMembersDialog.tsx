import { useMemo, useState } from "react";
import { AlertTriangle, Loader2, Search, UserPlus, Users2 } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useModals } from "@/store/modals";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Avatar } from "@/components/common/Avatar";

export function AddGroupMembersDialog({
  tenantId,
  groupId,
  groupName,
  existingMemberIds,
  onClose,
}: {
  tenantId: string;
  groupId: string;
  groupName: string;
  existingMemberIds: string[];
  onClose: () => void;
}) {
  const users = useAsync(() => api.users.list(tenantId), [tenantId]);
  const { openWhatIf } = useModals();
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const existing = useMemo(() => new Set(existingMemberIds), [existingMemberIds]);
  const available = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (users.data ?? []).filter((user) => {
      if (existing.has(user.id)) return false;
      if (!needle) return true;
      return `${user.name} ${user.upn} ${user.mail}`.toLowerCase().includes(needle);
    });
  }, [existing, query, users.data]);

  function toggle(userId: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(userId)) next.delete(userId);
      else next.add(userId);
      return next;
    });
  }

  async function preview() {
    if (!selected.size || busy) return;
    setBusy(true);
    setError(null);
    const body = {
      action: "add_to_group" as const,
      tenantId,
      groupId,
      userIds: Array.from(selected),
    };
    try {
      const result = await api.changes.preview(body);
      onClose();
      openWhatIf({
        preview: result,
        execute: () => api.changes.execute(body, result.approvalToken),
      });
    } catch (err) {
      setBusy(false);
      setError(err instanceof RtmApiError ? err.message : "Could not generate the membership preview.");
    }
  }

  return (
    <Dialog open onClose={() => !busy && onClose()} width={620}>
      <div className="border-b border-[var(--border-card)] px-5 py-4">
        <div className="flex items-start gap-3">
          <div className="grid size-9 shrink-0 place-items-center rounded-[9px] bg-raised">
            <Users2 className="size-4 text-secondary" />
          </div>
          <div className="min-w-0">
            <h2 className="text-[15px] font-bold text-fg-strong">Add users to {groupName}</h2>
            <p className="mt-0.5 text-[11.5px] text-muted">
              Select users, then review the exact membership change through What-If.
            </p>
          </div>
        </div>
        <div className="relative mt-4">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" />
          <input
            autoFocus
            aria-label="Search users available to add"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search name or email…"
            className="h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control pl-9 pr-3 text-[12.5px] text-fg outline-none focus:border-[var(--ac)]/60"
          />
        </div>
      </div>

      <div className="max-h-[420px] overflow-y-auto px-3 py-2">
        {users.loading ? (
          <div className="flex min-h-44 items-center justify-center gap-2 text-[12.5px] text-muted">
            <Loader2 className="size-4 animate-spin" /> Loading users…
          </div>
        ) : users.error ? (
          <div className="m-2 flex items-start gap-2 rounded-[8px] border border-danger/30 bg-danger/10 px-3 py-2.5 text-[12.5px] text-danger">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{users.error.message}</span>
          </div>
        ) : available.length === 0 ? (
          <div className="grid min-h-44 place-items-center text-center">
            <div>
              <UserPlus className="mx-auto size-6 text-faint" />
              <p className="mt-2 text-[12.5px] font-semibold text-secondary">
                {query ? "No available users match" : "Every returned user is already a member"}
              </p>
            </div>
          </div>
        ) : (
          available.map((user) => (
            <label
              key={user.id}
              className="flex cursor-pointer items-center gap-3 rounded-[8px] px-3 py-2.5 transition-colors hover:bg-[var(--row-hover)]"
            >
              <Checkbox
                checked={selected.has(user.id)}
                onChange={() => toggle(user.id)}
                aria-label={`Select ${user.name}`}
              />
              <Avatar name={user.name} />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[12.5px] font-semibold text-fg">{user.name}</span>
                <span className="block truncate text-[11.5px] text-muted">{user.upn}</span>
              </span>
              <span className="text-[11px] text-muted">{user.status}</span>
            </label>
          ))
        )}
      </div>

      {error && (
        <div role="alert" className="mx-5 flex items-start gap-2 rounded-[8px] border border-danger/30 bg-danger/10 px-3 py-2 text-[12px] text-danger">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="mt-2 flex items-center justify-between border-t border-[var(--border-card)] px-5 py-4">
        <span className="text-[12px] text-muted">{selected.size} selected</span>
        <div className="flex gap-2">
          <Button type="button" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button type="button" variant="accent" onClick={() => void preview()} disabled={busy || selected.size === 0}>
            {busy ? <Loader2 className="size-4 animate-spin" /> : <UserPlus className="size-4" />}
            {busy ? "Generating…" : "Generate What-If"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
