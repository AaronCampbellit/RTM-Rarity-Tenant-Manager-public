import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, Layers, Loader2, Pencil, Search, Users2 } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input, Textarea } from "@/components/ui/input";
import { Avatar } from "@/components/common/Avatar";
import type { WorkingSet } from "@/types";

export function WorkingSetDetailDialog({
  workingSetId,
  onClose,
  onSaved,
  onOpenUsers,
}: {
  workingSetId: string;
  onClose: () => void;
  onSaved: (workingSet: WorkingSet) => void;
  onOpenUsers: (workingSet: WorkingSet) => void;
}) {
  const [detailVersion, setDetailVersion] = useState(0);
  const detail = useAsync(() => api.workingSets.get(workingSetId), [workingSetId, detailVersion]);
  const users = useAsync(
    () => detail.data ? api.users.list(detail.data.tenantId) : Promise.resolve([]),
    [detail.data?.tenantId],
  );
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [memberIds, setMemberIds] = useState<Set<string>>(() => new Set());
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!detail.data) return;
    setName(detail.data.name);
    setDescription(detail.data.description);
    setMemberIds(new Set(detail.data.userIds));
  }, [detail.data]);

  const filteredUsers = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (users.data ?? []).filter((user) => !needle || `${user.name} ${user.upn} ${user.mail}`.toLowerCase().includes(needle));
  }, [query, users.data]);

  const usersById = useMemo(() => new Map((users.data ?? []).map((user) => [user.id, user])), [users.data]);

  function toggle(userId: string) {
    setMemberIds((current) => {
      const next = new Set(current);
      if (next.has(userId)) next.delete(userId);
      else next.add(userId);
      return next;
    });
    setSaved(false);
  }

  function cancelEdit() {
    if (!detail.data || busy) return;
    setName(detail.data.name);
    setDescription(detail.data.description);
    setMemberIds(new Set(detail.data.userIds));
    setQuery("");
    setError(null);
    setEditing(false);
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (!name.trim() || memberIds.size === 0 || busy) return;
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const updated = await api.workingSets.update(workingSetId, {
        name: name.trim(),
        description: description.trim(),
        userIds: Array.from(memberIds),
      });
      onSaved(updated);
      setDetailVersion((version) => version + 1);
      setEditing(false);
      setSaved(true);
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "The working set could not be updated.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onClose={() => !busy && onClose()} width={720}>
      <div className="border-b border-[var(--border-card)] px-5 py-4">
        <div className="flex items-start gap-3">
          <div className="grid size-10 shrink-0 place-items-center rounded-[10px] bg-raised">
            <Layers className="size-4.5 text-secondary" />
          </div>
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-[16px] font-bold text-fg-strong">{detail.data?.name ?? "Working Set"}</h2>
            <p className="mt-0.5 text-[11.5px] text-muted">
              {detail.data ? `${detail.data.tenant} · ${detail.data.items} users` : "Loading saved scope…"}
            </p>
          </div>
          {!editing && detail.data && (
            <Button variant="default" size="sm" onClick={() => { setEditing(true); setSaved(false); }}>
              <Pencil className="size-3.5" /> Edit
            </Button>
          )}
        </div>
      </div>

      {detail.loading ? (
        <div className="grid min-h-80 place-items-center text-muted"><Loader2 className="size-5 animate-spin" /></div>
      ) : detail.error ? (
        <div className="m-5 flex items-start gap-2 rounded-[8px] border border-danger/30 bg-danger/10 px-3 py-2.5 text-[12.5px] text-danger">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" /> {detail.error.message}
        </div>
      ) : detail.data && !editing ? (
        <div className="space-y-4 px-5 py-4">
          {saved && (
            <div role="status" className="flex items-center gap-2 rounded-[8px] border border-success/30 bg-success/10 px-3 py-2 text-[12px] text-success">
              <CheckCircle2 className="size-4" /> Working Set updated.
            </div>
          )}
          <div className="grid gap-3 sm:grid-cols-3">
            <Fact label="Tenant" value={detail.data.tenant} />
            <Fact label="Created by" value={detail.data.createdBy} />
            <Fact label="Last used" value={detail.data.lastUsed} />
          </div>
          <section>
            <h3 className="text-[10.5px] font-bold uppercase tracking-wide text-faint">Description</h3>
            <p className="mt-1.5 rounded-[9px] border border-[var(--border-card)] bg-raised/30 px-3 py-2.5 text-[12.5px] text-secondary">
              {detail.data.description || "No description provided."}
            </p>
          </section>
          <section>
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-[10.5px] font-bold uppercase tracking-wide text-faint">Saved users</h3>
              <span className="text-[11px] text-muted">{detail.data.userIds.length} retained IDs</span>
            </div>
            <div className="max-h-64 overflow-y-auto rounded-[9px] border border-[var(--border-card)]">
              {detail.data.userIds.length ? detail.data.userIds.map((id) => {
                const user = usersById.get(id);
                return (
                  <div key={id} className="flex items-center gap-3 border-b border-[var(--border-card)] px-3 py-2.5 last:border-0">
                    <Avatar name={user?.name ?? id} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[12.5px] font-semibold text-fg">{user?.name ?? "Unavailable user"}</span>
                      <span className="block truncate text-[11.5px] text-muted">{user?.upn ?? id}</span>
                    </span>
                  </div>
                );
              }) : (
                <p className="px-3 py-8 text-center text-[12px] text-muted">No retained user identities are available for this set.</p>
              )}
            </div>
          </section>
        </div>
      ) : detail.data ? (
        <form onSubmit={save}>
          <div className="space-y-4 px-5 py-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="working-set-edit-name" className="mb-1.5 block text-[12px] font-semibold text-secondary">Name <span className="text-accent">*</span></label>
                <Input id="working-set-edit-name" autoFocus required maxLength={120} value={name} onChange={(event) => setName(event.target.value)} />
              </div>
              <div className="sm:row-span-2">
                <label htmlFor="working-set-edit-description" className="mb-1.5 block text-[12px] font-semibold text-secondary">Description</label>
                <Textarea id="working-set-edit-description" rows={4} maxLength={500} value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Optional — what is this set for?" />
              </div>
            </div>
            <section>
              <div className="mb-2 flex items-center justify-between">
                <label htmlFor="working-set-user-search" className="text-[12px] font-semibold text-secondary">Users <span className="text-accent">*</span></label>
                <span className="text-[11px] text-muted">{memberIds.size} selected</span>
              </div>
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" />
                <Input id="working-set-user-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search users…" className="pl-9" />
              </div>
              <div className="mt-2 max-h-64 overflow-y-auto rounded-[9px] border border-[var(--border-card)]">
                {users.loading ? (
                  <div className="grid min-h-32 place-items-center"><Loader2 className="size-4 animate-spin text-muted" /></div>
                ) : filteredUsers.map((user) => (
                  <label key={user.id} className="flex cursor-pointer items-center gap-3 border-b border-[var(--border-card)] px-3 py-2.5 last:border-0 hover:bg-[var(--row-hover)]">
                    <Checkbox checked={memberIds.has(user.id)} onChange={() => toggle(user.id)} aria-label={`Include ${user.name}`} />
                    <Avatar name={user.name} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[12.5px] font-semibold text-fg">{user.name}</span>
                      <span className="block truncate text-[11.5px] text-muted">{user.upn}</span>
                    </span>
                  </label>
                ))}
              </div>
              {memberIds.size === 0 && <p className="mt-1.5 text-[11.5px] text-danger">A Working Set must contain at least one user.</p>}
            </section>
            {error && (
              <div role="alert" className="flex items-start gap-2 rounded-[8px] border border-danger/30 bg-danger/10 px-3 py-2 text-[12px] text-danger">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" /> {error}
              </div>
            )}
          </div>
          <div className="flex justify-end gap-2 border-t border-[var(--border-card)] px-5 py-4">
            <Button type="button" onClick={cancelEdit} disabled={busy}>Cancel</Button>
            <Button type="submit" variant="accent" disabled={busy || !name.trim() || memberIds.size === 0}>
              {busy && <Loader2 className="size-4 animate-spin" />}{busy ? "Saving…" : "Save changes"}
            </Button>
          </div>
        </form>
      ) : null}

      {!editing && detail.data && (
        <div className="flex items-center justify-between border-t border-[var(--border-card)] px-5 py-4">
          <Button onClick={onClose}>Close</Button>
          <Button variant="accent" onClick={() => onOpenUsers(detail.data!)}>
            <Users2 className="size-4" /> Open in Users
          </Button>
        </div>
      )}
    </Dialog>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[9px] border border-[var(--border-card)] bg-raised/30 px-3 py-2.5">
      <p className="text-[10px] font-bold uppercase tracking-wide text-faint">{label}</p>
      <p className="mt-1 truncate text-[12.5px] text-fg">{value || "—"}</p>
    </div>
  );
}
