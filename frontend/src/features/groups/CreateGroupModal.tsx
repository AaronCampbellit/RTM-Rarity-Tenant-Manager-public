import { useState } from "react";
import { AlertTriangle, Loader2, Users2 } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { Group, NewGroup } from "@/types";

// The two group types RTM can create through Microsoft Graph. Distribution
// and mail-enabled security groups are Exchange-managed and can't be created
// via Graph, so they aren't offered here.
const TYPES: { value: NewGroup["type"]; label: string; hint: string }[] = [
  {
    value: "Security",
    label: "Security group",
    hint: "Controls access to resources and apps. Not mail-enabled.",
  },
  {
    value: "M365",
    label: "Microsoft 365 group",
    hint: "Collaboration group with a shared mailbox, calendar, and SharePoint site.",
  },
];

/**
 * Create a new group in the active tenant (admin-only). The type picker
 * chooses between the two Graph-creatable group types; both are created with
 * assigned membership.
 */
export function CreateGroupModal({
  open,
  tenantId,
  onClose,
  onCreated,
}: {
  open: boolean;
  tenantId: string;
  onClose: () => void;
  onCreated: (g: Group) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [type, setType] = useState<NewGroup["type"]>("Security");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setName("");
    setDescription("");
    setType("Security");
    setError(null);
    setBusy(false);
  }

  function close() {
    if (busy) return;
    reset();
    onClose();
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = await api.groups.create(tenantId, { name, description, type });
      reset();
      onCreated(created);
    } catch (err) {
      setBusy(false);
      setError(
        err instanceof RtmApiError
          ? err.message
          : "Unable to create the group. Please try again.",
      );
    }
  }

  return (
    <Dialog open={open} onClose={close} width={480}>
      <form onSubmit={submit} className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
            <Users2 className="size-4 text-secondary" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">New Group</h2>
            <p className="text-[12px] text-muted">
              Created in Microsoft 365 with assigned membership.
            </p>
          </div>
        </div>

        <div className="mt-4 space-y-3.5">
          <div>
            <label htmlFor="group-name" className="mb-1.5 block text-[12px] font-semibold text-secondary">
              Group name <span className="text-accent" aria-hidden="true">*</span>
            </label>
            <Input
              id="group-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Project Phoenix"
              maxLength={256}
              required
              autoFocus
            />
          </div>

          <div>
            <label htmlFor="group-description" className="mb-1.5 block text-[12px] font-semibold text-secondary">
              Description <span className="text-accent" aria-hidden="true">*</span>
            </label>
            <Input
              id="group-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Explain the group’s purpose and intended membership"
              maxLength={1024}
              required
            />
            <p className="mt-1 text-[11px] text-muted">
              Required so technicians can understand why the group exists before changing its membership.
            </p>
          </div>

          <div>
            <label className="mb-1.5 block text-[12px] font-semibold text-secondary">
              Group type
            </label>
            <div className="space-y-2">
              {TYPES.map((t) => (
                <label
                  key={t.value}
                  className={`flex cursor-pointer items-start gap-2.5 rounded-[10px] border px-3 py-2.5 transition-colors ${
                    type === t.value
                      ? "border-[var(--ac)] bg-[rgba(229,72,77,.06)]"
                      : "border-[var(--border-card)] hover:bg-raised/50"
                  }`}
                >
                  <input
                    type="radio"
                    name="group-type"
                    className="mt-0.5 accent-[var(--ac)]"
                    checked={type === t.value}
                    onChange={() => setType(t.value)}
                  />
                  <div className="min-w-0">
                    <p className="text-[13px] font-semibold text-fg">{t.label}</p>
                    <p className="text-[11.5px] text-muted">{t.hint}</p>
                  </div>
                </label>
              ))}
            </div>
            <p className="mt-2 text-[11.5px] text-faint">
              Distribution and mail-enabled security groups are managed in
              Exchange and can't be created here.
            </p>
          </div>
        </div>

        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <Button type="button" variant="default" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" variant="accent" disabled={busy || !name.trim() || !description.trim()}>
            {busy && <Loader2 className="size-4 animate-spin" />}
            Create Group
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
