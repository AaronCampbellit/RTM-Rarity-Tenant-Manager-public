import { useEffect, useState } from "react";
import { Loader2, Save, X } from "lucide-react";
import { api } from "@/api/client";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import type { TLApplication } from "@/types";

interface AppRenameModalProps {
  tenantId?: string;
  app: TLApplication | null;
  onClose: () => void;
  onSaved: () => void;
}

export function AppRenameModal({ tenantId, app, onClose, onSaved }: AppRenameModalProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setName(app?.name ?? "");
    setDescription(app?.description ?? "");
    setError("");
  }, [app]);

  if (!app) return null;

  async function save() {
    if (!app) return;
    if (!name.trim()) {
      setError("Application name is required.");
      return;
    }
    setSaving(true);
    setError("");
    try {
      const preview = await api.threatlocker.previewAppUpdate(tenantId, app.id, {
        name: name.trim(),
        description,
      });
      if (!window.confirm(`${preview.summary}. Apply this change?`)) return;
      await api.threatlocker.updateApp(tenantId, app.id, { name: name.trim(), description, approvalToken: preview.approvalToken });
      onSaved();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to rename application.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={!!app} onClose={onClose} width={560}>
      <div className="flex items-center justify-between border-b border-[var(--border-card)] px-5 py-4">
        <div>
          <h2 className="text-[15px] font-bold text-fg-strong">Rename application</h2>
          <p className="text-[12px] text-muted">{app.id}</p>
        </div>
        <button className="grid size-8 place-items-center rounded-[8px] text-muted hover:bg-raised hover:text-fg" onClick={onClose}>
          <X className="size-4" />
        </button>
      </div>

      <div className="space-y-4 p-5">
        <label className="block space-y-1.5">
          <span className="text-[12px] font-semibold text-secondary">Name</span>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="block space-y-1.5">
          <span className="text-[12px] font-semibold text-secondary">Description</span>
          <Textarea rows={3} value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        {error && (
          <p className="rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            {error}
          </p>
        )}
      </div>

      <div className="flex items-center justify-end gap-2 border-t border-[var(--border-card)] px-5 py-4">
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="accent" onClick={save} disabled={saving || !name.trim()}>
          {saving ? <Loader2 className="animate-spin" /> : <Save />}
          Save
        </Button>
      </div>
    </Dialog>
  );
}
