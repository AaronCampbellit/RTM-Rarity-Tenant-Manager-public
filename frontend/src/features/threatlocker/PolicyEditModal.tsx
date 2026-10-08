import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Loader2, Save, X } from "lucide-react";
import { api } from "@/api/client";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import type { TLPolicyDetail, TLPolicyPatch } from "@/types";

interface PolicyEditModalProps {
  tenantId?: string;
  policyId: string | null;
  onClose: () => void;
  onSaved: () => void;
}

export function PolicyEditModal({ tenantId, policyId, onClose, onSaved }: PolicyEditModalProps) {
  const [policy, setPolicy] = useState<TLPolicyDetail | null>(null);
  const [form, setForm] = useState<TLPolicyPatch>({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!policyId) return;
    let alive = true;
    setLoading(true);
    setError("");
    api.threatlocker
      .policy(tenantId, policyId)
      .then((p) => {
        if (!alive) return;
        setPolicy(p);
        setForm({
          name: p.name,
          description: p.description,
          comments: p.comments,
          isEnabled: p.isEnabled,
          policyActionId: p.policyActionId,
          monitorMode: p.monitorMode,
          orderBy: p.orderBy,
          neverExpires: p.neverExpires,
          endDate: p.endDate,
          logAction: p.logAction,
          notifyOnMatch: p.notifyOnMatch,
          notifyOnRequest: p.notifyOnRequest,
          killRunningProcesses: p.killRunningProcesses,
          applicationSelection: p.applicationSelection,
          applicationIds: p.applicationIds,
        });
      })
      .catch((e) => alive && setError(e instanceof Error ? e.message : "Unable to load policy."))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [tenantId, policyId]);

  if (!policyId) return null;

  const set = <K extends keyof TLPolicyPatch>(key: K, value: TLPolicyPatch[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  async function save() {
    if (!policyId) return;
    setSaving(true);
    setError("");
    try {
      const preview = await api.threatlocker.previewPolicyUpdate(tenantId, policyId, form);
      if (!window.confirm(`${preview.summary}. Apply this change?`)) return;
      await api.threatlocker.updatePolicy(tenantId, policyId, { ...form, approvalToken: preview.approvalToken });
      onSaved();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to save policy.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={!!policyId} onClose={onClose} width={720}>
      <div className="flex items-center justify-between border-b border-[var(--border-card)] px-5 py-4">
        <div>
          <h2 className="text-[15px] font-bold text-fg-strong">Edit policy</h2>
          <p className="text-[12px] text-muted">{policy?.id ?? policyId}</p>
        </div>
        <button className="grid size-8 place-items-center rounded-[8px] text-muted hover:bg-raised hover:text-fg" onClick={onClose}>
          <X className="size-4" />
        </button>
      </div>

      <div className="space-y-4 p-5">
        {loading ? (
          <div className="flex items-center gap-2 py-8 text-[13px] text-muted">
            <Loader2 className="size-4 animate-spin" /> Loading policy…
          </div>
        ) : (
          <>
            <Field label="Name">
              <Input value={form.name ?? ""} onChange={(e) => set("name", e.target.value)} />
            </Field>
            <Field label="Description">
              <Textarea rows={3} value={form.description ?? ""} onChange={(e) => set("description", e.target.value)} />
            </Field>
            <Field label="Comments">
              <Textarea rows={2} value={form.comments ?? ""} onChange={(e) => set("comments", e.target.value)} />
            </Field>

            <ApplicationsList policy={policy} />

            <div className="grid gap-3 sm:grid-cols-2">
              <Toggle label="Enabled" checked={!!form.isEnabled} onChange={() => set("isEnabled", !form.isEnabled)} />
              <Toggle label="Log action" checked={!!form.logAction} onChange={() => set("logAction", !form.logAction)} />
              <Toggle label="Notify on match" checked={!!form.notifyOnMatch} onChange={() => set("notifyOnMatch", !form.notifyOnMatch)} />
              <Toggle label="Notify on request" checked={!!form.notifyOnRequest} onChange={() => set("notifyOnRequest", !form.notifyOnRequest)} />
              <Toggle label="Kill running processes" checked={!!form.killRunningProcesses} onChange={() => set("killRunningProcesses", !form.killRunningProcesses)} />
              <Toggle label="Never expires" checked={!!form.neverExpires} onChange={() => set("neverExpires", !form.neverExpires)} />
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Action ID">
                <Input type="number" value={form.policyActionId ?? 0} onChange={(e) => set("policyActionId", Number(e.target.value))} />
              </Field>
              <Field label="Monitor mode">
                <Input type="number" value={form.monitorMode ?? 0} onChange={(e) => set("monitorMode", Number(e.target.value))} />
              </Field>
              <Field label="Order">
                <Input type="number" value={form.orderBy ?? 0} onChange={(e) => set("orderBy", Number(e.target.value))} />
              </Field>
            </div>
            {!form.neverExpires && (
              <Field label="End date">
                <Input value={form.endDate ?? ""} onChange={(e) => set("endDate", e.target.value)} />
              </Field>
            )}
          </>
        )}
        {error && <p className="rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">{error}</p>}
      </div>

      <div className="flex items-center justify-end gap-2 border-t border-[var(--border-card)] px-5 py-4">
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="accent" onClick={save} disabled={loading || saving}>
          {saving ? <Loader2 className="animate-spin" /> : <Save />}
          Save policy
        </Button>
      </div>
    </Dialog>
  );
}

function ApplicationsList({ policy }: { policy: TLPolicyDetail | null }) {
  const apps =
    policy?.applications?.length
      ? policy.applications
      : (policy?.applicationIds ?? []).map((id) => ({ id, name: "", path: "" }));

  return (
    <section className="rounded-[8px] border border-[var(--border-card)] bg-raised/30">
      <div className="flex items-center justify-between border-b border-[var(--border-card)] px-3 py-2">
        <h3 className="text-[12px] font-semibold text-secondary">Applications</h3>
        <span className="tabular text-[11.5px] text-muted">{apps.length}</span>
      </div>
      <div className="max-h-48 overflow-y-auto p-2">
        {apps.length === 0 ? (
          <p className="px-1 py-2 text-[12.5px] text-muted">No specific applications listed.</p>
        ) : (
          <div className="space-y-1.5">
            {apps.map((app, i) => (
              <div key={`${app.id || app.name || app.path}-${i}`} className="rounded-[7px] border border-[var(--border-card)] bg-card px-2.5 py-2">
                <p className="break-words text-[12.5px] font-semibold text-fg">{app.name || app.id || "Unnamed application"}</p>
                {app.path && <p className="mono mt-1 break-all text-[11px] text-muted">{app.path}</p>}
                {app.id && app.name && <p className="mono mt-1 break-all text-[11px] text-faint">{app.id}</p>}
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-[12px] font-semibold text-secondary">{label}</span>
      {children}
    </label>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: () => void }) {
  return (
    <div className="flex items-center justify-between rounded-[8px] border border-[var(--border-card)] bg-raised/40 px-3 py-2">
      <span className="text-[12.5px] text-secondary">{label}</span>
      <Switch checked={checked} onChange={onChange} />
    </div>
  );
}
