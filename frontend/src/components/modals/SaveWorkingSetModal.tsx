import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle, CheckCircle2, Layers, Loader2 } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { useModals } from "@/store/modals";
import { normalizeWorkingSetUserIds } from "@/features/working-sets/workingSet";
import type { WorkingSet } from "@/types";

/** Save-as-Working-Set — small modal launched from the Users action bar. */
export function SaveWorkingSetModal() {
  const { workingSet, closeWorkingSet } = useModals();
  const navigate = useNavigate();
  const open = workingSet !== null;
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<WorkingSet | null>(null);

  useEffect(() => {
    if (workingSet) {
      setName(`${workingSet.tenant} — Selection`);
      setDesc("");
      setBusy(false);
      setError(null);
      setCreated(null);
    }
  }, [workingSet]);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (!workingSet || busy || !name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await api.workingSets.create({
        name: name.trim(),
        description: desc.trim(),
        tenantId: workingSet.tenantId,
        userIds: normalizeWorkingSetUserIds(workingSet.userIds),
      });
      setCreated(saved);
      workingSet.onSaved?.(saved);
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "The working set could not be saved.");
    } finally {
      setBusy(false);
    }
  }

  function close() {
    if (!busy) closeWorkingSet();
  }

  return (
    <Dialog open={open} onClose={close} width={440}>
      <div className="flex items-center gap-2.5 p-5 pb-3">
        <div className="grid size-8 place-items-center rounded-[8px] bg-[var(--acb)]">
          <Layers className="size-4 text-[var(--ac)]" />
        </div>
        <div>
          <h2 className="text-[15px] font-bold text-fg-strong">Save as Working Set</h2>
          <p className="text-[12.5px] text-muted">
            {workingSet?.userIds.length ?? 0} users from {workingSet?.tenant ?? "—"}
          </p>
        </div>
      </div>

      {created ? (
        <>
          <div className="mx-5 rounded-[10px] border border-success/30 bg-success/10 p-4" role="status">
            <div className="flex items-start gap-2.5">
              <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-success" />
              <div>
                <p className="text-[13px] font-semibold text-fg">Working Set saved</p>
                <p className="mt-1 text-[12px] leading-5 text-secondary">
                  {created.name} contains {created.items} user{created.items === 1 ? "" : "s"} from {created.tenant}.
                </p>
              </div>
            </div>
          </div>
          <div className="mt-4 flex justify-end gap-2 border-t border-[var(--border-card)] px-5 py-4">
            <Button variant="default" onClick={close}>Done</Button>
            <Button
              variant="accent"
              onClick={() => {
                closeWorkingSet();
                navigate("/working-sets");
              }}
            >
              View Working Sets
            </Button>
          </div>
        </>
      ) : (
        <form onSubmit={save}>
          <div className="space-y-3 px-5">
            <div>
              <label htmlFor="working-set-name" className="mb-1.5 block text-[12px] font-semibold text-secondary">
                Name
              </label>
              <Input id="working-set-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={120} autoFocus />
            </div>
            <div>
              <label htmlFor="working-set-description" className="mb-1.5 block text-[12px] font-semibold text-secondary">
                Description
              </label>
              <Textarea
                id="working-set-description"
                rows={3}
                maxLength={500}
                placeholder="Optional — what is this set for?"
                value={desc}
                onChange={(e) => setDesc(e.target.value)}
              />
            </div>
            {error && (
              <div role="alert" className="flex items-start gap-2 rounded-[8px] border border-danger/30 bg-danger/10 px-3 py-2 text-[12px] text-danger">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </div>

          <div className="mt-4 flex justify-end gap-2 border-t border-[var(--border-card)] px-5 py-4">
            <Button type="button" variant="default" onClick={close} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" variant="accent" disabled={busy || !name.trim()}>
              {busy && <Loader2 className="size-4 animate-spin" />}
              {busy ? "Saving…" : "Save Working Set"}
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
