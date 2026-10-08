import { useState } from "react";
import { AlertTriangle, Loader2, Play } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useModals } from "@/store/modals";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { ChangeRequest, MaintenanceType } from "@/types";

const ACTIONS: { value: ChangeRequest["action"]; label: string }[] = [
  { value: "enter_maintenance_mode", label: "Enter maintenance mode" },
  { value: "secure_device", label: "Secure (end maintenance)" },
  { value: "restart_agent", label: "Restart ThreatLocker agent" },
];

const MAINTENANCE_TYPES: { value: MaintenanceType; label: string }[] = [
  { value: "monitor_only", label: "Monitor Only — log, don't block" },
  { value: "learning", label: "Learning — build policies from activity" },
];

const SELECT_CLASS =
  "h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none focus:border-[var(--ac)]";

const WARNINGS: Partial<Record<ChangeRequest["action"], string>> = {
  secure_device:
    "The previous mode is not snapshotted — this cannot be reverted automatically.",
  restart_agent: "Cannot be reverted — the agent service restarts on each device.",
};

/**
 * Step 1 of the ThreatLocker device write flow: choose the action (and, for
 * maintenance mode, the type + bounded duration), then generate the live
 * What-If preview and hand off to the mandatory What-If gate.
 */
export function DeviceActionDialog({
  open,
  tenantId,
  deviceIds,
  onClose,
}: {
  open: boolean;
  tenantId?: string;
  deviceIds: string[];
  onClose: () => void;
}) {
  const { openWhatIf } = useModals();
  const [action, setAction] = useState<ChangeRequest["action"]>("enter_maintenance_mode");
  const [maintenanceType, setMaintenanceType] = useState<MaintenanceType>("monitor_only");
  const [duration, setDuration] = useState("60");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isMaintenance = action === "enter_maintenance_mode";
  const durationMinutes = Number.parseInt(duration, 10);
  const durationValid =
    Number.isFinite(durationMinutes) && durationMinutes >= 1 && durationMinutes <= 1440;

  function reset() {
    setAction("enter_maintenance_mode");
    setMaintenanceType("monitor_only");
    setDuration("60");
    setError(null);
  }

  function close() {
    if (busy) return;
    reset();
    onClose();
  }

  const canGenerate = !isMaintenance || durationValid;

  async function generate() {
    if (!canGenerate) return;
    setBusy(true);
    setError(null);
    const body: ChangeRequest = {
      action,
      tenantId: tenantId ?? "",
      deviceIds,
      ...(isMaintenance ? { maintenanceType, durationMinutes } : {}),
    };
    try {
      const preview = await api.changes.preview(body);
      setBusy(false);
      reset();
      onClose();
      openWhatIf({ preview, execute: () => api.changes.execute(body, preview.approvalToken) });
    } catch (err) {
      setBusy(false);
      setError(
        err instanceof RtmApiError
          ? err.message
          : "Could not generate the preview. Please try again.",
      );
    }
  }

  return (
    <Dialog open={open} onClose={close} width={440}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
            <Play className="size-4 text-secondary" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">Run What If</h2>
            <p className="text-[12px] text-muted">
              Apply an action to {deviceIds.length} selected device
              {deviceIds.length === 1 ? "" : "s"}
            </p>
          </div>
        </div>

        <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
          Action
        </label>
        <select
          value={action}
          onChange={(e) => {
            setAction(e.target.value as ChangeRequest["action"]);
            setError(null);
          }}
          className={SELECT_CLASS}
        >
          {ACTIONS.map((a) => (
            <option key={a.value} value={a.value}>
              {a.label}
            </option>
          ))}
        </select>

        {isMaintenance && (
          <>
            <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
              Maintenance type
            </label>
            <select
              value={maintenanceType}
              onChange={(e) => setMaintenanceType(e.target.value as MaintenanceType)}
              className={SELECT_CLASS}
            >
              {MAINTENANCE_TYPES.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
            <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
              Duration (minutes, max 1440)
            </label>
            <Input
              type="number"
              min={1}
              max={1440}
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
            />
            <p className="mt-2 text-[12px] font-medium text-[#f5b569]">
              Protection is reduced until the window ends
              {maintenanceType === "disable_protection"
                ? " — Disable Protection turns enforcement off entirely."
                : "."}
            </p>
          </>
        )}

        {WARNINGS[action] && (
          <p className="mt-3 text-[12px] font-medium text-[#f5b569]">{WARNINGS[action]}</p>
        )}

        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <p className="mt-3 text-[12px] text-muted">
          The What-If preview is computed from the devices&apos; current state
          in the global workspace — nothing changes until you approve it.
        </p>

        <div className="mt-4 flex justify-end gap-2">
          <Button variant="default" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button variant="accent" onClick={generate} disabled={!canGenerate || busy}>
            {busy && <Loader2 className="size-4 animate-spin" />}
            Generate Preview
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
