import { Monitor } from "lucide-react";
import { Dialog } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { deviceModeLabel, deviceModeTone } from "./mode";
import type { Device } from "@/types";

/** Read-only ThreatLocker detail for one device. Writes go through the
 * selection → What-If flow on the page. */
export function DeviceDetailModal({
  device,
  onClose,
}: {
  device: Device | null;
  onClose: () => void;
}) {
  const open = !!device;
  return (
    <Dialog open={open} onClose={onClose} width={460}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
            <Monitor className="size-4 text-secondary" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">{device?.hostname}</h2>
            <p className="text-[12px] text-muted">{device?.group}</p>
          </div>
          <div className="ml-auto">
            {device && <Badge tone={deviceModeTone(device.mode)}>{deviceModeLabel(device.mode)}</Badge>}
          </div>
        </div>

        {device && (
          <div className="mt-5 rounded-[10px] border border-[var(--border)] bg-raised/40">
            <Row label="Operating system">
              <span className="capitalize text-secondary">{device.os}</span>
            </Row>
            <Row label="Agent version">
              <span className="mono text-secondary">{device.agentVersion}</span>
            </Row>
            <Row label="Protection mode">
              <span className="flex items-center gap-2">
                <Badge tone={deviceModeTone(device.mode)}>{deviceModeLabel(device.mode)}</Badge>
                {device.modeExpires && (
                  <span className="text-[11px] text-muted">until {device.modeExpires}</span>
                )}
              </span>
            </Row>
            <Row label="Tamper protection">
              <Badge tone={device.tamperProtection ? "success" : "danger"} dot={false}>
                {device.tamperProtection ? "On" : "Off"}
              </Badge>
            </Row>
            <Row label="Last check-in" last>
              <span className={device.online ? "text-secondary" : "text-muted"}>
                {device.lastCheckIn}
                {device.online ? "" : " · offline"}
              </span>
            </Row>
          </div>
        )}

        <p className="mt-4 text-[12px] text-muted">
          To change this device's state, select it in the list and run a
          What-If action.
        </p>
      </div>
    </Dialog>
  );
}

function Row({
  label,
  last,
  children,
}: {
  label: string;
  last?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className={`flex items-center justify-between px-3.5 py-2.5 ${
        last ? "" : "border-b border-[var(--border)]"
      }`}
    >
      <span className="text-[12.5px] text-secondary">{label}</span>
      {children}
    </div>
  );
}
