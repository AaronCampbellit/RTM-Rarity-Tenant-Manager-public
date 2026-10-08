import { useState } from "react";
import { AlertTriangle, FileCheck2, Loader2 } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useModals } from "@/store/modals";
import { Dialog } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { ApprovalRequest, ChangeRequest } from "@/types";

const SCOPES: { value: NonNullable<ChangeRequest["scope"]>; label: string }[] = [
  { value: "computer", label: "This computer only" },
  { value: "group", label: "The computer's group" },
  { value: "organization", label: "The whole organization" },
];

const SELECT_CLASS =
  "h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none focus:border-[var(--ac)]";

/**
 * ThreatLocker approval-request detail with the approve/deny decision.
 * Approving creates a ThreatLocker permit policy — both decisions go through
 * the mandatory What-If gate and are executed as jobs.
 */
export function ApprovalDetailModal({
  request,
  tenantId,
  onClose,
}: {
  request: ApprovalRequest | null;
  tenantId?: string;
  onClose: () => void;
}) {
  const { openWhatIf } = useModals();
  const [scope, setScope] = useState<NonNullable<ChangeRequest["scope"]>>("computer");
  const [expiresAt, setExpiresAt] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const open = !!request;

  function reset() {
    setScope("computer");
    setExpiresAt("");
    setReason("");
    setError(null);
    setBusy(null);
  }

  function close() {
    if (busy) return;
    reset();
    onClose();
  }

  async function decide(kind: "approve" | "deny") {
    if (!request) return;
    setBusy(kind);
    setError(null);
    const body: ChangeRequest =
      kind === "approve"
        ? {
            action: "approve_request",
            tenantId: tenantId ?? "",
            approvalRequestIds: [request.id],
            scope,
            ...(expiresAt.trim() ? { expiresAt: expiresAt.trim() } : {}),
          }
        : {
            action: "deny_request",
            tenantId: tenantId ?? "",
            approvalRequestIds: [request.id],
            ...(reason.trim() ? { reason: reason.trim() } : {}),
          };
    try {
      const preview = await api.changes.preview(body);
      reset();
      onClose();
      openWhatIf({ preview, execute: () => api.changes.execute(body, preview.approvalToken) });
    } catch (err) {
      setBusy(null);
      setError(
        err instanceof RtmApiError
          ? err.message
          : "Could not generate the preview. Please try again.",
      );
    }
  }

  return (
    <Dialog open={open} onClose={close} width={500}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
            <FileCheck2 className="size-4 text-secondary" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">{request?.application}</h2>
            <p className="text-[12px] text-muted">
              Requested by {request?.requester} on {request?.deviceName}
            </p>
          </div>
          <div className="ml-auto">
            <Badge tone="warning" dot={false}>
              <span className="capitalize">{request?.requestType}</span>
            </Badge>
          </div>
        </div>

        <div className="mt-4 rounded-[10px] border border-[var(--border)] bg-raised/40">
          <div className="border-b border-[var(--border)] px-3.5 py-2.5">
            <p className="text-[11px] uppercase tracking-wide text-muted">Full path</p>
            <p className="mono mt-0.5 break-all text-[12px] text-secondary">{request?.path}</p>
          </div>
          <div className="border-b border-[var(--border)] px-3.5 py-2.5">
            <p className="text-[11px] uppercase tracking-wide text-muted">Hash</p>
            <p className="mono mt-0.5 break-all text-[12px] text-secondary">{request?.hash}</p>
          </div>
          <div className="px-3.5 py-2.5">
            <p className="text-[11px] uppercase tracking-wide text-muted">Requested</p>
            <p className="mt-0.5 text-[12px] text-secondary">{request?.requestedAt}</p>
          </div>
        </div>

        <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
          Permit scope (when approving)
        </label>
        <select
          value={scope}
          onChange={(e) => setScope(e.target.value as NonNullable<ChangeRequest["scope"]>)}
          className={SELECT_CLASS}
        >
          {SCOPES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>

        <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
          Permit expiry (optional, RFC3339)
        </label>
        <Input
          value={expiresAt}
          onChange={(e) => setExpiresAt(e.target.value)}
          placeholder="2026-07-11T17:00:00Z"
          className="mono"
        />

        <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
          Deny reason (optional)
        </label>
        <Input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Why the request is denied"
        />

        <p className="mt-3 text-[12px] font-medium text-[#f5b569]">
          Approving creates a ThreatLocker permit policy at the chosen scope —
          neither decision can be reverted from RTM.
        </p>

        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <Button variant="default" onClick={close} disabled={!!busy}>
            Cancel
          </Button>
          <Button variant="default" onClick={() => decide("deny")} disabled={!!busy}>
            {busy === "deny" && <Loader2 className="size-4 animate-spin" />}
            Deny…
          </Button>
          <Button variant="accent" onClick={() => decide("approve")} disabled={!!busy}>
            {busy === "approve" && <Loader2 className="size-4 animate-spin" />}
            Approve…
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
