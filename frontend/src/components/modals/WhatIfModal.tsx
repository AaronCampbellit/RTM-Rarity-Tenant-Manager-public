import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle, Ban, CheckCircle2, KeyRound, Loader2, ShieldAlert, SkipForward, Zap } from "lucide-react";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useModals } from "@/store/modals";
import { RtmApiError } from "@/api/client";
import { CopyButton } from "@/components/ui/copy-button";
import type { JobRef, StatusTone } from "@/types";

const RISK_TONE: Record<string, StatusTone> = {
  Low: "success",
  Medium: "warning",
  High: "danger",
};

/**
 * What-If Preview — the mandatory gate before any write (Security Spec →
 * Write Action Guardrail). The preview is computed by the API from live
 * tenant state; approving executes the change as a tracked job.
 */
export function WhatIfModal() {
  const { whatIf, closeWhatIf } = useModals();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<JobRef | null>(null);

  if (!whatIf) return null;
  const wi = whatIf.preview;
  const nothingToDo = wi.targetCount === 0;
  const cannotRevert = wi.warnings.some((warning) => /cannot be reverted/i.test(warning));

  function close() {
    if (busy) return;
    setError(null);
    setResult(null);
    closeWhatIf();
  }

  async function approve() {
    if (!whatIf) return;
    setBusy(true);
    setError(null);
    try {
      const execution = await whatIf.execute();
      setBusy(false);
      if (execution.status !== "queued" || execution.oneTimePasswords?.length) {
        setResult(execution);
        return;
      }
      closeWhatIf();
      navigate("/jobs");
    } catch (err) {
      setBusy(false);
      setError(
        err instanceof RtmApiError
          ? err.message
          : "The change could not be queued. Please try again.",
      );
    }
  }

  if (result) {
    const passwords = result.oneTimePasswords ?? [];
    const succeeded = result.status === "succeeded";
    return (
      <Dialog open onClose={close} width={640}>
        <div className="flex items-start gap-3 p-5">
          <div className={`grid size-9 shrink-0 place-items-center rounded-[9px] ${succeeded ? "bg-[rgba(46,160,67,.14)]" : "bg-[rgba(210,161,6,.15)]"}`}>
            {succeeded
              ? <CheckCircle2 className="size-[18px] text-[#57d677]" />
              : <AlertTriangle className="size-[18px] text-[#e3b341]" />}
          </div>
          <div>
            <h2 className="text-[16px] font-bold text-fg-strong">User access action finished</h2>
            <p className="text-[13px] text-secondary">
              {result.status === "succeeded"
                ? "Every requested step succeeded."
                : result.status === "partial_success"
                  ? "Some steps failed. Review the tracked job for the exact per-user result."
                  : "The requested steps failed. Review the tracked job for Microsoft’s response."}
            </p>
          </div>
        </div>

        <div className="px-5 pb-2">
          <div className="rounded-[10px] border border-[rgba(210,161,6,.35)] bg-[rgba(210,161,6,.08)] px-3.5 py-3 text-[12.5px] text-body">
            <p className="flex items-center gap-1.5 font-semibold text-[#e3b341]">
              <KeyRound className="size-4" /> One-time Microsoft 365 passwords
            </p>
            <p className="mt-1 text-muted">
              RTM does not store these passwords. Copy them before closing this dialog; each user must change theirs at the next sign-in.
            </p>
          </div>

          <div className="mt-3 max-h-[300px] overflow-auto rounded-[10px] border border-[var(--border-card)]">
            {passwords.length === 0 ? (
              <p className="px-3.5 py-3 text-[12.5px] text-[#f7868a]">
                No password was issued because the password-reset step failed.
              </p>
            ) : (
              passwords.map((credential) => (
                <div key={credential.userId} className="border-b border-[var(--border-card)] px-3.5 py-3 last:border-0">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate text-[13px] font-semibold text-fg">{credential.user}</p>
                      <p className="truncate text-[12px] text-muted">{credential.upn}</p>
                    </div>
                    <CopyButton value={credential.password} />
                  </div>
                  <p className="mono mt-2 break-all rounded-[7px] bg-control px-3 py-2 text-[13px] text-fg-strong">
                    {credential.password}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="mt-4 flex justify-end gap-2 border-t border-[var(--border-card)] px-5 py-4">
          <Button variant="default" onClick={() => { close(); navigate("/jobs"); }}>
            View job history
          </Button>
          <Button variant="accent" onClick={close}>Done</Button>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog open onClose={close} width={640}>
      {/* header */}
      <div className="flex items-start gap-3 p-5">
        <div className="grid size-9 shrink-0 place-items-center rounded-[9px] bg-[rgba(210,161,6,.15)]">
          <AlertTriangle className="size-[18px] text-[#e3b341]" />
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="text-[16px] font-bold text-fg-strong">What If Preview</h2>
          <p className="truncate text-[13px] text-secondary">{wi.action}</p>
        </div>
        <Badge tone={RISK_TONE[wi.risk]}>{wi.risk} Risk</Badge>
      </div>

      {/* summary grid */}
      <div className="grid grid-cols-3 gap-2.5 px-5">
        <Field label="Tenant" value={wi.tenant} />
        <Field label="Target Objects" value={`${wi.targetCount} ${wi.targetNoun ?? "users"}`} />
        <Field label="Required Permission" value={wi.requiredPermission} mono />
      </div>

      {/* expected changes */}
      <div className="px-5 pt-4">
        <p className="mb-2 text-[10.5px] font-bold uppercase tracking-[.5px] text-faint">
          Expected Changes
        </p>
        <div className="overflow-hidden rounded-[10px] border border-[var(--border-card)]">
          {wi.changes.length === 0 && (
            <div className="px-3.5 py-3 text-[12.5px] text-muted">
              No changes would be applied.
            </div>
          )}
          {wi.changes.map((c, i) => (
            <div
              key={i}
              className="flex items-center justify-between gap-3 border-b border-[var(--border-card)] px-3.5 py-2.5 last:border-0"
            >
              <div className="min-w-0">
                <p className="truncate text-[13px] font-semibold text-fg">{c.object}</p>
                <p className="truncate text-[12px] text-muted">{c.detail}</p>
              </div>
              <Badge tone="success" dot={false}>
                {c.change}
              </Badge>
            </div>
          ))}
          {wi.moreCount > 0 && (
            <div className="bg-[#19191d] px-3.5 py-2 text-[12px] text-muted">
              + {wi.moreCount} more objects
            </div>
          )}
        </div>
      </div>

      {/* warnings */}
      {wi.warnings.length > 0 && (
        <div className="px-5 pt-3">
          <div className="rounded-[10px] border border-[rgba(210,161,6,.35)] bg-[rgba(210,161,6,.08)] px-3.5 py-3">
            <p className="flex items-center gap-1.5 text-[12.5px] font-semibold text-[#e3b341]">
              <ShieldAlert className="size-4" /> Warnings
            </p>
            {wi.warnings.map((w, i) => (
              <p key={i} className="mt-1 text-[12.5px] text-body">
                {w}
              </p>
            ))}
          </div>
        </div>
      )}

      {/* blocked — on-prem-mastered targets that RTM refuses to change */}
      {wi.blocked?.length > 0 && (
        <div className="px-5 pt-3">
          <div className="rounded-[10px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.08)] px-3.5 py-3">
            <p className="flex items-center gap-1.5 text-[12.5px] font-semibold text-[#f7868a]">
              <Ban className="size-4" /> Blocked — mastered by on-prem Active Directory
            </p>
            {wi.blocked.map((b, i) => (
              <div key={i} className="mt-1.5">
                <p className="text-[12.5px] text-body">
                  <span className="font-semibold text-fg">{b.object}</span> — {b.reason}
                </p>
                <p className="text-[12px] text-muted">{b.resolution}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* skipped */}
      {wi.skipped.length > 0 && (
        <div className="px-5 pt-3">
          <div className="rounded-[10px] border border-[var(--border-card)] bg-[#19191d] px-3.5 py-3">
            <p className="flex items-center gap-1.5 text-[12.5px] font-semibold text-secondary">
              <SkipForward className="size-4" /> Skipped
            </p>
            {wi.skipped.map((s, i) => (
              <p key={i} className="mt-1 text-[12.5px] text-muted">
                {s.object} — {s.reason}
              </p>
            ))}
          </div>
        </div>
      )}

      {error && (
        <div className="px-5 pt-3">
          <div className="flex items-start gap-2 rounded-[10px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3.5 py-2.5 text-[12.5px] text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* footer */}
      <div className="mt-4 flex items-center justify-between gap-3 border-t border-[var(--border-card)] px-5 py-4">
        <p className="flex items-center gap-1.5 text-[12px] text-muted">
          <Zap className="size-3.5" />
          {cannotRevert
            ? "Executes as a tracked, audited action and cannot be reverted."
            : "Executes immediately as a tracked, revertible job."}
        </p>
        <div className="flex gap-2">
          <Button variant="default" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button variant="accent" onClick={approve} disabled={busy || nothingToDo}>
            {busy && <Loader2 className="size-4 animate-spin" />}
            Approve &amp; Execute
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-[10px] border border-[var(--border-card)] bg-[#19191d] px-3 py-2.5">
      <p className="text-[10.5px] font-bold uppercase tracking-[.5px] text-faint">
        {label}
      </p>
      <p
        className={`mt-0.5 truncate text-[13px] font-semibold text-fg ${mono ? "mono text-[12px]" : ""}`}
      >
        {value}
      </p>
    </div>
  );
}
