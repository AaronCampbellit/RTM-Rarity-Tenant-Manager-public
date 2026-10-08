import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { AlertTriangle, Loader2, Undo2 } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useSetPageTitle } from "@/store/page";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { BackLink, SectionLabel } from "@/components/common/PageToolbar";
import { changeTone } from "@/components/common/status";

export function ChangeDetailPage() {
  useSetPageTitle("Change Detail");
  const { id } = useParams();
  const navigate = useNavigate();
  const { data: c, loading } = useAsync(() => api.changes.get(id ?? ""), [id]);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function revert() {
    if (!c) return;
    setBusy(true);
    setError(null);
    try {
      await api.changes.revert(c.id);
      navigate("/jobs");
    } catch (err) {
      setBusy(false);
      setError(
        err instanceof RtmApiError ? err.message : "The revert could not be queued.",
      );
    }
  }

  if (loading || !c) {
    return (
      <div>
        <BackLink onClick={() => navigate("/changes")}>Change History</BackLink>
        <Card className="p-8 text-center text-[13px] text-muted">Loading…</Card>
      </div>
    );
  }

  const canRevert = c.revertEligible && c.revert === "Available";

  return (
    <div className="space-y-4">
      <BackLink onClick={() => navigate("/changes")}>Change History</BackLink>

      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-[18px] font-bold text-fg-strong">{c.action}</h2>
            <Badge tone={changeTone(c.status)}>{c.status}</Badge>
          </div>
          <p className="text-[12.5px] text-muted">
            {c.target} · {c.timestamp}
          </p>
        </div>
        {canRevert && (
          <Button variant="accent" onClick={() => setConfirming(true)}>
            <Undo2 className="size-4" />
            Revert Change
          </Button>
        )}
      </div>

      {error && (
        <div className="flex items-start gap-2 rounded-[10px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3.5 py-2.5 text-[12.5px] text-[#f7868a]">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <Dialog open={confirming} onClose={() => !busy && setConfirming(false)} width={440}>
        <div className="px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
              <Undo2 className="size-4 text-secondary" />
            </div>
            <h2 className="text-[15px] font-bold text-fg-strong">Revert this change?</h2>
          </div>
          <p className="mt-3 text-[12.5px] leading-relaxed text-muted">
            RTM will queue a job that undoes exactly what this change did (
            <span className="font-semibold text-fg">{c.action}</span> on{" "}
            <span className="font-semibold text-fg">{c.target}</span>), using the
            revert snapshot captured at execution time.
          </p>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="default" onClick={() => setConfirming(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="accent" onClick={revert} disabled={busy}>
              {busy && <Loader2 className="size-4 animate-spin" />}
              Queue Revert
            </Button>
          </div>
        </div>
      </Dialog>

      {/* 4-up cards */}
      <div className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
        <MetaCard label="Technician" value={c.technician} />
        <MetaCard label="Tenant" value={c.tenant} />
        <MetaCard label="Graph Request ID" value={c.graphRequestId} mono />
        <MetaCard
          label="Revert Eligibility"
          value={c.revertEligible ? "Eligible" : "Not supported"}
          tone={c.revertEligible ? "success" : "neutral"}
        />
      </div>

      {/* before / after diff */}
      <div className="grid grid-cols-1 gap-3.5 lg:grid-cols-2">
        <DiffPanel title="Before" lines={c.before} />
        <DiffPanel title="After" lines={c.after} highlight />
      </div>

      {/* execution log */}
      <div>
        <SectionLabel>Execution Log</SectionLabel>
        <Card className="p-4">
          <div className="space-y-1">
            {c.executionLog.map((line, i) => (
              <p key={i} className="mono text-[12px] leading-relaxed text-secondary">
                {line}
              </p>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

function MetaCard({
  label,
  value,
  mono,
  tone,
}: {
  label: string;
  value: string;
  mono?: boolean;
  tone?: "success" | "neutral";
}) {
  return (
    <Card className="p-4">
      <p className="text-[10.5px] font-bold uppercase tracking-[.5px] text-faint">{label}</p>
      {tone ? (
        <div className="mt-2">
          <Badge tone={tone}>{value}</Badge>
        </div>
      ) : (
        <p className={`mt-1.5 break-words text-[13px] font-semibold text-fg ${mono ? "mono text-[12px]" : ""}`}>
          {value}
        </p>
      )}
    </Card>
  );
}

function DiffPanel({
  title,
  lines,
  highlight,
}: {
  title: string;
  lines: string[];
  highlight?: boolean;
}) {
  return (
    <div
      className="overflow-hidden rounded-[12px] border bg-card"
      style={{ borderColor: highlight ? "rgba(63,185,80,.35)" : "var(--border-card)" }}
    >
      <div className="border-b border-[var(--border-card)] px-4 py-2.5">
        <h3 className="text-[12.5px] font-semibold" style={{ color: highlight ? "#56d364" : "#d2d2d8" }}>
          {title}
        </h3>
      </div>
      <div className="space-y-1 p-4">
        {lines.map((l, i) => (
          <p key={i} className="mono text-[12px] text-secondary">
            {l}
          </p>
        ))}
      </div>
    </div>
  );
}
