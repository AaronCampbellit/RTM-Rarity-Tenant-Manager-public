import { StorylineTimeline } from "./StorylineTimeline";
import { useEffect, useState } from "react";
import { AlertTriangle, ArrowRight, CheckCircle2, Clock3, GitBranch, Loader2, ShieldAlert, Target, UserRoundCheck, X } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { SecurityStoryline, SecurityStorylineEvidence, SecurityTriageStatus } from "@/types";
import { securitySeverityTone, securityTriageTone } from "./securityOperations";

const STORYLINE_STAGES: SecurityTriageStatus[] = ["New", "In Progress", "Resolved", "Dismissed"];

export function StorylineDetailDrawer({ storyline, onClose, onChanged }: {
  storyline: SecurityStoryline;
  onClose: () => void;
  onChanged: (storyline: SecurityStoryline) => void;
}) {
  const detail = useAsync(() => api.security.storyline(storyline.id), [storyline.id]);
  const [status, setStatus] = useState<SecurityTriageStatus>(storyline.status);
  const [workflow, setWorkflow] = useState(storyline);
  const [evidenceView, setEvidenceView] = useState<"list" | "timeline">("list");
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    setStatus(storyline.status);
    setWorkflow(storyline);
  }, [storyline]);
  const current = detail.data
    ? { ...detail.data, status: workflow.status, owner: workflow.owner }
    : workflow;

  async function saveStatus() {
    setSaving(true); setError(undefined); setNotice(undefined);
    try {
      const updated = await api.security.triageStoryline(storyline.id, { status });
      setWorkflow(updated);
      onChanged(updated);
      setNotice("Storyline status updated.");
    } catch (caught) {
      setError(caught instanceof RtmApiError ? caught.message : "The storyline could not be updated.");
    } finally { setSaving(false); }
  }

  async function assignToMe() {
    setSaving(true); setError(undefined); setNotice(undefined);
    try {
      const updated = await api.security.triageStoryline(storyline.id, { assignment: "me", status: current.status === "New" ? "In Progress" : current.status });
      setWorkflow(updated);
      onChanged(updated);
      setStatus(updated.status);
      setNotice("Storyline accepted and assigned to you.");
    } catch (caught) {
      setError(caught instanceof RtmApiError ? caught.message : "The storyline could not be assigned.");
    } finally { setSaving(false); }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/55 backdrop-blur-[2px]" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside role="dialog" aria-modal="true" aria-labelledby="storyline-title" className="ml-auto flex h-full w-full max-w-[760px] flex-col border-l border-[var(--border-strong)] bg-card shadow-[-20px_0_60px_rgba(0,0,0,.45)]">
        <header className="border-b border-[var(--border-card)] px-5 py-4">
          <div className="flex items-start gap-3">
            <div className="grid size-10 shrink-0 place-items-center rounded-[10px] bg-danger/10"><ShieldAlert className="size-5 text-danger" /></div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={securitySeverityTone(current.severity)}>{current.severity}</Badge>
                <span className="text-[12px] font-bold text-fg-strong">{current.riskScore} risk</span>
                <Badge tone={securityTriageTone(current.status)}>{current.status}</Badge>
                <span className="text-[11px] capitalize text-muted">{current.confidence} confidence</span>
              </div>
              <h2 id="storyline-title" className="mt-2 text-[17px] font-bold leading-6 text-fg-strong">{current.title}</h2>
              <p className="mt-1 text-[11.5px] text-muted">{current.tenantNames.join(" · ")} · {current.signalCount} connected signals</p>
            </div>
            <button type="button" onClick={onClose} aria-label="Close storyline details" className="rounded-[7px] p-1.5 text-muted hover:bg-raised hover:text-fg"><X className="size-4.5" /></button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto px-5 py-4">
          {detail.loading ? <div className="grid min-h-80 place-items-center"><Loader2 className="size-5 animate-spin text-muted" /></div> : detail.error ? (
            <div role="alert" className="rounded-[9px] border border-danger/25 bg-[var(--bg-danger)] p-3 text-[12px] text-danger">{detail.error.message}</div>
          ) : detail.data ? (
            <div className="space-y-5">
              <section>
                <h3 className="text-[10.5px] font-bold uppercase tracking-wide text-faint">What RTM believes happened</h3>
                <p className="mt-2 text-[12.5px] leading-5 text-secondary">{detail.data.summary}</p>
                <div className="mt-3 flex flex-wrap items-center gap-1.5">
                  {detail.data.stages.map((stage, index) => <span key={stage} className="inline-flex items-center gap-1.5 rounded-full border border-[var(--border-card)] bg-raised px-2.5 py-1 text-[10.5px] font-semibold text-fg">{index > 0 ? <ArrowRight className="size-3 text-faint" /> : null}{stage}</span>)}
                </div>
              </section>

              <section>
                <h3 className="text-[10.5px] font-bold uppercase tracking-wide text-faint">Why these signals are connected</h3>
                <div className="mt-2 space-y-2">
                  {detail.data.reasons.map((reason) => <div key={reason} className="flex gap-2 rounded-[8px] border border-[var(--border-card)] bg-raised/40 px-3 py-2 text-[11.5px] leading-4.5 text-secondary"><GitBranch className="mt-0.5 size-3.5 shrink-0 text-info" />{reason}</div>)}
                </div>
              </section>

              <section>
                <h3 className="text-[10.5px] font-bold uppercase tracking-wide text-faint">Blast radius</h3>
                <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
                  <Fact label="Tenants" value={String(detail.data.tenantIds.length)} />
                  <Fact label="Accounts" value={String(detail.data.affectedUsers)} />
                  <Fact label="Resources" value={String(detail.data.affectedResources)} />
                  <Fact label="Workloads" value={String(detail.data.workloads.length)} />
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">{detail.data.entities.map((entity) => <Badge key={entity.key} tone={entity.primary ? "danger" : "neutral"} dot={false}>{entity.type}: {entity.label}</Badge>)}</div>
              </section>

              <section>
                <h3 className="text-[10.5px] font-bold uppercase tracking-wide text-faint">Recommended next actions</h3>
                <ol className="mt-2 space-y-2">{detail.data.recommendedActions.map((action, index) => <li key={action} className="flex gap-2.5 rounded-[8px] border border-[var(--border-card)] px-3 py-2.5 text-[11.5px] text-secondary"><span className="grid size-5 shrink-0 place-items-center rounded-full bg-danger/10 text-[10px] font-bold text-danger">{index + 1}</span>{action}</li>)}</ol>
                <p className="mt-2 text-[10.5px] text-muted">Guidance only. Any tenant change still runs through RTM What-If approval.</p>
              </section>

              {(detail.data.weakEvidence?.length ?? 0) > 0 ? <section><h3 className="text-[10.5px] font-bold uppercase tracking-wide text-faint">Conflicting or weak evidence</h3><div className="mt-2 rounded-[8px] border border-warning/25 bg-warning/5 px-3 py-2.5 text-[11.5px] text-secondary">{detail.data.weakEvidence?.join(" ")}</div></section> : null}

              <section>
                <h3 className="text-[10.5px] font-bold uppercase tracking-wide text-faint">Complete evidence chain</h3>
                <div role="group" aria-label="Evidence view" className="mt-3 flex gap-2">
                  <Button size="sm" aria-pressed={evidenceView === "list"} variant={evidenceView === "list" ? "accent" : "default"} onClick={() => setEvidenceView("list")}>List</Button>
                  <Button size="sm" aria-pressed={evidenceView === "timeline"} variant={evidenceView === "timeline" ? "accent" : "default"} onClick={() => setEvidenceView("timeline")}>Timeline</Button>
                </div>
                {evidenceView === "timeline" ? <StorylineTimeline key={storyline.id} items={detail.data.evidence} occurredAt={signalTime} getKey={signalKey} label="Storyline evidence timeline" unit="signals" description="Signals are positioned by occurrence time, not attack-stage order. Select a date and hour to review the supporting evidence." renderItem={(item) => <StorylineEvidenceCard item={item} />} /> : <div className="relative mt-3 space-y-3 before:absolute before:bottom-2 before:left-[9px] before:top-2 before:w-px before:bg-[var(--border-strong)]">
                  {detail.data.evidence.map((item) => (
                    <article key={item.detectionId} className="relative pl-7">
                      <span className="absolute left-1 top-1.5 size-2.5 rounded-full border-2 border-card bg-accent" />
                      <StorylineEvidenceCard item={item} />
                    </article>
                  ))}
                </div>}
              </section>
            </div>
          ) : null}
        </div>

        <footer className="border-t border-[var(--border-card)] bg-card px-5 py-4">
          {notice ? <div role="status" className="mb-2 flex items-center gap-2 text-[11.5px] text-success"><CheckCircle2 className="size-3.5" />{notice}</div> : null}
          {error ? <div role="alert" className="mb-2 flex items-center gap-2 text-[11.5px] text-danger"><AlertTriangle className="size-3.5" />{error}</div> : null}
          <div className="flex flex-col gap-2 sm:flex-row">
            <select aria-label="Storyline status" className="h-9 flex-1 rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[12px] text-fg" value={status} onChange={(event) => setStatus(event.target.value as SecurityTriageStatus)}>{STORYLINE_STAGES.map((stage) => <option key={stage}>{stage}</option>)}</select>
            <Button onClick={() => void saveStatus()} disabled={saving || status === current.status}>{saving ? <Loader2 className="animate-spin" /> : <Target />}Save status</Button>
            <Button variant="accent" onClick={() => void assignToMe()} disabled={saving}><UserRoundCheck />Accept & assign to me</Button>
          </div>
        </footer>
      </aside>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div className="rounded-[8px] border border-[var(--border-card)] bg-raised/35 px-3 py-2"><p className="text-[9.5px] font-bold uppercase tracking-wide text-faint">{label}</p><p className="mt-1 text-[15px] font-bold text-fg-strong">{value}</p></div>;
}

function signalTime(item: SecurityStorylineEvidence) { return item.occurredAt; }
function signalKey(item: SecurityStorylineEvidence) { return `${item.tenantId}:${item.detectionId}`; }
function StorylineEvidenceCard({ item }: { item: SecurityStorylineEvidence }) {
  return (<div className="rounded-[9px] border border-[var(--border-card)] bg-raised/35 p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2"><div className="flex items-center gap-2"><Badge tone={securitySeverityTone(item.severity)}>{item.severity}</Badge><span className="text-[10.5px] font-semibold text-info">{item.stage}</span></div><span className="inline-flex items-center gap-1 text-[10.5px] text-muted"><Clock3 className="size-3" />{new Date(item.occurredAt).toLocaleString()}</span></div>
                        <h4 className="mt-2 text-[12.5px] font-semibold text-fg">{item.title}</h4>
                        <p className="mt-0.5 text-[10.5px] text-muted">{item.tenantName} · {item.ruleId} · {item.confidence} confidence</p>
                        {item.events.map((event) => <div key={event.eventId} className="mt-2 border-t border-[var(--border-card)] pt-2 text-[11px] leading-4.5 text-secondary"><strong className="text-fg">{event.operation}</strong>{event.actor ? ` by ${event.actor}` : ""}{event.target ? ` → ${event.target}` : ""}{event.clientIp ? ` from ${event.clientIp}` : ""}</div>)}
                      </div>);
}
