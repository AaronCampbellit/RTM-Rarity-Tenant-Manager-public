import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  BellRing,
  Check,
  Clock3,
  Loader2,
  UserRoundCheck,
  UserRoundX,
  X,
} from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/store/auth";
import type {
  SecurityIncident,
  SecurityIncidentDetail,
  SecurityTriageRequest,
  SecurityTriageStatus,
} from "@/types";
import {
  relativeSecurityTime,
  friendlySecurityEntityLabel,
  safeSecurityIncidentUrl,
  securityIncidentReceivedAt,
  securityWorkloadLabel,
  securitySeverityTone,
  securityTriageTone,
} from "./securityOperations";
import { IncidentRemediationPlan } from "./IncidentRemediationPlan";

const TRIAGE_STATUSES: SecurityTriageStatus[] = [
  "New",
  "In Progress",
  "Resolved",
  "Dismissed",
];

export function IncidentDetailDrawer({
  incident,
  onClose,
  onChanged,
}: {
  incident: SecurityIncident;
  onClose: () => void;
  onChanged: (incident: SecurityIncidentDetail) => void;
}) {
  const { user } = useAuth();
  const query = useAsync(
    () => api.security.incident(incident.tenantId, incident.id),
    [incident.tenantId, incident.id],
  );
  const [detail, setDetail] = useState<SecurityIncidentDetail>();
  const [status, setStatus] = useState<SecurityTriageStatus>(incident.status);
  const [saving, setSaving] = useState(false);
  const [actionError, setActionError] = useState<string>();

  useEffect(() => {
    if (!query.data) return;
    setDetail(query.data);
    setStatus(query.data.status);
  }, [query.data]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function triage(body: SecurityTriageRequest) {
    setSaving(true);
    setActionError(undefined);
    try {
      const updated = await api.security.triage(incident.tenantId, incident.id, body);
      setDetail(updated);
      setStatus(updated.status);
      onChanged(updated);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "The triage update failed.");
    } finally {
      setSaving(false);
    }
  }

  const current = detail ?? incident;
  const assignedToMe = !!current.owner && current.owner === user?.name;
  const incidentWebUrl = safeSecurityIncidentUrl(current.incidentWebUrl);
  const readableEntities = detail?.entities
    ?.map((entity) => ({ ...entity, label: friendlySecurityEntityLabel(entity.label) }))
    .filter((entity, index, all) => entity.label && all.findIndex((item) => item.type === entity.type && item.label === entity.label) === index);

  return createPortal(
    <div className="fixed inset-0 z-50 animate-fade" aria-hidden={false}>
      <button
        aria-label="Close incident details"
        className="absolute inset-0 cursor-default bg-black/50 backdrop-blur-[1px]"
        onClick={onClose}
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-labelledby="security-incident-title"
        className="absolute inset-y-0 right-0 flex w-full max-w-[590px] animate-[drawer-in_.2s_ease-out] flex-col border-l border-[var(--border-strong)] bg-sidebar shadow-[var(--shadow-drawer)]"
      >
        <div className="border-b border-[var(--border-card)] px-5 py-4">
          <div className="flex items-start gap-3">
            <Badge tone={securitySeverityTone(current.severity)} className="mt-0.5">
              {current.severity}
            </Badge>
            <div className="min-w-0 flex-1">
              <h2 id="security-incident-title" className="text-[17px] font-bold leading-6 text-fg-strong">
                {current.title}
              </h2>
              <p className="mt-1 text-[12px] text-muted">
                {current.tenantName} · {current.source} · {current.id}
              </p>
            </div>
            <Button variant="ghost" size="icon" aria-label="Close" onClick={onClose}>
              <X />
            </Button>
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <Badge tone={securityTriageTone(current.status)}>{current.status}</Badge>
            <span className="text-[12px] text-muted">
              {current.owner ? `Owned by ${current.owner}` : "Unassigned"}
            </span>
            <span className="text-faint">·</span>
            <span className="inline-flex items-center gap-1 text-[12px] text-muted">
              <Clock3 className="size-3.5" /> Received by RTM {relativeSecurityTime(securityIncidentReceivedAt(current))}
            </span>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-5">
          {query.loading && (
            <div className="grid min-h-64 place-items-center">
              <div className="text-center">
                <Loader2 className="mx-auto size-5 animate-spin text-muted" />
                <p className="mt-2 text-[12px] text-muted">Loading incident evidence…</p>
              </div>
            </div>
          )}
          {query.error && (
            <div className="rounded-[10px] border border-accent/30 bg-[var(--bg-danger)] p-4 text-[12.5px] text-danger">
              {query.error.message}
            </div>
          )}
          {!query.loading && !query.error && detail && (
            <div className="space-y-6">
              <section>
                <SectionHeading>Incident summary</SectionHeading>
                <p className="text-[13px] leading-5 text-body">
                  {detail.description || "Microsoft did not provide an incident description."}
                </p>
              </section>

              {detail.evidence && (
                <section>
                  <SectionHeading>What happened</SectionHeading>
                  <div className="rounded-[10px] border border-[var(--border-card)] bg-card p-3.5">
                    <EvidenceFact label="Action" value={detail.evidence.operation} wide />
                    <div className="mt-3 grid gap-3 sm:grid-cols-2">
                      <EvidenceFact label="Actor" value={detail.evidence.actor || "Unknown actor"} />
                      <EvidenceFact label="Target" value={detail.evidence.target || "Target not identified"} />
                      {detail.evidence.relatedResource && <EvidenceFact label="Related service or resource" value={detail.evidence.relatedResource} />}
                      <EvidenceFact label="Workload" value={securityWorkloadLabel(detail.evidence.workload)} />
                      <EvidenceFact label="Result" value={detail.evidence.resultStatus || "Unknown"} />
                      <EvidenceFact label="Occurred" value={new Date(detail.evidence.occurredAt).toLocaleString()} />
                      {detail.evidence.clientIp && <EvidenceFact label="Client IP" value={detail.evidence.clientIp} />}
                    </div>
                    {!!detail.evidence.changes?.length && (
                      <div className="mt-4 border-t border-[var(--border-card)] pt-3">
                        <p className="mb-2 text-[10px] font-bold uppercase tracking-[.4px] text-faint">Key changes</p>
                        <div className="space-y-2">
                          {detail.evidence.changes.map((change) => (
                            <div key={`${change.field}-${change.before}-${change.after}`} className="rounded-[8px] bg-raised px-3 py-2.5">
                              <p className="text-[11px] font-semibold text-secondary">{change.field}</p>
                              <div className="mt-1 flex min-w-0 items-center gap-2 text-[12px] text-body">
                                <span className="min-w-0 break-words">{change.before || "Not set"}</span>
                                <ArrowRight className="size-3.5 shrink-0 text-faint" />
                                <span className="min-w-0 break-words font-semibold text-fg">{change.after || "Removed"}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </section>
              )}

              <IncidentRemediationPlan plan={detail.remediation} />

              <section>
                <SectionHeading>RTM triage</SectionHeading>
                <div className="rounded-[10px] border border-[var(--border-card)] bg-card p-3.5">
                  <p className="mb-3 text-[11.5px] leading-4 text-muted">
                    Local workflow only — assignment and status changes are audited in RTM and do not mutate the source provider.
                  </p>
                  <div className="flex flex-col gap-2 sm:flex-row">
                    <select
                      aria-label="Triage status"
                      value={status}
                      onChange={(event) => setStatus(event.target.value as SecurityTriageStatus)}
                      className="h-9 min-w-0 flex-1 rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none focus:border-[var(--ac)]/50"
                    >
                      {TRIAGE_STATUSES.map((item) => (
                        <option key={item}>{item}</option>
                      ))}
                    </select>
                    <Button
                      variant="accent"
                      disabled={saving || status === detail.status}
                      onClick={() => void triage({ status })}
                    >
                      {saving ? <Loader2 className="animate-spin" /> : <Check />}
                      Save status
                    </Button>
                  </div>
                  <Button
                    className="mt-2 w-full"
                    disabled={saving}
                    onClick={() =>
                      void triage({ assignment: assignedToMe ? "unassigned" : "me" })
                    }
                  >
                    {assignedToMe ? <UserRoundX /> : <UserRoundCheck />}
                    {assignedToMe ? "Unassign from me" : "Assign to me"}
                  </Button>
                  {actionError && (
                    <p role="alert" className="mt-2 text-[12px] text-danger">
                      {actionError}
                    </p>
                  )}
                </div>
              </section>

              <section>
                <SectionHeading>Affected entities</SectionHeading>
                {readableEntities?.length ? (
                  <div className="flex flex-wrap gap-2">
                    {readableEntities.map((entity) => (
                      <div
                        key={`${entity.type}-${entity.label}`}
                        className="rounded-[8px] border border-[var(--border-card)] bg-card px-3 py-2"
                      >
                        <p className="text-[10px] font-bold uppercase tracking-[.4px] text-faint">
                          {entity.type}
                        </p>
                        <p className="mt-0.5 text-[12.5px] font-medium text-fg">{entity.label}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-[12px] text-muted">No normalized entities were returned.</p>
                )}
              </section>

              <section>
                <SectionHeading>Correlated alerts</SectionHeading>
                <div className="space-y-2">
                  {detail.alerts.map((alert) => (
                    <div key={alert.id} className="rounded-[10px] border border-[var(--border-card)] bg-card p-3.5">
                      <div className="flex items-start gap-2.5">
                        <BellRing className="mt-0.5 size-4 shrink-0 text-secondary" />
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <p className="text-[12.5px] font-semibold text-fg">{alert.title}</p>
                            <Badge tone={securitySeverityTone(alert.severity)}>{alert.severity}</Badge>
                          </div>
                          <p className="mt-1 text-[11.5px] text-muted">
                            {alert.serviceSource} · {relativeSecurityTime(alert.updatedAt)}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section>
                <SectionHeading>Evidence timeline</SectionHeading>
                <div className="relative ml-1 border-l border-[var(--border-strong)] pl-5">
                  {detail.timeline.map((event) => (
                    <div key={event.id} className="relative pb-5 last:pb-0">
                      <span className="absolute -left-[24.5px] top-1.5 size-2 rounded-full border-2 border-sidebar bg-info" />
                      <p className="text-[12.5px] font-semibold text-fg">{event.title}</p>
                      <p className="mt-0.5 text-[11.5px] text-muted">
                        {new Date(event.timestamp).toLocaleString()} · {event.source}
                      </p>
                      {event.description && (
                        <p className="mt-1 text-[12px] leading-4 text-secondary">{event.description}</p>
                      )}
                    </div>
                  ))}
                </div>
              </section>

              <details className="rounded-[10px] border border-[var(--border-card)] bg-card">
                <summary className="cursor-pointer px-3.5 py-3 text-[12px] font-semibold text-secondary hover:text-fg">
                  Provider and detection metadata
                </summary>
                <div className="grid grid-cols-2 gap-2 border-t border-[var(--border-card)] p-3.5">
                  <Fact label="Provider status" value={detail.providerStatus || "—"} />
                  <Fact label="Alerts" value={String(detail.alertCount)} />
                  <Fact label="Classification" value={detail.classification || "Not set"} />
                  <Fact label="Determination" value={detail.determination || "Not set"} />
                  <Fact label="Provider owner" value={detail.providerOwner || "Unassigned"} />
                  <Fact label="Received by RTM" value={readableDateTime(securityIncidentReceivedAt(detail))} preserveCase />
                  <Fact label="Created" value={new Date(detail.createdAt).toLocaleString()} preserveCase />
                  {detail.detectionType && <Fact label="Detection type" value={detail.detectionType} />}
                  {detail.confidence && <Fact label="Confidence" value={detail.confidence} />}
                  {detail.ruleId && <Fact label="Rule" value={`${detail.ruleId} v${detail.ruleVersion ?? 1}`} wide preserveCase />}
                  <Fact label="Incident ID" value={detail.id} wide preserveCase />
                  {detail.evidence?.eventId && <Fact label="Source event ID" value={detail.evidence.eventId} wide preserveCase />}
                </div>
              </details>
            </div>
          )}
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-[var(--border-card)] bg-card px-5 py-3.5">
          <span className="inline-flex items-center gap-1.5 text-[11.5px] text-muted">
            {current.sample ? (
              <><AlertTriangle className="size-3.5 text-warning" /> Sample evidence</>
            ) : (
              <><Check className="size-3.5 text-success" /> Live {current.source} evidence</>
            )}
          </span>
          {incidentWebUrl && !current.sample && (
            <a
              href={incidentWebUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex h-9 items-center gap-2 rounded-[8px] border border-[var(--border-strong)] bg-control px-3.5 text-[13px] font-semibold text-body hover:bg-hover hover:text-fg"
            >
              Open in Defender <ArrowUpRight className="size-4" />
            </a>
          )}
        </div>
      </aside>
    </div>,
    document.body,
  );
}

function SectionHeading({ children }: { children: string }) {
  return (
    <h3 className="mb-2 text-[10.5px] font-bold uppercase tracking-[.5px] text-faint">
      {children}
    </h3>
  );
}

function EvidenceFact({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={wide ? "" : "min-w-0"}>
      <p className="text-[10px] font-bold uppercase tracking-[.4px] text-faint">{label}</p>
      <p className="mt-1 break-words text-[12.5px] font-medium leading-5 text-fg">{value}</p>
    </div>
  );
}

function Fact({
  label,
  value,
  wide = false,
  preserveCase = false,
}: {
  label: string;
  value: string;
  wide?: boolean;
  preserveCase?: boolean;
}) {
  return (
    <div className={`rounded-[8px] bg-raised px-3 py-2.5 ${wide ? "col-span-2" : ""}`}>
      <p className="text-[10px] font-bold uppercase tracking-[.4px] text-faint">{label}</p>
      <p
        className={`mt-1 text-[12px] font-medium text-body ${wide ? "break-all" : "truncate"} ${preserveCase ? "" : "capitalize"}`}
        title={value}
      >
        {value}
      </p>
    </div>
  );
}

function readableDateTime(value: string): string {
  const timestamp = new Date(value).getTime();
  return Number.isFinite(timestamp) ? new Date(timestamp).toLocaleString() : "—";
}
