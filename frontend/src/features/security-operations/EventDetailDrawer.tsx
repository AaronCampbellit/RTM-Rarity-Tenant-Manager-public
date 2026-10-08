import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, Braces, Loader2, Plus, X } from "lucide-react";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/api/hooks";
import { hasPermission, useAuth } from "@/store/auth";
import type {
  SecurityAuditEvent,
  SecurityAuditEventEvidence,
  SecurityDetectionRule,
} from "@/types";
import { securitySeverityTone } from "./securityOperations";
import { newSecurityRule } from "./securityRules";
import { RuleEditorDrawer } from "./RuleEditorDrawer";

export function EventDetailDrawer({
  event,
  onClose,
}: {
  event: SecurityAuditEvent;
  onClose: () => void;
}) {
  const { user } = useAuth();
  const query = useAsync(
    () => api.security.event(event.tenantId, event.id),
    [event.tenantId, event.id],
  );
  const [draft, setDraft] = useState<SecurityDetectionRule>();

  useEffect(() => {
    const onKey = (item: KeyboardEvent) => item.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      {createPortal(
        <div className="fixed inset-0 z-50 animate-fade">
          <button
            aria-label="Close event details"
            className="absolute inset-0 cursor-default bg-black/55 backdrop-blur-[1px]"
            onClick={onClose}
          />
          <aside
            role="dialog"
            aria-modal="true"
            aria-labelledby="event-detail-title"
            className="absolute inset-y-0 right-0 flex w-full max-w-[720px] animate-[drawer-in_.2s_ease-out] flex-col border-l border-[var(--border-strong)] bg-sidebar shadow-[var(--shadow-drawer)]"
          >
            <div className="flex items-start gap-3 border-b border-[var(--border-card)] px-5 py-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <Braces className="size-4 text-[var(--ac)]" />
                  <h2
                    id="event-detail-title"
                    className="truncate text-[17px] font-bold text-fg-strong"
                  >
                    {event.operation}
                  </h2>
                </div>
                <p className="mono mt-1 truncate text-[11px] text-muted">
                  {event.tenantName} · {event.providerRecordId}
                </p>
              </div>
              {hasPermission(user, "security.manage") && (
                <Button onClick={() => setDraft(newSecurityRule(event))}>
                  <Plus />
                  Create rule from event
                </Button>
              )}
              <Button variant="ghost" size="icon" aria-label="Close" onClick={onClose}>
                <X />
              </Button>
            </div>

            <div className="flex-1 overflow-y-auto px-5 py-5">
              {query.loading && (
                <div className="grid min-h-64 place-items-center">
                  <Loader2 className="size-5 animate-spin text-muted" />
                </div>
              )}
              {query.error && (
                <p className="flex gap-2 rounded-[8px] bg-[var(--bg-danger)] p-3 text-[12px] text-danger">
                  <AlertTriangle className="size-4" />
                  {query.error.message}
                </p>
              )}
              {query.data && (
                <div className="space-y-6">
                  <section>
                    <Heading>Normalized event</Heading>
                    <div className="grid gap-2 sm:grid-cols-2">
                      <Fact label="Tenant" value={query.data.tenantName} />
                      <Fact
                        label="Source"
                        value={query.data.sources.map(sourceLabel).join(" + ")}
                      />
                      <Fact label="Workload" value={query.data.workload} />
                      <Fact label="Result" value={query.data.resultStatus || "—"} />
                      <Fact label="Actor" value={query.data.actor || "—"} />
                      <Fact label="Client IP" value={query.data.clientIp || "—"} />
                      <Fact label="Object" value={query.data.objectId || "—"} wide />
                      <Fact label="Content type" value={query.data.contentType} wide />
                    </div>
                  </section>

                  <section>
                    <Heading>Event pipeline latency</Heading>
                    <p className="mb-2 text-[11.5px] text-muted">
                      Microsoft does not expose its internal publication timestamp. “First
                      observed” is the earliest time RTM could retrieve the record.
                    </p>
                    <div className="grid gap-2 sm:grid-cols-2">
                      <Fact label="1 · Occurred" value={timeWithDelta(query.data.occurredAt)} />
                      <Fact
                        label="2 · First observed from Microsoft"
                        value={timeWithDelta(query.data.availableAt, query.data.occurredAt)}
                      />
                      <Fact
                        label="3 · Stored by RTM"
                        value={timeWithDelta(query.data.ingestedAt, query.data.availableAt)}
                      />
                      <Fact
                        label="4 · Detection created"
                        value={
                          query.data.relatedDetections.length
                            ? timeWithDelta(
                                earliestDetection(query.data.relatedDetections),
                                query.data.ingestedAt,
                              )
                            : "No matching rule"
                        }
                      />
                    </div>
                  </section>

                  <section>
                    <Heading>Related detections</Heading>
                    {query.data.relatedDetections.length ? (
                      <div className="space-y-2">
                        {query.data.relatedDetections.map((detection) => (
                          <div
                            key={detection.id}
                            className="rounded-[9px] border border-[var(--border-card)] bg-card p-3"
                          >
                            <div className="flex items-center gap-2">
                              <Badge tone={securitySeverityTone(detection.severity)}>
                                {detection.severity}
                              </Badge>
                              <span className="text-[12.5px] font-semibold text-fg">
                                {detection.title}
                              </span>
                            </div>
                            <p className="mono mt-2 text-[10.5px] text-muted">
                              {detection.ruleId} · v{detection.ruleVersion}
                            </p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="rounded-[8px] border border-[var(--border-card)] bg-card p-3 text-[12px] text-muted">
                        No detection currently references this event.
                      </p>
                    )}
                  </section>

                  <section>
                    <Heading>
                      {query.data.sourceEvidence.length
                        ? "Source-native provider evidence"
                        : "Redacted provider evidence"}
                    </Heading>
                    <p className="mb-2 text-[11.5px] text-muted">
                      Secrets and token-like fields are removed recursively before this
                      response leaves the API. Semantically equivalent provider records remain
                      separate below.
                    </p>
                    {query.data.sourceEvidence.length ? (
                      <div className="space-y-3">
                        {query.data.sourceEvidence.map((evidence) => (
                          <ProviderEvidence
                            key={`${evidence.source}:${evidence.providerRecordId}`}
                            evidence={evidence}
                          />
                        ))}
                      </div>
                    ) : (
                      <EvidenceJSON raw={query.data.raw} truncated={query.data.rawTruncated} />
                    )}
                  </section>
                </div>
              )}
            </div>
          </aside>
        </div>,
        document.body,
      )}
      {draft && (
        <RuleEditorDrawer
          initial={draft}
          onClose={() => setDraft(undefined)}
          onSaved={() => {
            setDraft(undefined);
            onClose();
          }}
        />
      )}
    </>
  );
}

function ProviderEvidence({ evidence }: { evidence: SecurityAuditEventEvidence }) {
  return (
    <div className="overflow-hidden rounded-[10px] border border-[var(--border-card)] bg-card">
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--border-card)] px-3 py-2.5">
        <span className="text-[12px] font-semibold text-fg">{sourceLabel(evidence.source)}</span>
        <span className="mono text-[10px] text-muted">{evidence.contentType}</span>
        {evidence.rawTruncated && <Badge tone="warning">Truncated</Badge>}
        <span className="ml-auto text-[10px] text-faint">
          Observed {new Date(evidence.availableAt).toLocaleString()}
        </span>
      </div>
      <pre className="max-h-[420px] overflow-auto bg-[#0d0d10] p-4 text-[11.5px] leading-5 text-[#c4c4cb]">
        {JSON.stringify(evidence.raw, null, 2)}
      </pre>
    </div>
  );
}

function EvidenceJSON({ raw, truncated }: { raw: unknown; truncated: boolean }) {
  return (
    <div>
      {truncated && <Badge tone="warning">Truncated</Badge>}
      <pre className="mt-2 max-h-[560px] overflow-auto rounded-[10px] border border-[var(--border-card)] bg-[#0d0d10] p-4 text-[11.5px] leading-5 text-[#c4c4cb]">
        {JSON.stringify(raw, null, 2)}
      </pre>
    </div>
  );
}

function Heading({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="mb-2 text-[11px] font-bold uppercase tracking-[.5px] text-faint">
      {children}
    </h3>
  );
}

function Fact({ label, value, wide }: { label: string; value: string; wide?: boolean }) {
  return (
    <div
      className={`rounded-[8px] border border-[var(--border-card)] bg-card px-3 py-2.5 ${wide ? "sm:col-span-2" : ""}`}
    >
      <p className="text-[10px] font-bold uppercase tracking-[.4px] text-faint">{label}</p>
      <p className="mt-1 break-all text-[12px] text-body">{value}</p>
    </div>
  );
}

function sourceLabel(source: string) {
  return source === "entra_graph"
    ? "Entra Graph fast lane"
    : source === "m365_audit"
      ? "Microsoft 365 audit"
      : source;
}

function earliestDetection(detections: Array<{ createdAt: string }>) {
  return detections.reduce(
    (earliest, item) => (item.createdAt < earliest ? item.createdAt : earliest),
    detections[0].createdAt,
  );
}

function timeWithDelta(value: string, previous?: string) {
  const formatted = new Date(value).toLocaleString();
  if (!previous) return formatted;
  const milliseconds = Math.max(0, new Date(value).getTime() - new Date(previous).getTime());
  const delay =
    milliseconds < 60_000
      ? `${Math.round(milliseconds / 1000)}s`
      : milliseconds < 3_600_000
        ? `${Math.round(milliseconds / 60_000)}m`
        : `${(milliseconds / 3_600_000).toFixed(1)}h`;
  return `${formatted} (+${delay})`;
}
