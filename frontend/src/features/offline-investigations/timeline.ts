import type { OfflineTimelineEvent, OfflineTimelineFact, OfflineTimelineSignal } from "@/types";

export type TimelineFocus = "all" | "signals" | "failures" | "external";

export interface TimelineFilters {
  query: string;
  focus: TimelineFocus;
  workload: string;
}

export interface TimelineActivityGroup {
  id: string;
  operation: string;
  workload: string;
  actor?: string;
  clientIp?: string;
  objectId?: string;
  resultStatus?: string;
  evidenceType: string;
  source: string;
  severity?: string;
  newestAt: string;
  oldestAt: string;
  events: OfflineTimelineEvent[];
  facts: OfflineTimelineFact[];
  signals: OfflineTimelineSignal[];
}

const BURST_WINDOW_MS = 15 * 60 * 1000;

export function filterTimelineEvents(events: OfflineTimelineEvent[], filters: TimelineFilters): OfflineTimelineEvent[] {
  const needle = filters.query.trim().toLocaleLowerCase();
  return events.filter((event) => {
    if (filters.workload && event.workload !== filters.workload) return false;
    if (filters.focus === "signals" && (event.signals ?? []).length === 0) return false;
    if (filters.focus === "failures" && isSuccessfulResult(event.resultStatus)) return false;
    if (filters.focus === "external" && !(event.facts ?? []).some((fact) => fact.label === "Access" && fact.value === "External")) return false;
    if (!needle) return true;
    const searchable = [
      event.operation, event.workload, event.actor, event.clientIp, event.objectId,
      event.resultStatus, event.source,
      ...(event.facts ?? []).flatMap((fact) => [fact.label, fact.value]),
      ...(event.signals ?? []).flatMap((signal) => [signal.title, signal.ruleId, signal.severity]),
    ].filter(Boolean).join(" ").toLocaleLowerCase();
    return searchable.includes(needle);
  });
}

export function groupTimelineEvents(events: OfflineTimelineEvent[]): TimelineActivityGroup[] {
  const sorted = [...events].sort((left, right) => Date.parse(right.occurredAt) - Date.parse(left.occurredAt));
  const groups: TimelineActivityGroup[] = [];
  const latestByKey = new Map<string, TimelineActivityGroup>();
  for (const event of sorted) {
    const key = timelineGroupKey(event);
    const existing = latestByKey.get(key);
    const eventTime = Date.parse(event.occurredAt);
    const oldestTime = existing ? Date.parse(existing.oldestAt) : Number.NaN;
    if (existing && oldestTime-eventTime <= BURST_WINDOW_MS) {
      existing.events.push(event);
      existing.oldestAt = event.occurredAt;
      mergeFacts(existing.facts, event.facts ?? []);
      mergeSignals(existing.signals, event.signals ?? []);
      existing.severity = higherSeverity(existing.severity, event.severity);
      continue;
    }
    const group: TimelineActivityGroup = {
      id: event.id, operation: event.operation, workload: event.workload, actor: event.actor,
      clientIp: event.clientIp, objectId: event.objectId, resultStatus: event.resultStatus,
      evidenceType: event.evidenceType, source: event.source, severity: event.severity,
      newestAt: event.occurredAt, oldestAt: event.occurredAt, events: [event],
      facts: [...(event.facts ?? [])], signals: [...(event.signals ?? [])],
    };
    groups.push(group);
    latestByKey.set(key, group);
  }
  return groups;
}

export function timelineWorkloads(events: OfflineTimelineEvent[]): string[] {
  return [...new Set(events.map((event) => event.workload).filter(Boolean))].sort((left, right) => left.localeCompare(right));
}

function timelineGroupKey(event: OfflineTimelineEvent): string {
  const application = (event.facts ?? []).find((fact) => fact.label === "Application")?.value ?? "";
  const access = (event.facts ?? []).find((fact) => fact.label === "Access")?.value ?? "";
  return [event.operation, event.workload, event.actor, event.clientIp, event.objectId, event.resultStatus, application, access]
    .map((value) => value?.trim().toLocaleLowerCase() ?? "").join("|");
}

function isSuccessfulResult(result?: string): boolean {
  if (!result) return true;
  return ["success", "succeeded", "0"].includes(result.trim().toLocaleLowerCase());
}

function mergeFacts(target: OfflineTimelineFact[], incoming: OfflineTimelineFact[]) {
  const seen = new Set(target.map((fact) => `${fact.label}\u0000${fact.value}`));
  for (const fact of incoming) {
    const key = `${fact.label}\u0000${fact.value}`;
    if (!seen.has(key)) {
      target.push(fact);
      seen.add(key);
    }
  }
}

function mergeSignals(target: OfflineTimelineSignal[], incoming: OfflineTimelineSignal[]) {
  const seen = new Set(target.map((signal) => `${signal.ruleId}\u0000${signal.title}`));
  for (const signal of incoming) {
    const key = `${signal.ruleId}\u0000${signal.title}`;
    if (!seen.has(key)) {
      target.push(signal);
      seen.add(key);
    }
  }
}

function higherSeverity(left?: string, right?: string): string | undefined {
  const rank: Record<string, number> = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };
  return (rank[right ?? ""] ?? 0) > (rank[left ?? ""] ?? 0) ? right : left;
}
