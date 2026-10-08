import { useEffect, useMemo, useState } from "react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { SecurityAuditEvent, SecurityAuditEventSearch } from "@/types";
import { timelineDays, timelineDaySearch } from "./eventTimeline";

export function EventTimeline({ search, onSelect }: { search: SecurityAuditEventSearch; onSelect: (event: SecurityAuditEvent) => void }) {
  const days = useMemo(() => timelineDays(search), [search]);
  const [dayKey, setDayKey] = useState(days.at(-1)?.key);
  const day = days.find((item) => item.key === dayKey) ?? days[days.length - 1];
  return <section aria-label="Security event timeline" className="rounded-xl border border-[var(--border-card)] bg-card p-4 sm:p-5">
    <h3 className="font-semibold text-fg">Explore events over time</h3>
    <p className="mt-1 text-xs text-muted">Select a date to explore its events. Dates run left to right; dots represent days, not event counts. Times use {Intl.DateTimeFormat().resolvedOptions().timeZone}.</p>
    <div className="mt-5 overflow-x-auto pb-3" tabIndex={0} aria-label="Dates, scroll horizontally">
      <div className="flex min-w-full w-max py-2">
        {days.map((item) => <button key={item.key} type="button" aria-pressed={item.key === day.key} onClick={() => setDayKey(item.key)} className="group relative flex w-24 shrink-0 flex-col items-center gap-3 rounded-lg py-2 text-xs text-secondary focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--ac)]">
          <span className="absolute left-0 right-0 top-4 border-t-2 border-[var(--border-strong)]" />
          <span className={`relative size-4 rounded-full border-2 ${item.key === day.key ? "border-[var(--ac)] bg-[var(--ac)]" : "border-[var(--border-strong)] bg-card group-hover:border-[var(--ac)]"}`} />
          <span className={item.key === day.key ? "font-semibold text-fg" : ""}>{item.start.toLocaleDateString(undefined, { month: "short", day: "numeric" })}</span>
          <span className="text-[10px] text-muted">{item.start.toLocaleDateString(undefined, { weekday: "short", year: "numeric" })}</span>
        </button>)}
      </div>
    </div>
    {day && <DayTimeline key={day.key} search={timelineDaySearch(search, day)} label={day.start.toLocaleDateString(undefined, { dateStyle: "full" })} onSelect={onSelect} />}
  </section>;
}

function DayTimeline({ search, label, onSelect }: { search: SecurityAuditEventSearch; label: string; onSelect: (event: SecurityAuditEvent) => void }) {
  const [events, setEvents] = useState<SecurityAuditEvent[]>([]);
  const [offset, setOffset] = useState(0);
  const [nextOffset, setNextOffset] = useState<number>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [retry, setRetry] = useState(0);
  const [hour, setHour] = useState<number>();
  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(undefined);
    api.security.events({ ...search, offset }).then((page) => {
      if (!alive) return;
      setEvents((current) => {
        const unique = new Map(current.map((event) => [`${event.tenantId}:${event.id}`, event]));
        page.events.forEach((event) => unique.set(`${event.tenantId}:${event.id}`, event));
        return [...unique.values()].sort((a, b) => Date.parse(a.occurredAt) - Date.parse(b.occurredAt));
      });
      setNextOffset(page.nextOffset);
    }).catch((reason) => { if (alive) setError(reason instanceof Error ? reason.message : "Unable to load events."); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
    // The parent remounts this view when the applied search or selected day changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [offset, retry]);
  const hours = useMemo(() => Array.from({ length: 24 }, (_, value) => events.filter((event) => new Date(event.occurredAt).getHours() === value)), [events]);
  const selectedHour = hour ?? hours.findIndex((group) => group.length > 0);
  return <div className="mt-3 border-t border-[var(--border-card)] pt-5">
    <h4 className="font-semibold text-fg">{label}</h4>
    <p aria-live="polite" className="mt-1 text-xs text-muted">{loading ? "Loading events…" : `${events.length} matching events loaded${nextOffset != null ? " · Partial day — load more to include remaining events" : " · All matching events in the searched portion of this day"}`}. Click an hour to inspect its events.</p>
    {error && <div role="alert" className="mt-3 text-sm text-danger">{error} <Button size="sm" onClick={() => setRetry((value) => value + 1)}>Retry</Button></div>}
    <div className="mt-4 overflow-x-auto pb-3" tabIndex={0} aria-label="Hourly timeline, scroll horizontally">
      <div className="flex min-w-full w-max">
        {hours.map((group, value) => <button key={value} type="button" disabled={!group.length} aria-pressed={selectedHour === value} aria-label={`${String(value).padStart(2, "0")}:00, ${group.length} loaded events`} onClick={() => setHour(value)} className="relative flex w-16 shrink-0 flex-col items-center gap-3 rounded-lg py-3 text-xs focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--ac)] disabled:text-muted">
          <span className="text-secondary">{group.length || "—"}</span>
          <span className="absolute inset-x-0 top-[47px] border-t border-[var(--border-strong)]" />
          <span className={`relative size-3 rounded-full border ${selectedHour === value ? "border-[var(--ac)] bg-[var(--ac)]" : group.length ? "border-info bg-info" : "border-[var(--border-strong)] bg-card"}`} />
          <span>{String(value).padStart(2, "0")}:00</span>
        </button>)}
      </div>
    </div>
    {!loading && !error && events.length === 0 && <p className="py-6 text-center text-sm text-muted">No events match the search on this day. Select another date or adjust the filters.</p>}
    {selectedHour >= 0 && <div className="mt-3"><p className="mb-3 text-xs font-semibold text-secondary">{String(selectedHour).padStart(2, "0")}:00–{String(selectedHour).padStart(2, "0")}:59 · {hours[selectedHour].length} loaded events · Earliest first</p>
      <ol className="max-h-[480px] space-y-2 overflow-y-auto">{hours[selectedHour].map((event) => <li key={`${event.tenantId}:${event.id}`}><button type="button" onClick={() => onSelect(event)} className="flex w-full flex-wrap items-center gap-3 rounded-lg border border-[var(--border-card)] bg-control p-3 text-left text-xs hover:border-[var(--ac)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--ac)]">
        <time className="text-secondary tabular" dateTime={event.occurredAt}>{new Date(event.occurredAt).toLocaleTimeString()}</time>
        <span className="min-w-0 flex-1 basis-48"><span className="block break-words font-semibold text-fg">{event.operation}</span><span className="mt-1 block break-all text-muted">{event.tenantName} · {event.actor || "Unknown actor"} · {event.workload}</span></span>
        <Badge tone={/fail|error/i.test(event.resultStatus ?? "") ? "danger" : "neutral"}>{event.resultStatus || "Unknown"}</Badge>
      </button></li>)}</ol>
    </div>}
    {nextOffset != null && <Button className="mt-4" disabled={loading || !!error} onClick={() => setOffset(nextOffset)}>{loading ? "Loading…" : "Load more events for this day"}</Button>}
  </div>;
}
