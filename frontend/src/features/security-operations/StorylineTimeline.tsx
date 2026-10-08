import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { groupTimelineActivity } from "./storylineTimeline";

export function StorylineTimeline<T>({ items, occurredAt, getKey, renderItem, label, description, unit }: {
  items: T[];
  occurredAt: (item: T) => string;
  getKey: (item: T) => string;
  renderItem: (item: T) => ReactNode;
  label: string;
  description: string;
  unit: string;
}) {
  const { days, undated } = useMemo(() => groupTimelineActivity(items, occurredAt), [items, occurredAt]);
  const [selection, setSelection] = useState<{ day: number; hour?: number }>();
  const day = days.find((value) => value.start.getTime() === selection?.day) ?? days.at(-1);
  const requestedHour = day?.start.getTime() === selection?.day ? selection?.hour : undefined;
  const hour = requestedHour != null && day?.hours[requestedHour].length
    ? requestedHour : day?.hours.findIndex((group) => group.length > 0) ?? -1;
  const selectedDayButton = useRef<HTMLButtonElement>(null);
  const selectedHourButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    // Move only each horizontal rail; leave the page and drawer scroll position alone.
    const observers: ResizeObserver[] = [];
    for (const button of [selectedDayButton.current, selectedHourButton.current]) {
      const rail = button?.parentElement?.parentElement;
      if (!button || !rail) continue;
      const center = () => {
        const item = button.getBoundingClientRect();
        const bounds = rail.getBoundingClientRect();
        rail.scrollLeft += item.left - bounds.left - (rail.clientWidth - item.width) / 2;
      };
      center();
      const observer = new ResizeObserver(center);
      observer.observe(rail);
      observers.push(observer);
    }
    return () => observers.forEach((observer) => observer.disconnect());
  }, [day?.start.getTime(), hour]);
  const focus = "focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--ac)]";
  return <section aria-label={label} className="min-w-0 p-4">
    <p className="text-xs leading-5 text-muted">{description} Dates with activity run left to right; gaps between dates are omitted. Times use {Intl.DateTimeFormat().resolvedOptions().timeZone}.</p>
    {undated > 0 && <p role="status" className="mt-2 text-xs text-warning">{undated} {unit} have no valid timestamp and are available in the list view.</p>}
    {!day ? <p className="py-6 text-sm text-muted">No dated activity matches these filters.</p> : <>
      <div tabIndex={0} aria-label={`${label} dates, scroll horizontally`} className="mt-4 overflow-x-auto pb-3">
        <div className="flex w-max min-w-full">
          {days.map((value) => <button type="button" ref={value === day ? selectedDayButton : undefined} key={value.start.getTime()} aria-pressed={value === day} aria-label={`${value.start.toLocaleDateString(undefined, { dateStyle: "full" })}, ${value.count} ${unit}`} onClick={() => setSelection({ day: value.start.getTime() })} className={`relative flex w-28 shrink-0 flex-col items-center gap-3 rounded-lg py-3 text-xs text-secondary ${focus}`}>
            <span>{value.count} {unit}</span>
            <span className="absolute inset-x-0 top-[49px] border-t-2 border-[var(--border-strong)]" />
            <span className={`relative size-4 rounded-full border-2 ${value === day ? "border-[var(--ac)] bg-[var(--ac)]" : "border-info bg-card"}`} />
            <span className={value === day ? "font-semibold text-fg" : ""}>{value.start.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}</span>
          </button>)}
        </div>
      </div>
      <div className="mt-2 border-t border-[var(--border-card)] pt-4">
        <h4 className="text-sm font-semibold text-fg">{day.start.toLocaleDateString(undefined, { dateStyle: "full" })}</h4>
        <p className="mt-1 text-xs text-muted">{day.count} {unit} · Select an hour to explore the activity.</p>
        <div tabIndex={0} aria-label={`${label} hours, scroll horizontally`} className="mt-3 overflow-x-auto pb-3">
          <div className="flex w-max min-w-full">
            {day.hours.map((group, index) => <button type="button" ref={hour === index ? selectedHourButton : undefined} key={index} disabled={!group.length} aria-pressed={hour === index} aria-label={`${String(index).padStart(2, "0")}:00, ${group.length} ${unit}`} onClick={() => setSelection({ day: day.start.getTime(), hour: index })} className={`relative flex w-16 shrink-0 flex-col items-center gap-3 rounded-lg py-3 text-xs text-secondary disabled:text-muted ${focus}`}>
              <span>{group.length || "—"}</span>
              <span className="absolute inset-x-0 top-[47px] border-t border-[var(--border-strong)]" />
              <span className={`relative size-3 rounded-full border ${hour === index ? "border-[var(--ac)] bg-[var(--ac)]" : group.length ? "border-info bg-info" : "border-[var(--border-strong)] bg-card"}`} />
              <span>{String(index).padStart(2, "0")}:00</span>
            </button>)}
          </div>
        </div>
        {hour >= 0 && <div className="mt-3">
          <p aria-live="polite" className="mb-3 text-xs font-semibold text-secondary">{String(hour).padStart(2, "0")}:00–{String(hour).padStart(2, "0")}:59 · {day.hours[hour].length} {unit} · Earliest first</p>
          <ol className="max-h-[480px] space-y-3 overflow-y-auto">{day.hours[hour].map((item) => <li key={getKey(item)}>{renderItem(item)}</li>)}</ol>
        </div>}
      </div>
    </>}
  </section>;
}
