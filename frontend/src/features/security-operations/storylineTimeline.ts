/** Group retained activity by local calendar day, without inventing dates for missing timestamps. */
export function groupTimelineActivity<T>(items: T[], occurredAt: (item: T) => string) {
  const days = new Map<number, { start: Date; hours: T[][]; count: number }>();
  const ordered = items.map((item) => ({ item, time: new Date(occurredAt(item)) }))
    .filter(({ time }) => Number.isFinite(time.getTime()))
    .sort((a, b) => a.time.getTime() - b.time.getTime());
  for (const { item, time } of ordered) {
    const start = new Date(time);
    start.setHours(0, 0, 0, 0);
    let day = days.get(start.getTime());
    if (!day) {
      day = { start, hours: Array.from({ length: 24 }, () => []), count: 0 };
      days.set(start.getTime(), day);
    }
    day.hours[time.getHours()].push(item);
    day.count++;
  }
  return { days: [...days.values()], undated: items.length - ordered.length };
}
