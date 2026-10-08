import type { SecurityAuditEventSearch } from "@/types";

/** Calendar arithmetic preserves local days across daylight-saving transitions. */
export function timelineDays(search: SecurityAuditEventSearch) {
  const end = new Date(search.to);
  const cursor = new Date(search.from);
  cursor.setHours(0, 0, 0, 0);
  const days: { key: string; start: Date; end: Date }[] = [];
  while (cursor <= end) {
    const start = new Date(cursor);
    cursor.setDate(cursor.getDate() + 1);
    days.push({ key: start.toISOString(), start, end: new Date(cursor.getTime() - 1) });
  }
  return days;
}

export function timelineDaySearch(search: SecurityAuditEventSearch, day: { start: Date; end: Date }): SecurityAuditEventSearch {
  return {
    ...search,
    from: new Date(Math.max(new Date(search.from).getTime(), day.start.getTime())).toISOString(),
    to: new Date(Math.min(new Date(search.to).getTime(), day.end.getTime())).toISOString(),
    offset: 0,
    limit: 100,
  };
}
