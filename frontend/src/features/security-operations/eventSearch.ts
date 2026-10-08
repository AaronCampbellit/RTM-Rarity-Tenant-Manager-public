import type { SecurityAuditEventSearch } from "@/types";

export function normalizeEventSearch(
  draft: SecurityAuditEventSearch,
  offset = 0,
): SecurityAuditEventSearch {
  const from = new Date(draft.from);
  const to = new Date(draft.to);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
    throw new Error("Choose both a start and end time before running the search.");
  }
  if (to < from) {
    throw new Error("The end time must be after the start time.");
  }
  if (to.getTime() - from.getTime() > 180 * 24 * 60 * 60 * 1000) {
    throw new Error("Raw-event searches are limited to a 180-day window.");
  }
  return { ...draft, offset, from: from.toISOString(), to: to.toISOString() };
}
