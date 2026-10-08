import type { SecurityAuditEventDetail } from "../types";

/**
 * Older retained records and partial connector responses can omit collection
 * fields. Keep that provider variability at the API boundary so the event
 * drawer always receives a stable, render-safe contract.
 */
export function normalizeSecurityEventDetail(
  event: SecurityAuditEventDetail | null | undefined,
): SecurityAuditEventDetail {
  if (!event) throw new Error("The event detail response was empty.");
  return {
    ...event,
    sources: Array.isArray(event.sources) ? event.sources : [],
    sourceEvidence: Array.isArray(event.sourceEvidence)
      ? event.sourceEvidence.map((evidence) => ({
          ...evidence,
          raw: evidence.raw ?? {},
          rawTruncated: evidence.rawTruncated === true,
        }))
      : [],
    relatedDetections: Array.isArray(event.relatedDetections) ? event.relatedDetections : [],
    raw: event.raw ?? {},
    rawTruncated: event.rawTruncated === true,
  };
}
