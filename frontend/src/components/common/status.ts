import type { StatusTone } from "@/types";

/** Map domain status strings to badge tones, matching the prototype. */

export const tenantTone = (s: string): StatusTone =>
  s === "Connected" ? "success" : s === "Degraded" ? "warning" : "danger";

export const mfaTone = (s: string): StatusTone =>
  s === "Enforced" ? "success" : s === "Enabled" ? "info" : "warning";

export const userTone = (s: string): StatusTone =>
  s === "Active" ? "success" : s === "Guest" ? "info" : "neutral";

export const jobTone = (s: string): StatusTone =>
  ({
    Running: "info",
    Completed: "success",
    Queued: "neutral",
    Failed: "danger",
    Partial: "warning",
  })[s] as StatusTone;

export const changeTone = (s: string): StatusTone =>
  ({
    Completed: "success",
    Partial: "warning",
    Failed: "danger",
    Reverted: "info",
  })[s] as StatusTone;

export const auditTone = (s: string): StatusTone =>
  s === "Success" ? "success" : s === "Denied" ? "warning" : "danger";

export const poolTone = (s: string): StatusTone =>
  s === "Full" ? "danger" : s === "Low" ? "warning" : "success";

export const sharingTone = (s: string): StatusTone =>
  s === "Anyone" ? "danger" : s === "External" ? "warning" : "success";

/** Source of authority (user.sourceOfAuthority / group.source). On-prem-mastered
 * objects are warning-toned so they stand out as "can't edit here". */
export const sourceLabel = (s?: string): string =>
  s === "on_prem" || s === "On-prem sync" ? "On-prem AD" : s === "unknown" ? "Unknown" : "Cloud";

export const sourceTone = (s?: string): StatusTone =>
  s === "on_prem" || s === "On-prem sync" ? "warning" : s === "unknown" ? "neutral" : "info";

/** Tenant identity mode badge. Hybrid/mixed are warning-toned to signal the
 * on-prem boundary; cloud is clean. */
export const identityModeLabel = (m?: string): string =>
  ({ cloud: "Cloud-only", hybrid: "Hybrid AD", mixed: "Mixed (Hybrid AD)", unknown: "Unknown" })[
    m ?? "unknown"
  ] ?? "Unknown";

export const identityModeTone = (m?: string): StatusTone =>
  m === "hybrid" || m === "mixed" ? "warning" : m === "cloud" ? "success" : "neutral";

/** Whether an identity mode involves on-prem-synced objects (drives the notice). */
export const isHybridMode = (m?: string): boolean => m === "hybrid" || m === "mixed";

export const roleTone = (r: string): StatusTone =>
  r === "Admin" ? "danger" : "neutral";
