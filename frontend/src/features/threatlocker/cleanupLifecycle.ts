import type { StatusTone, TLAppCleanupOperationStatus } from "@/types";

export function isActiveCleanupStatus(status: TLAppCleanupOperationStatus): boolean {
  return status === "submitted" ||
    status === "verification_pending" ||
    status === "needs_reconciliation";
}

export function cleanupStatusLabel(status: TLAppCleanupOperationStatus): string {
  const words = status.split("_").join(" ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function cleanupStatusTone(status: TLAppCleanupOperationStatus): StatusTone {
  switch (status) {
    case "verified":
      return "success";
    case "needs_reconciliation":
      return "danger";
    case "failed":
      return "neutral";
    default:
      return "warning";
  }
}
