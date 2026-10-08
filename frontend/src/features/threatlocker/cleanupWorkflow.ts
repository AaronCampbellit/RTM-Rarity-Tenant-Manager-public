import type { TLAppCleanupOperationStatus } from "@/types";

export type CleanupWorkflowStage = "discover" | "review" | "parent" | "approve" | "verify" | "complete";

export function cleanupWorkflowStage({
  hasCandidate,
  hasPreview = false,
  needsParentPromotion = false,
  operationStatus,
}: {
  hasCandidate: boolean;
  hasPreview?: boolean;
  needsParentPromotion?: boolean;
  operationStatus?: TLAppCleanupOperationStatus;
}): CleanupWorkflowStage {
  if (operationStatus === "verified") return "complete";
  if (operationStatus === "verification_pending" || operationStatus === "needs_reconciliation") {
    return "verify";
  }
  if (hasPreview && needsParentPromotion) return "parent";
  if (hasPreview) return "approve";
  if (hasCandidate) return "review";
  return "discover";
}

export function selectVisibleCleanupCandidates<T>(ranked: T[], limit = 100): T[] {
  return ranked.slice(0, limit);
}
