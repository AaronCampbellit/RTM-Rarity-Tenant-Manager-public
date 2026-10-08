import assert from "node:assert/strict";
import test from "node:test";

import {
  cleanupWorkflowStage,
  selectVisibleCleanupCandidates,
} from "../src/features/threatlocker/cleanupWorkflow.ts";

test("guided cleanup advances from recommendation through portal verification", () => {
  assert.equal(cleanupWorkflowStage({ hasCandidate: false }), "discover");
  assert.equal(cleanupWorkflowStage({ hasCandidate: true }), "review");
  assert.equal(
    cleanupWorkflowStage({
      hasCandidate: true,
      hasPreview: true,
      needsParentPromotion: true,
    }),
    "parent",
  );
  assert.equal(cleanupWorkflowStage({ hasCandidate: true, hasPreview: true }), "approve");
  assert.equal(
    cleanupWorkflowStage({
      hasCandidate: true,
      hasPreview: true,
      operationStatus: "verification_pending",
    }),
    "verify",
  );
  assert.equal(
    cleanupWorkflowStage({
      hasCandidate: true,
      hasPreview: true,
      operationStatus: "verified",
    }),
    "complete",
  );
});

test("cleanup recommendation rail mounts only the highest-ranked hundred matches", () => {
  const ranked = Array.from({ length: 125 }, (_, index) => ({ id: `candidate-${index + 1}` }));
  const visible = selectVisibleCleanupCandidates(ranked);

  assert.equal(visible.length, 100);
  assert.equal(visible[0]?.id, "candidate-1");
  assert.equal(visible[99]?.id, "candidate-100");
});
