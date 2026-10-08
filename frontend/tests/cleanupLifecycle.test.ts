import assert from "node:assert/strict";
import test from "node:test";

import {
  cleanupStatusLabel,
  cleanupStatusTone,
  isActiveCleanupStatus,
} from "../src/features/threatlocker/cleanupLifecycle.ts";

test("cleanup lifecycle keeps uncertain outcomes active and visually distinct", () => {
  assert.equal(isActiveCleanupStatus("needs_reconciliation"), true);
  assert.equal(cleanupStatusLabel("needs_reconciliation"), "Needs reconciliation");
  assert.equal(cleanupStatusTone("needs_reconciliation"), "danger");
});

test("verified cleanup is terminal and successful", () => {
  assert.equal(isActiveCleanupStatus("verified"), false);
  assert.equal(cleanupStatusLabel("verified"), "Verified");
  assert.equal(cleanupStatusTone("verified"), "success");
});
