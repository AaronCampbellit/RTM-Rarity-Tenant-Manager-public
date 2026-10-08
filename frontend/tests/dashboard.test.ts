import assert from "node:assert/strict";
import test from "node:test";

import { dashboardAttentionJobs } from "../src/features/dashboard/dashboard.ts";
import type { Job } from "../src/types/index.ts";

function job(id: string, status: Job["status"], acknowledged = false): Job {
  return {
    id,
    type: "Test job",
    tenant: "Contoso",
    status,
    progress: 0,
    started: "now",
    duration: "—",
    triggeredBy: "Tester",
    acknowledged,
  };
}

test("dashboard jobs show only active work and unacknowledged failures", () => {
  const result = dashboardAttentionJobs([
    job("completed", "Completed"),
    job("running", "Running"),
    job("queued", "Queued"),
    job("failed", "Failed"),
    job("partial", "Partial"),
    job("acknowledged", "Failed", true),
  ]);

  assert.deepEqual(result.map((item) => item.id), ["running", "queued", "failed", "partial"]);
});

test("dashboard job attention list is bounded", () => {
  const result = dashboardAttentionJobs(
    Array.from({ length: 6 }, (_, index) => job(`job-${index}`, "Running")),
  );

  assert.equal(result.length, 4);
});
