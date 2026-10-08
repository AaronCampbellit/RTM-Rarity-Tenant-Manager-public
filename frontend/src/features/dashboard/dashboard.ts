import type { Job } from "@/types";

const ACTIVE_JOB_STATUSES = new Set<Job["status"]>(["Running", "Queued"]);
const FAILED_JOB_STATUSES = new Set<Job["status"]>(["Failed", "Partial"]);

/** Keep the dashboard focused on in-flight work and unacknowledged failures. */
export function dashboardAttentionJobs(jobs: Job[], limit = 4) {
  return jobs
    .filter(
      (job) =>
        ACTIVE_JOB_STATUSES.has(job.status) ||
        (FAILED_JOB_STATUSES.has(job.status) && !job.acknowledged),
    )
    .slice(0, limit);
}
