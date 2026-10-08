export const THREATLOCKER_REFRESH_MS = 60_000;

export const threatLockerQueryKeys = {
  apps: "threatlocker:global:apps",
  devices: "threatlocker:global:devices",
  policies: "threatlocker:global:policies",
  approvals: "threatlocker:global:approvals",
  cleanupOperations: "threatlocker:global:cleanup-operations",
  cleanupCandidates: "threatlocker:global:cleanup-candidates",
} as const;

export interface ThreatLockerPreloadLoaders {
  apps: () => Promise<unknown>;
  devices: () => Promise<unknown>;
  policies: () => Promise<unknown>;
  approvals: () => Promise<unknown>;
  cleanupOperations: () => Promise<unknown>;
  cleanupCandidates: () => Promise<unknown>;
}

export async function runThreatLockerPreload(
  loaders: ThreatLockerPreloadLoaders,
  concurrency = 2,
  includeAdminDatasets = true,
): Promise<void> {
  const tasks = [
    loaders.apps,
    loaders.devices,
    loaders.policies,
    loaders.approvals,
  ];
  if (includeAdminDatasets) {
    tasks.push(loaders.cleanupOperations, loaders.cleanupCandidates);
  }
  let next = 0;
  const worker = async () => {
    while (next < tasks.length) {
      const task = tasks[next++];
      try {
        await task();
      } catch {
        // Preload is opportunistic. The session store retains the error and
        // the page can retry without blocking unrelated authenticated routes.
      }
    }
  };
  const workerCount = Math.max(1, Math.min(concurrency, tasks.length));
  await Promise.all(Array.from({ length: workerCount }, worker));
}
