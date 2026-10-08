import { useEffect } from "react";
import { api } from "@/api/client";
import { loadSessionQuery } from "@/api/sessionQueryStore";
import { hasPermission, useAuth } from "@/store/auth";
import {
  runThreatLockerPreload,
  THREATLOCKER_REFRESH_MS,
  threatLockerQueryKeys,
} from "./preload";

function preloadThreatLocker(force: boolean, includeAdminDatasets: boolean) {
  return runThreatLockerPreload({
    apps: () => loadSessionQuery(
      threatLockerQueryKeys.apps,
      () => api.threatlocker.apps(undefined, "", { refresh: force }),
      { force },
    ),
    devices: () => loadSessionQuery(
      threatLockerQueryKeys.devices,
      () => api.threatlocker.devices(),
      { force },
    ),
    policies: () => loadSessionQuery(
      threatLockerQueryKeys.policies,
      () => api.threatlocker.policies(),
      { force },
    ),
    approvals: () => loadSessionQuery(
      threatLockerQueryKeys.approvals,
      () => api.threatlocker.approvalRequests(undefined, "pending"),
      { force },
    ),
    cleanupOperations: () => loadSessionQuery(
      threatLockerQueryKeys.cleanupOperations,
      () => api.threatlocker.appCleanupOperations(),
      { force },
    ),
    cleanupCandidates: () => loadSessionQuery(
      threatLockerQueryKeys.cleanupCandidates,
      () => api.threatlocker.appCleanupCandidates(),
      { force },
    ),
  }, 2, includeAdminDatasets);
}

export function ThreatLockerPreloader() {
  const { user } = useAuth();
  const includeAdminDatasets = hasPermission(user, "threatlocker.manage");

  useEffect(() => {
    void preloadThreatLocker(false, includeAdminDatasets);
    const timer = window.setInterval(
      () => void preloadThreatLocker(true, includeAdminDatasets),
      THREATLOCKER_REFRESH_MS,
    );
    return () => window.clearInterval(timer);
  }, [includeAdminDatasets]);

  return null;
}
