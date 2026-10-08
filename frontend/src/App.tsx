import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Outlet, Route, Routes } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { AuthProvider, useAuth } from "./store/auth";
import { TenantProvider } from "./store/tenant";
import { ModalsProvider } from "./store/modals";
import { PageProvider } from "./store/page";
import { SyncProvider } from "./store/sync";
import { AppShell } from "./components/layout/AppShell";
import { LoginPage } from "./features/auth/LoginPage";
import { ChangePasswordPage } from "./features/auth/ChangePasswordPage";

import { DashboardPage } from "./features/dashboard/DashboardPage";
import { TenantsPage } from "./features/tenants/TenantsPage";
import { TenantDetailPage } from "./features/tenants/TenantDetailPage";
import { UsersPage } from "./features/users/UsersPage";
import { GroupsPage } from "./features/groups/GroupsPage";
import { GroupMembersPage } from "./features/groups/GroupMembersPage";
import { LicensingPage } from "./features/licensing/LicensingPage";
import { ExchangePage } from "./features/exchange/ExchangePage";
import { SharePointPage } from "./features/sharepoint/SharePointPage";
import { ThreatLockerPage } from "./features/threatlocker/ThreatLockerPage";
import { WorkingSetsPage } from "./features/working-sets/WorkingSetsPage";
import { JobsPage } from "./features/jobs/JobsPage";
import { ChangeHistoryPage } from "./features/change-history/ChangeHistoryPage";
import { ChangeDetailPage } from "./features/change-history/ChangeDetailPage";
import { GlobalReportsPage } from "./features/global-reports/GlobalReportsPage";
import { AuditLogsPage } from "./features/audit/AuditLogsPage";
import { AdminSettingsPage } from "./features/admin/AdminSettingsPage";
import { SecurityOperationsPage } from "./features/security-operations/SecurityOperationsPage";
import { DetectionRulesPage } from "./features/security-operations/DetectionRulesPage";
import { RawEventExplorerPage } from "./features/security-operations/RawEventExplorerPage";
import { DocumentationPage } from "./features/documentation/DocumentationPage";

const OfflineInvestigationsPage = lazy(() =>
  import("./features/offline-investigations/OfflineInvestigationsPage").then((module) => ({ default: module.OfflineInvestigationsPage })),
);

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}

/** App-wide providers that require an authenticated session (they fetch data). */
function AuthedProviders() {
  return (
    <TenantProvider>
      <SyncProvider>
        <ModalsProvider>
          <PageProvider>
            <Outlet />
          </PageProvider>
        </ModalsProvider>
      </SyncProvider>
    </TenantProvider>
  );
}

function FullscreenSpinner() {
  return (
    <div className="grid min-h-screen place-items-center bg-app">
      <Loader2 className="size-6 animate-spin text-muted" />
    </div>
  );
}

function AppRoutes() {
  const { status, user } = useAuth();
  if (status === "loading") return <FullscreenSpinner />;

  // Default/seeded credentials: the API is locked until the password rotates,
  // so the only screen that makes sense is the change-password one.
  if (status === "authed" && user?.mustChangePassword) {
    return <ChangePasswordPage />;
  }

  return (
    <Routes>
      <Route
        path="/login"
        element={status === "authed" ? <Navigate to="/dashboard" replace /> : <LoginPage />}
      />
      <Route
        element={status === "authed" ? <AuthedProviders /> : <Navigate to="/login" replace />}
      >
        <Route path="/" element={<AppShell />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="tenants" element={<TenantsPage />} />
          <Route path="tenants/:id" element={<TenantDetailPage />} />
          <Route path="users" element={<UsersPage />} />
          <Route path="groups" element={<GroupsPage />} />
          <Route path="groups/:id/members" element={<GroupMembersPage />} />
          <Route path="licensing" element={<LicensingPage />} />
          <Route path="exchange" element={<ExchangePage />} />
          <Route path="sharepoint" element={<SharePointPage />} />
          <Route path="share-detective" element={<Navigate to="/sharepoint?tab=investigations" replace />} />
          <Route path="threatlocker" element={<ThreatLockerPage />} />
          <Route path="security" element={<SecurityOperationsPage />} />
          <Route path="detection-rules" element={<DetectionRulesPage />} />
          <Route path="security-events" element={<RawEventExplorerPage />} />
          <Route path="offline-investigations" element={<Suspense fallback={<FullscreenSpinner />}><OfflineInvestigationsPage /></Suspense>} />
          <Route path="offline-investigations/:id" element={<Suspense fallback={<FullscreenSpinner />}><OfflineInvestigationsPage /></Suspense>} />
          <Route path="working-sets" element={<WorkingSetsPage />} />
          <Route path="jobs" element={<JobsPage />} />
          <Route path="changes" element={<ChangeHistoryPage />} />
          <Route path="changes/:id" element={<ChangeDetailPage />} />
          <Route path="global-reports" element={<GlobalReportsPage />} />
          <Route path="audit" element={<AuditLogsPage />} />
          <Route path="admin" element={<AdminSettingsPage />} />
          <Route path="documentation" element={<DocumentationPage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}
