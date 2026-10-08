/**
 * API client. Mirrors the REST contract in `specs/RTM API Specification.md`
 * (versioned under /api/v1, tenant-scoped, async actions return a job).
 *
 * BETA: ships with an in-memory mock layer so the UI runs without the Go API.
 * Set VITE_USE_MOCK=false (and run the backend) to hit the real endpoints —
 * the method signatures and return shapes are identical either way, so no UI
 * code changes when the backend lands.
 */
import * as mock from "./mock";
import { normalizeSecurityEventDetail } from "./securityEventDetail";
import { threatLockerReadPath } from "@/features/threatlocker/threatlockerPaths";
import type { ExportGenerateRequest } from "@/lib/csv";
import type {
  ApiError,
  AppSetting,
  Approval,
  ApprovalRequest,
  AuditEntry,
  Device,
  DeviceGroup,
  ChangeDetail,
  ChangeRecord,
  ChangeRequest,
  CreatedTechnician,
  CreatedTenant,
  DashboardStat,
  GlobalReport,
  Group,
  GroupMember,
  Job,
  JobRef,
  License,
  LoginResponse,
  NewGroup,
  NewTechnician,
  NewTenant,
  NewWorkingSet,
  OfflineInvestigation,
  OfflineInvestigationDetail,
  OfflineInvestigationFile,
  PasswordResetResult,
  Preflight,
  ExchangeBootstrapStart,
  ExchangeBootstrapPreview,
  Principal,
  Mailbox,
  MailboxPermissionFeed,
  MailboxSettings,
  ShareInvestigation,
  ShareRevokePreview,
  ShareRevokeResult,
  SharePointInventory,
  SharePointInventoryScope,
  SharePointPermissionRequest,
  SharePointPermissionPreview,
  SharePointPermissionResult,
  SharePointScan,
  SharePointScopePermission,
  SharePointPermissionTarget,
  SecurityIncidentDetail,
  SecurityAuditEventDetail,
  SecurityAuditEventPage,
  SecurityAuditEventSearch,
  SecurityDetectionRule,
  SecurityDetectionRuleRevision,
  SecurityOperationsSnapshot,
  SecurityStoryline,
  SecurityStorylineDetail,
  SecurityBulkTriageRequest,
  SecurityBulkTriageResult,
  SecurityRuleMutation,
  SecurityRuleConditionOptions,
  SecurityRulePreview,
  SecurityTriageRequest,
  SitePermission,
  Role,
  Site,
  Technician,
  Tenant,
  TenantSettingsUpdate,
  TenantSettingsResult,
  TLAppCleanupCandidate,
  TLAppCleanupPreview,
  TLAppCleanupOperation,
  TLAppCleanupRequest,
  TLAppCleanupResult,
  TLAppParentPromotion,
  TLApplication,
  TLApplicationDetail,
  TLApplicationPatch,
  TLPolicy,
  TLPolicyConsolidateResult,
  TLPolicyDeployResult,
  TLPolicyDetail,
  TLPolicyPatch,
  TLPolicyTemplate,
  TenantTestResult,
  User,
  UserRaw,
  WhatIfPreview,
  WorkingSet,
  WorkingSetUpdate,
} from "@/types";

export const USE_MOCK = import.meta.env.VITE_USE_MOCK !== "false";
const BASE = "/api/v1";

export class RtmApiError extends Error {
  code: string;
  correlationId: string;
  status: number;
  constructor(payload: ApiError, status = 0) {
    super(payload.error.message);
    this.code = payload.error.code;
    this.correlationId = payload.error.correlation_id;
    this.status = status;
  }
}

/** Bearer token attached to real API requests (set by the auth store). */
let authToken: string | null = null;
export function setAuthToken(token: string | null) {
  authToken = token;
}

/** Real network request against the Go API. */
async function http<T>(path: string, init?: RequestInit): Promise<T> {
  if (/^\/tenants\/(?:\/|\?|$)/.test(path)) {
    throw new RtmApiError({ error: { code: "VALIDATION_FAILED", message: "A tenant must be selected before loading tenant-scoped data.", correlation_id: "client" } }, 400);
  }
  const headers: Record<string, string> = {
    ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
    ...(init?.headers as Record<string, string>),
  };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    throw new RtmApiError(
      (body as ApiError) ?? {
        error: {
          code: "INTERNAL_ERROR",
          message: `Request failed (${res.status}).`,
          correlation_id: "unknown",
        },
      },
      res.status,
    );
  }
  return body as T;
}

/** Resolve mock data with a small delay so loading states are exercised. */
function mocked<T>(value: T, ms = 220): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms));
}

function threatLockerPath(_tenantId: string | undefined, suffix = "") {
  return `/threatlocker${suffix}`;
}

/**
 * Each method either serves mock data or calls the real endpoint. Tenant
 * scoping (`:tenantId`) is part of the path per the API spec; the mock ignores
 * it since the sample dataset is single-tenant, but the real API enforces it
 * server-side.
 */
/** Demo principal used in mock mode (no real backend / login). */
const MOCK_PRINCIPAL: Principal = {
  id: "tech_1",
  name: "Jordan Meyer",
  email: "jordan.meyer@rarity.io",
  role: "Admin",
  permissions: [
    "tenants.manage",
    "technicians.manage",
    "roles.manage",
    "settings.manage",
    "changes.execute",
    "security.manage",
    "threatlocker.manage",
  ],
  isAdmin: true,
};

export const api = {
  auth: {
    login: (email: string, password: string): Promise<LoginResponse> =>
      USE_MOCK
        ? mocked({
            accessToken: "mock-token",
            refreshToken: "mock-refresh",
            user: MOCK_PRINCIPAL,
          })
        : http("/auth/login", {
            method: "POST",
            body: JSON.stringify({ email, password }),
          }),
    me: (): Promise<Principal> =>
      USE_MOCK ? mocked(MOCK_PRINCIPAL) : http("/auth/me"),
    changePassword: (
      currentPassword: string,
      newPassword: string,
    ): Promise<LoginResponse> =>
      USE_MOCK
        ? mocked({
            accessToken: "mock-token",
            refreshToken: "mock-refresh",
            user: MOCK_PRINCIPAL,
          })
        : http("/auth/change-password", {
            method: "POST",
            body: JSON.stringify({ currentPassword, newPassword }),
          }),
  },
  tenants: {
    list: (): Promise<Tenant[]> =>
      USE_MOCK ? mocked([...mock.tenants]) : http("/tenants"),
    get: (id: string): Promise<Tenant> => {
      if (USE_MOCK) {
        const t = mock.tenants.find((x) => x.id === id);
        if (!t) return Promise.reject(new RtmApiError(mock.notFound("Tenant")));
        return mocked(t);
      }
      return http(`/tenants/${id}`);
    },
    create: (body: NewTenant): Promise<CreatedTenant> =>
      USE_MOCK
        ? mocked(mock.createTenant(body))
        : http("/tenants", { method: "POST", body: JSON.stringify(body) }),
    update: (id: string, body: TenantSettingsUpdate): Promise<TenantSettingsResult> =>
      USE_MOCK
        ? mocked({ tenant: mock.updateTenant(id, body) })
        : http(`/tenants/${id}`, { method: "PUT", body: JSON.stringify(body) }),
    test: (id: string): Promise<TenantTestResult> =>
      USE_MOCK
        ? mocked({ status: "Connected" } as TenantTestResult, 600)
        : http(`/tenants/${id}/test`, { method: "POST" }),
    preflight: (id: string): Promise<Preflight> =>
      USE_MOCK
        ? mocked(mock.getPreflight())
        : http(`/tenants/${id}/preflight`),
    runPreflight: (id: string): Promise<Preflight> =>
      USE_MOCK
        ? mocked(mock.runPreflight(), 700)
        : http(`/tenants/${id}/preflight`, { method: "POST" }),
    previewExchangeBootstrap: (id: string): Promise<ExchangeBootstrapPreview> =>
      USE_MOCK
        ? mocked({
            approvalToken: "mock-exchange-approval",
            callbackUrl: "https://rtm.example/api/v1/microsoft/exchange/bootstrap/callback",
            httpsReady: true,
            preview: {
              delegatedPermission: "RoleManagement.ReadWrite.Exchange",
              runtimePermission: "Exchange.ManageAsAppV2",
              exchangeRole: "Recipient Management",
              scope: "All mailboxes in this tenant",
              tokenRetention: "Discarded immediately after authorization",
              apiVersion: "Microsoft Graph beta",
            },
          })
        : http(`/tenants/${id}/exchange/bootstrap/preview`, { method: "POST" }),
    startExchangeBootstrap: (id: string, approvalToken: string, clientId: string, clientSecret: string): Promise<ExchangeBootstrapStart> =>
      USE_MOCK
        ? mocked({
            authorizationUrl: `/tenants/${id}?exchangeAuthorization=success&assignment=created`,
            expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
            preview: {
              delegatedPermission: "RoleManagement.ReadWrite.Exchange",
              runtimePermission: "Exchange.ManageAsAppV2",
              exchangeRole: "Recipient Management",
              scope: "All mailboxes in this tenant",
              tokenRetention: "Discarded immediately after authorization",
              apiVersion: "Microsoft Graph beta",
            },
          })
        : http(`/tenants/${id}/exchange/bootstrap`, { method: "POST", body: JSON.stringify({ approvalToken, clientId, clientSecret }) }),
    remove: (id: string): Promise<{ status: string }> => {
      if (USE_MOCK) {
        if (!mock.removeTenant(id))
          return Promise.reject(new RtmApiError(mock.notFound("Tenant")));
        return mocked({ status: "deleted" });
      }
      return http(`/tenants/${id}`, { method: "DELETE" });
    },
  },
  security: {
    operations: (): Promise<SecurityOperationsSnapshot> =>
      USE_MOCK ? mocked(mock.getSecurityOperations()) : http("/security/operations"),
    storyline: (storylineId: string): Promise<SecurityStorylineDetail> => {
      if (USE_MOCK) {
        const storyline = mock.getSecurityStoryline(storylineId);
        if (!storyline) return Promise.reject(new RtmApiError(mock.notFound("Attack storyline")));
        return mocked(storyline);
      }
      return http(`/security/storylines/${encodeURIComponent(storylineId)}`);
    },
    triageStoryline: (storylineId: string, body: SecurityTriageRequest): Promise<SecurityStoryline> => {
      if (USE_MOCK) {
        const storyline = mock.triageSecurityStoryline(storylineId, body);
        if (!storyline) return Promise.reject(new RtmApiError(mock.notFound("Attack storyline")));
        return mocked(storyline, 320);
      }
      return http(`/security/storylines/${encodeURIComponent(storylineId)}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
    },
    incident: (tenantId: string, incidentId: string): Promise<SecurityIncidentDetail> => {
      if (USE_MOCK) {
        const incident = mock.getSecurityIncident(tenantId, incidentId);
        if (!incident) {
          return Promise.reject(new RtmApiError(mock.notFound("Security incident")));
        }
        return mocked(incident);
      }
      return http(`/security/incidents/${tenantId}/${incidentId}`);
    },
    triage: (
      tenantId: string,
      incidentId: string,
      body: SecurityTriageRequest,
    ): Promise<SecurityIncidentDetail> => {
      if (USE_MOCK) {
        const incident = mock.triageSecurityIncident(tenantId, incidentId, body);
        if (!incident) {
          return Promise.reject(new RtmApiError(mock.notFound("Security incident")));
        }
        return mocked(incident, 320);
      }
      return http(`/security/incidents/${tenantId}/${incidentId}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
    },
    bulkTriage: (body: SecurityBulkTriageRequest): Promise<SecurityBulkTriageResult> =>
      USE_MOCK
        ? mocked(mock.bulkTriageSecurityIncidents(body), 420)
        : http("/security/incidents", {
            method: "PATCH",
            body: JSON.stringify(body),
          }),
    events: (query: SecurityAuditEventSearch): Promise<SecurityAuditEventPage> => {
      if (USE_MOCK) return mocked(mock.searchSecurityEvents(query));
      const params = new URLSearchParams();
      Object.entries(query).forEach(([key, value]) => {
        if (value !== undefined && value !== "") params.set(key, String(value));
      });
      return http(`/security/events?${params.toString()}`);
    },
    event: (tenantId: string, eventId: string): Promise<SecurityAuditEventDetail> => {
      if (USE_MOCK) {
        const event = mock.getSecurityEvent(tenantId, eventId);
        if (!event) return Promise.reject(new RtmApiError(mock.notFound("Security event")));
        return mocked(normalizeSecurityEventDetail(event));
      }
      return http<SecurityAuditEventDetail>(`/security/events/${encodeURIComponent(tenantId)}/${encodeURIComponent(eventId)}`).then(normalizeSecurityEventDetail);
    },
    offlineInvestigations: (): Promise<OfflineInvestigation[]> =>
      USE_MOCK ? mocked(mock.listOfflineInvestigations()) : http("/security/offline-investigations"),
    createOfflineInvestigation: (body: { name: string; tenantLabel: string }): Promise<OfflineInvestigation> =>
      USE_MOCK
        ? mocked(mock.createOfflineInvestigation(body), 320)
        : http("/security/offline-investigations", { method: "POST", body: JSON.stringify(body) }),
    offlineInvestigation: (id: string): Promise<OfflineInvestigationDetail> => {
      if (USE_MOCK) {
        const investigation = mock.getOfflineInvestigation(id);
        if (!investigation) return Promise.reject(new RtmApiError(mock.notFound("Offline investigation")));
        return mocked(investigation);
      }
      return http(`/security/offline-investigations/${encodeURIComponent(id)}`);
    },
    uploadOfflineInvestigationFile: (id: string, file: File): Promise<OfflineInvestigationFile> => {
      if (USE_MOCK) return mocked(mock.uploadOfflineInvestigationFile(id, file), 500);
      const body = new FormData();
      body.set("file", file);
      return http(`/security/offline-investigations/${encodeURIComponent(id)}/files`, { method: "POST", body });
    },
    analyzeOfflineInvestigation: (id: string): Promise<Job> =>
      USE_MOCK
        ? mocked(mock.analyzeOfflineInvestigation(id), 650)
        : http(`/security/offline-investigations/${encodeURIComponent(id)}/analyze`, { method: "POST" }),
    deleteOfflineInvestigation: (id: string): Promise<void> =>
      USE_MOCK
        ? mocked(mock.deleteOfflineInvestigation(id))
        : http(`/security/offline-investigations/${encodeURIComponent(id)}`, { method: "DELETE" }),
    rules: (): Promise<SecurityDetectionRule[]> =>
      USE_MOCK ? mocked(mock.listSecurityRules()) : http("/security/detection-rules"),
    ruleOptions: (tenantId?: string): Promise<SecurityRuleConditionOptions> => {
      if (USE_MOCK) return mocked(mock.securityRuleConditionOptions(tenantId));
      const params = new URLSearchParams();
      if (tenantId) params.set("tenantId", tenantId);
      const query = params.toString();
      return http(`/security/detection-rules/options${query ? `?${query}` : ""}`);
    },
    rule: (ruleId: string): Promise<SecurityDetectionRule> => {
      if (USE_MOCK) {
        const rule = mock.getSecurityRule(ruleId);
        if (!rule) return Promise.reject(new RtmApiError(mock.notFound("Detection rule")));
        return mocked(rule);
      }
      return http(`/security/detection-rules/${encodeURIComponent(ruleId)}`);
    },
    previewRule: (body: SecurityRuleMutation): Promise<SecurityRulePreview> =>
      USE_MOCK
        ? mocked(mock.previewSecurityRule(body.rule), 450)
        : http("/security/detection-rules/preview", { method: "POST", body: JSON.stringify(body) }),
    createRule: (body: SecurityRuleMutation): Promise<SecurityDetectionRule> =>
      USE_MOCK
        ? mocked(mock.createSecurityRule(body.rule), 400)
        : http("/security/detection-rules", { method: "POST", body: JSON.stringify(body) }),
    updateRule: (ruleId: string, body: SecurityRuleMutation): Promise<SecurityDetectionRule> =>
      USE_MOCK
        ? mocked(mock.updateSecurityRule(ruleId, body.rule), 400)
        : http(`/security/detection-rules/${encodeURIComponent(ruleId)}`, { method: "PUT", body: JSON.stringify(body) }),
    ruleRevisions: (ruleId: string): Promise<SecurityDetectionRuleRevision[]> =>
      USE_MOCK
        ? mocked(mock.listSecurityRuleRevisions(ruleId))
        : http(`/security/detection-rules/${encodeURIComponent(ruleId)}/revisions`),
    restoreRule: (ruleId: string, revision: number, approvalToken?: string): Promise<SecurityDetectionRule> =>
      USE_MOCK
        ? mocked(mock.restoreSecurityRule(ruleId, revision), 400)
        : http(`/security/detection-rules/${encodeURIComponent(ruleId)}/revisions/${revision}/restore`, {
            method: "POST",
            body: JSON.stringify({ approvalToken }),
          }),
  },
  users: {
    list: (tenantId: string): Promise<User[]> =>
      USE_MOCK ? mocked(mock.users) : http(`/tenants/${tenantId}/users`),
    raw: (tenantId: string, userId: string): Promise<UserRaw> => {
      if (USE_MOCK) {
        const raw = mock.buildUserRaw(userId);
        if (!raw) return Promise.reject(new RtmApiError(mock.notFound("User")));
        return mocked(raw);
      }
      return http(`/tenants/${tenantId}/users/${userId}/raw`);
    },
  },
  shareDetective: {
    list: (tenantId: string): Promise<ShareInvestigation[]> =>
      USE_MOCK
        ? mocked(mock.listShareInvestigations(tenantId))
        : http(`/tenants/${tenantId}/share-detective/investigations`),
    start: (tenantId: string, subjectId: string): Promise<ShareInvestigation> => {
      if (USE_MOCK) {
        const inv = mock.startShareInvestigation(tenantId, subjectId);
        if (!inv) return Promise.reject(new RtmApiError(mock.notFound("User")));
        return mocked(inv, 900);
      }
      return http(`/tenants/${tenantId}/share-detective/investigations`, {
        method: "POST",
        body: JSON.stringify({ subjectId }),
      });
    },
    get: (tenantId: string, invId: string): Promise<ShareInvestigation> => {
      if (USE_MOCK) {
        const inv = mock.getShareInvestigation(invId);
        if (!inv) return Promise.reject(new RtmApiError(mock.notFound("Investigation")));
        return mocked(inv);
      }
      return http(`/tenants/${tenantId}/share-detective/investigations/${invId}`);
    },
    revokePreview: (
      tenantId: string,
      invId: string,
      findingIds: string[],
    ): Promise<ShareRevokePreview> => {
      if (USE_MOCK) {
        const p = mock.previewShareRevoke(invId, findingIds);
        if (!p) return Promise.reject(new RtmApiError(mock.notFound("Investigation")));
        return mocked(p, 400);
      }
      return http(`/tenants/${tenantId}/share-detective/investigations/${invId}/revoke-preview`, {
        method: "POST",
        body: JSON.stringify({ findingIds }),
      });
    },
    revoke: (
      tenantId: string,
      invId: string,
      findingIds: string[],
      approvalToken?: string,
    ): Promise<ShareRevokeResult> => {
      if (USE_MOCK) {
        const r = mock.executeShareRevoke(invId, findingIds);
        if (!r) return Promise.reject(new RtmApiError(mock.notFound("Investigation")));
        return mocked(r, 600);
      }
      return http(`/tenants/${tenantId}/share-detective/investigations/${invId}/revoke`, {
        method: "POST",
        body: JSON.stringify({ findingIds, approvalToken }),
      });
    },
  },
  groups: {
    list: (tenantId: string): Promise<Group[]> =>
      USE_MOCK ? mocked([...mock.groups]) : http(`/tenants/${tenantId}/groups`),
    create: (tenantId: string, body: NewGroup): Promise<Group> =>
      USE_MOCK
        ? mocked(mock.createGroup(body))
        : http(`/tenants/${tenantId}/groups`, {
            method: "POST",
            body: JSON.stringify(body),
          }),
    members: (tenantId: string, groupId: string): Promise<GroupMember[]> =>
      USE_MOCK
        ? mocked(mock.groupMembers)
        : http(`/tenants/${tenantId}/groups/${groupId}/members`),
  },
  licenses: {
    list: (tenantId: string): Promise<License[]> =>
      USE_MOCK ? mocked(mock.licenses) : http(`/tenants/${tenantId}/licenses`),
  },
  exchange: {
    mailboxes: (tenantId: string): Promise<Mailbox[]> =>
      USE_MOCK
        ? mocked(mock.mailboxes)
        : http(`/tenants/${tenantId}/exchange/mailboxes`),
    settings: (tenantId: string, mailboxId: string): Promise<MailboxSettings> =>
      USE_MOCK
        ? mocked(mock.getMailboxSettings(mailboxId))
        : http(`/tenants/${tenantId}/exchange/mailboxes/${mailboxId}/settings`),
    permissions: (
      tenantId: string,
      mailboxId: string,
    ): Promise<MailboxPermissionFeed> =>
      USE_MOCK
        ? mocked(mock.getMailboxPermissions(mailboxId))
        : http(`/tenants/${tenantId}/exchange/mailboxes/${mailboxId}/permissions`),
  },
  sharepoint: {
    sites: (tenantId: string): Promise<Site[]> =>
      USE_MOCK
        ? mocked([...mock.sites])
        : http(`/tenants/${tenantId}/sharepoint/sites`),
    permissions: (tenantId: string, siteId: string): Promise<SitePermission[]> =>
      USE_MOCK
        ? mocked(mock.getSitePermissions(siteId))
        : http(`/tenants/${tenantId}/sharepoint/sites/${siteId}/permissions`),
    inventory: (tenantId: string, scope: SharePointInventoryScope): Promise<SharePointInventory> =>
      USE_MOCK
        ? mocked(mock.getSharePointInventory(scope))
        : http(`/tenants/${tenantId}/sharepoint/inventory?scope=${encodeURIComponent(scope)}`),
    scans: (tenantId: string): Promise<SharePointScan[]> =>
      USE_MOCK
        ? mocked(mock.getSharePointScans())
        : http(`/tenants/${tenantId}/sharepoint/scans`),
    startScan: (
      tenantId: string,
      body: { scope: SharePointInventoryScope; siteId?: string; nodeId?: string },
    ): Promise<SharePointScan> =>
      USE_MOCK
        ? mocked(mock.startSharePointScan(body.scope, body.siteId, body.nodeId), 500)
        : http(`/tenants/${tenantId}/sharepoint/scans`, {
            method: "POST",
            body: JSON.stringify(body),
          }),
    scopePermissions: (
      tenantId: string,
      target: SharePointPermissionTarget,
    ): Promise<SharePointScopePermission[]> => {
      if (USE_MOCK) return mocked(mock.getSharePointScopePermissions(target));
      const params = new URLSearchParams({
        siteId: target.siteId,
        kind: target.kind,
        path: target.path,
      });
      if (target.driveId) params.set("driveId", target.driveId);
      if (target.itemId) params.set("itemId", target.itemId);
      return http(`/tenants/${tenantId}/sharepoint/permissions?${params.toString()}`);
    },
    previewPermission: (
      tenantId: string,
      body: SharePointPermissionRequest,
    ): Promise<SharePointPermissionPreview> =>
      USE_MOCK
        ? mocked(mock.previewSharePointPermission(body))
        : http(`/tenants/${tenantId}/sharepoint/permissions/preview`, {
            method: "POST",
            body: JSON.stringify(body),
          }),
    executePermission: (
      tenantId: string,
      body: SharePointPermissionRequest,
      approvalToken: string,
    ): Promise<SharePointPermissionResult> =>
      USE_MOCK
        ? mocked(mock.executeSharePointPermission(body), 500)
        : http(`/tenants/${tenantId}/sharepoint/permissions/execute`, {
            method: "POST",
            body: JSON.stringify({ ...body, approvalToken }),
          }),
    revertPermission: (
      tenantId: string,
      changeId: string,
    ): Promise<SharePointPermissionResult> =>
      USE_MOCK
        ? mocked({ status: "Completed", changeId })
        : http(`/tenants/${tenantId}/sharepoint/permissions/revert`, {
            method: "POST",
            body: JSON.stringify({ changeId }),
          }),
  },
  threatlocker: {
    devices: (tenantId?: string): Promise<Device[]> =>
      USE_MOCK
        ? mocked([...mock.devices])
        : http(threatLockerPath(tenantId, "/devices")),
    device: (tenantId: string | undefined, deviceId: string): Promise<Device> => {
      if (USE_MOCK) {
        const d = mock.devices.find((x) => x.id === deviceId);
        if (!d) return Promise.reject(new RtmApiError(mock.notFound("Device")));
        return mocked(d);
      }
      return http(threatLockerPath(tenantId, `/devices/${deviceId}`));
    },
    deviceGroups: (tenantId?: string): Promise<DeviceGroup[]> =>
      USE_MOCK
        ? mocked([...mock.deviceGroups])
        : http(threatLockerPath(tenantId, "/device-groups")),
    apps: (
      _tenantId?: string,
      search = "",
      options: { refresh?: boolean } = {},
    ): Promise<TLApplication[]> =>
      USE_MOCK
        ? mocked(mock.getTLApplications(search))
        : http(threatLockerReadPath("/apps", { search, refresh: options.refresh })),
    appCleanupCandidates: (
      _tenantId?: string,
      options: { refresh?: boolean } = {},
    ): Promise<TLAppCleanupCandidate[]> =>
      USE_MOCK
        ? mocked(mock.getTLAppCleanupCandidates())
        : http(threatLockerReadPath("/apps/cleanup-candidates", options)),
    app: (tenantId: string | undefined, appId: string): Promise<TLApplicationDetail> =>
      USE_MOCK
        ? mocked(mock.getTLApplication(appId))
        : http(threatLockerPath(tenantId, `/apps/${appId}`)),
    updateApp: (
      tenantId: string | undefined,
      appId: string,
      body: TLApplicationPatch,
    ): Promise<TLApplicationDetail> =>
      USE_MOCK
        ? mocked(mock.updateTLApplication(appId, body))
        : http(threatLockerPath(tenantId, `/apps/${appId}`), {
            method: "PATCH",
          body: JSON.stringify(body),
        }),
    previewAppUpdate: (tenantId: string | undefined, appId: string, body: TLApplicationPatch): Promise<{ approvalToken: string; summary: string }> =>
      USE_MOCK ? mocked({ approvalToken: "mock", summary: `Update application ${appId}` }) : http(threatLockerPath(tenantId, `/apps/${appId}/preview`), { method: "POST", body: JSON.stringify(body) }),
    previewAppCleanup: (
      tenantId: string | undefined,
      body: TLAppCleanupRequest,
    ): Promise<TLAppCleanupPreview> =>
      USE_MOCK
        ? mocked(mock.previewTLAppCleanup(body), 360)
        : http(threatLockerPath(tenantId, "/apps/cleanup-preview"), {
            method: "POST",
          body: JSON.stringify(body),
          }),
    promoteCleanupParent: (
      tenantId: string | undefined,
      body: TLAppParentPromotion,
    ): Promise<TLAppCleanupResult> =>
      USE_MOCK
        ? mocked(mock.promoteTLAppCleanupParent(body), 500)
        : http(threatLockerPath(tenantId, "/apps/cleanup-parent-promote"), {
            method: "POST",
            body: JSON.stringify(body),
          }),
    executeAppCleanup: (
      tenantId: string | undefined,
      body: TLAppCleanupRequest,
    ): Promise<TLAppCleanupResult> =>
      USE_MOCK
        ? mocked(mock.executeTLAppCleanup(body), 600)
        : http(threatLockerPath(tenantId, "/apps/cleanup-execute"), {
            method: "POST",
            body: JSON.stringify(body),
          }),
    appCleanupOperations: (tenantId?: string): Promise<TLAppCleanupOperation[]> =>
      USE_MOCK
        ? mocked(mock.getTLAppCleanupOperations())
        : http(threatLockerPath(tenantId, "/apps/cleanup-operations")),
    verifyAppCleanup: (
      tenantId: string | undefined,
      operationId: string,
    ): Promise<TLAppCleanupOperation> =>
      USE_MOCK
        ? mocked(mock.verifyTLAppCleanupOperation(operationId), 420)
        : http(threatLockerPath(tenantId, `/apps/cleanup-operations/${operationId}/verify`), {
            method: "POST",
          }),
    reconcileAppCleanup: (
      tenantId: string | undefined,
      operationId: string,
      resolution: "verified" | "not_applied",
    ): Promise<TLAppCleanupOperation> =>
      USE_MOCK
        ? mocked(mock.reconcileTLAppCleanupOperation(operationId, resolution))
        : http(threatLockerPath(tenantId, `/apps/cleanup-operations/${operationId}/reconcile`), {
            method: "POST",
            body: JSON.stringify({ resolution }),
          }),
    approvalRequests: (
      tenantId: string | undefined,
      status?: ApprovalRequest["status"],
    ): Promise<ApprovalRequest[]> =>
      USE_MOCK
        ? mocked(mock.approvalRequests.filter((r) => r.status === (status ?? "pending")))
        : http(
            `${threatLockerPath(tenantId, "/approval-requests")}${status ? `?status=${status}` : ""}`,
          ),
    policies: (tenantId?: string): Promise<TLPolicy[]> =>
      USE_MOCK
        ? mocked([...mock.tlPolicies])
        : http(threatLockerPath(tenantId, "/policies")),
    policy: (tenantId: string | undefined, policyId: string): Promise<TLPolicyDetail> =>
      USE_MOCK
        ? mocked(mock.getTLPolicy(policyId))
        : http(threatLockerPath(tenantId, `/policies/${policyId}`)),
    updatePolicy: (
      tenantId: string | undefined,
      policyId: string,
      body: TLPolicyPatch,
    ): Promise<TLPolicyDetail> =>
      USE_MOCK
        ? mocked(mock.updateTLPolicy(policyId, body))
        : http(threatLockerPath(tenantId, `/policies/${policyId}`), {
            method: "PATCH",
          body: JSON.stringify(body),
        }),
    previewPolicyUpdate: (tenantId: string | undefined, policyId: string, body: TLPolicyPatch): Promise<{ approvalToken: string; summary: string }> =>
      USE_MOCK ? mocked({ approvalToken: "mock", summary: `Update policy ${policyId}` }) : http(threatLockerPath(tenantId, `/policies/${policyId}/preview`), { method: "POST", body: JSON.stringify(body) }),
    promotePolicyGlobal: (tenantId: string | undefined, policyId: string, approvalToken?: string): Promise<TLPolicyConsolidateResult> =>
      USE_MOCK
        ? mocked(mock.promoteTLPolicyGlobal(policyId))
        : http(threatLockerPath(tenantId, `/policies/${policyId}/promote-global`), {
            method: "POST",
            body: JSON.stringify({ approvalToken }),
          }),
    previewPolicyPromotion: (tenantId: string | undefined, policyId: string): Promise<{ approvalToken: string; summary: string }> =>
      USE_MOCK ? mocked({ approvalToken: "mock", summary: `Promote policy ${policyId}` }) : http(threatLockerPath(tenantId, `/policies/${policyId}/promote-global/preview`), { method: "POST", body: "{}" }),
    promotePolicy: (body: {
      tenantId: string;
      policyId: string;
      name?: string;
      description?: string;
    }): Promise<TLPolicyTemplate> =>
      USE_MOCK
        ? mocked(mock.promoteTLPolicy(body))
        : http("/threatlocker/policy-templates/promote", {
            method: "POST",
            body: JSON.stringify(body),
          }),
    mergePolicies: (body: {
      tenantId: string;
      policyIds: string[];
      name?: string;
      description?: string;
    }): Promise<TLPolicyTemplate> =>
      USE_MOCK
        ? mocked(mock.mergeTLPolicies(body))
        : http("/threatlocker/policy-templates/merge", {
            method: "POST",
            body: JSON.stringify(body),
          }),
    deployTemplate: (
      templateId: string,
      body: { tenantIds?: string[]; all?: boolean; approvalToken?: string },
    ): Promise<TLPolicyDeployResult> =>
      USE_MOCK
        ? mocked(mock.deployTLPolicyTemplate(templateId, body))
        : http(`/threatlocker/policy-templates/${templateId}/deploy`, {
            method: "POST",
          body: JSON.stringify(body),
        }),
    previewTemplateDeploy: (templateId: string, body: { tenantIds?: string[]; all?: boolean }): Promise<{ approvalToken: string; summary: string }> =>
      USE_MOCK ? mocked({ approvalToken: "mock", summary: `Deploy policy template ${templateId}` }) : http(`/threatlocker/policy-templates/${templateId}/deploy/preview`, { method: "POST", body: JSON.stringify(body) }),
    approvalRequest: (tenantId: string | undefined, requestId: string): Promise<ApprovalRequest> => {
      if (USE_MOCK) {
        const q = mock.approvalRequests.find((x) => x.id === requestId);
        if (!q) return Promise.reject(new RtmApiError(mock.notFound("Approval request")));
        return mocked(q);
      }
      return http(threatLockerPath(tenantId, `/approval-requests/${requestId}`));
    },
  },
  workingSets: {
    list: (): Promise<WorkingSet[]> =>
      USE_MOCK ? mocked(mock.workingSets) : http("/working-sets"),
    get: (id: string): Promise<WorkingSet> => {
      if (USE_MOCK) {
        const workingSet = mock.workingSets.find((candidate) => candidate.id === id);
        return workingSet ? mocked({ ...workingSet, userIds: [...workingSet.userIds] }) : Promise.reject(new RtmApiError(mock.notFound("Working set")));
      }
      return http(`/working-sets/${id}`);
    },
    create: (body: NewWorkingSet): Promise<WorkingSet> =>
      USE_MOCK
        ? mocked(mock.createWorkingSet(body))
        : http<WorkingSet>("/working-sets", {
            method: "POST",
            body: JSON.stringify(body),
          }),
    update: (id: string, body: WorkingSetUpdate): Promise<WorkingSet> => {
      if (USE_MOCK) {
        const workingSet = mock.workingSets.find((candidate) => candidate.id === id);
        if (!workingSet) return Promise.reject(new RtmApiError(mock.notFound("Working set")));
        return mocked(mock.updateWorkingSet(id, body));
      }
      return http<WorkingSet>(`/working-sets/${id}`, {
        method: "PUT",
        body: JSON.stringify(body),
      });
    },
  },
  jobs: {
    list: (): Promise<Job[]> => (USE_MOCK ? mocked(mock.jobs) : http("/jobs")),
    acknowledge: (jobId: string): Promise<{ status: string }> =>
      USE_MOCK
        ? mocked(mock.acknowledgeJob(jobId))
        : http(`/jobs/${jobId}/acknowledge`, { method: "POST", body: JSON.stringify({}) }),
  },
  changes: {
    list: (): Promise<ChangeRecord[]> =>
      USE_MOCK ? mocked(mock.changes) : http("/changes"),
    get: (id: string): Promise<ChangeDetail> => {
      if (USE_MOCK) {
        const c = mock.changeDetail[id] ?? Object.values(mock.changeDetail)[0];
        return mocked(c);
      }
      return http(`/changes/${id}`);
    },
    preview: (body: ChangeRequest): Promise<WhatIfPreview> =>
      USE_MOCK
        ? mocked(mock.buildWhatIfPreview(body))
        : http("/changes/preview", { method: "POST", body: JSON.stringify(body) }),
    execute: (body: ChangeRequest, approvalToken?: string): Promise<JobRef> =>
      USE_MOCK
        ? mocked(
            body.action === "reset_password" || body.action === "revoke_user_access"
              ? {
                  job_id: "job_exec_sensitive",
                  status: "succeeded",
                  oneTimePasswords: (body.userIds ?? []).map((userId, index) => {
                    const selected = mock.users.find((user) => user.id === userId);
                    return {
                      userId,
                      user: selected?.name ?? `Selected user ${index + 1}`,
                      upn: selected?.upn ?? userId,
                      password: `Rtm-${crypto.randomUUID().replaceAll("-", "").slice(0, 18)}`,
                    };
                  }),
                } as JobRef
              : { job_id: "job_exec_new", status: "queued" } as JobRef,
          )
        : http("/changes/execute", { method: "POST", body: JSON.stringify({ ...body, approvalToken }) }),
    revert: (id: string): Promise<JobRef> =>
      USE_MOCK
        ? mocked({ job_id: "job_revert_new", status: "queued" } as JobRef)
        : http("/changes/revert", { method: "POST", body: JSON.stringify({ id }) }),
  },
  globalReports: {
    get: (type: string): Promise<GlobalReport> =>
      USE_MOCK
        ? mocked(mock.globalReports[type] ?? mock.globalReports.mfa)
        : http(`/global-reports/${type}`),
  },
  exports: {
    generate: (body: ExportGenerateRequest): Promise<{ status: "recorded" }> =>
      USE_MOCK
        ? mocked(mock.recordExport(body))
        : http("/exports/generate", { method: "POST", body: JSON.stringify(body) }),
  },
  audit: {
    list: (): Promise<AuditEntry[]> =>
      USE_MOCK ? mocked(mock.audit) : http("/audit"),
  },
  admin: {
    technicians: (): Promise<Technician[]> =>
      USE_MOCK ? mocked([...mock.technicians]) : http("/admin/technicians"),
    createTechnician: (body: NewTechnician): Promise<CreatedTechnician> =>
      USE_MOCK
        ? mocked(mock.createTechnician(body))
        : http("/admin/technicians", { method: "POST", body: JSON.stringify(body) }),
    updateTechnician: (
      id: string,
      body: { role?: string; status?: string },
    ): Promise<{ status: string }> =>
      USE_MOCK
        ? mocked(mock.updateTechnician(id, body))
        : http(`/admin/technicians/${id}`, {
            method: "PATCH",
            body: JSON.stringify(body),
          }),
    deleteTechnician: (id: string): Promise<{ status: string }> =>
      USE_MOCK
        ? mocked(mock.deleteTechnician(id))
        : http(`/admin/technicians/${id}`, { method: "DELETE" }),
    resetTechnicianPassword: (id: string): Promise<PasswordResetResult> =>
      USE_MOCK
        ? mocked(mock.resetTechnicianPassword(id))
        : http(`/admin/technicians/${id}/reset-password`, { method: "POST" }),
    roles: (): Promise<Role[]> =>
      USE_MOCK ? mocked(mock.roles) : http("/admin/roles"),
    updateRole: (
      name: string,
      body: { description: string; permissionKeys: string[] },
    ): Promise<Role> =>
      USE_MOCK
        ? mocked(mock.updateRole(name, body))
        : http(`/admin/roles/${encodeURIComponent(name)}`, {
            method: "PUT",
            body: JSON.stringify(body),
          }),
    settings: (): Promise<AppSetting[]> =>
      USE_MOCK ? mocked([...mock.appSettings]) : http("/admin/settings"),
    updateSetting: (key: string, enabled: boolean): Promise<{ status: string }> =>
      USE_MOCK
        ? mocked(mock.updateSetting(key, enabled))
        : http(`/admin/settings/${key}`, {
            method: "PATCH",
          body: JSON.stringify({ enabled }),
        }),
    updateSettingValue: (key: string, value: string): Promise<{ status: string }> =>
      USE_MOCK
        ? mocked(mock.updateSettingValue(key, value))
        : http(`/admin/settings/${key}`, {
          method: "PATCH",
          body: JSON.stringify({ value }),
        }),
    threatLocker: (): Promise<import("@/types").ThreatLockerGlobalConfiguration> =>
      USE_MOCK ? mocked(mock.getThreatLockerGlobalConfiguration()) : http("/admin/threatlocker"),
    updateThreatLocker: (
      body: import("@/types").UpdateThreatLockerGlobalConfiguration,
    ): Promise<import("@/types").ThreatLockerGlobalConfiguration> =>
      USE_MOCK
        ? mocked(mock.updateThreatLockerGlobalConfiguration(body))
        : http("/admin/threatlocker", { method: "PUT", body: JSON.stringify(body) }),
  },
  dashboard: {
    stats: (): Promise<DashboardStat[]> =>
      USE_MOCK ? mocked(mock.dashboardStats) : http("/dashboard/stats"),
    approvals: (): Promise<Approval[]> =>
      USE_MOCK ? mocked(mock.approvals) : http("/dashboard/approvals"),
  },
};
