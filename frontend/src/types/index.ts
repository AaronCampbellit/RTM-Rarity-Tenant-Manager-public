/**
 * API model types — mirror the REST contract in
 * `specs/RTM API Specification.md`. These are the shapes the real Go API
 * returns under `/api/v1/...`; the mock layer (src/api/mock.ts) produces the
 * same shapes so screens are wired identically whether data is real or mocked.
 */

export type StatusTone =
  | "success"
  | "danger"
  | "warning"
  | "info"
  | "neutral";

/** Standard error envelope (Coding Standards → Error Response Shape). */
export interface ApiError {
  error: {
    code: string;
    message: string;
    correlation_id: string;
  };
}

/** Async workflow response (API Spec → Async Operations). */
export interface JobRef {
  job_id: string;
  status: JobStatus;
  /** Returned once for Microsoft 365 password-reset/containment actions. */
  oneTimePasswords?: OneTimePassword[];
}

export interface OneTimePassword {
  userId: string;
  user: string;
  upn: string;
  password: string;
}

/** Authenticated operator (from /auth/login and /auth/me). */
export interface Principal {
  id: string;
  name: string;
  email: string;
  role?: string;
  permissions?: string[];
  isAdmin: boolean;
  /** Default/seeded credential: the API is gated until the password rotates. */
  mustChangePassword?: boolean;
}

/** Input to POST /tenants. All secrets are write-only: no API response ever
 * includes them. Leave clientId/clientSecret empty to use the global app
 * registration. Exchange may use a dedicated app. SharePoint uses RTM's
 * central certificate-backed app and stores only the tenant admin URL. */
export interface NewTenant {
  name: string;
  domain: string;
  microsoftTenantId: string;
  clientId?: string;
  clientSecret?: string;
  exchangeClientId?: string;
  exchangeClientSecret?: string;
  sharePointAdminUrl?: string;
	/** Onboarding-only evidence import. Microsoft 365 Management Activity is
	 * bounded to seven days and imported in one-day background slices. */
	historyWindow?: "start_now" | "last_24h" | "last_7d" | "maximum_available";
	historicalIncidentMode?: "recent_24h" | "all" | "baseline_only";
}

/** Which service integrations have their tenant-specific connection material
 * stored. SharePoint means the admin URL is configured; its app/certificate
 * are deployment-managed. */
export interface TenantConnections {
  graph: boolean;
  exchange: boolean;
  sharePoint: boolean;
}

/** POST /tenants response: the tenant, plus why the initial connection test
 * failed (missing admin consent, bad secret, …) when it did. */
export type CreatedTenant = Tenant & {
	connectionError?: string;
	historyImport?: SecurityHistoryImport;
};

export interface TenantSettingsUpdate {
  name?: string;
  domain?: string;
  microsoftTenantId?: string;
  clientId?: string;
  clientSecret?: string;
  clearGraph?: boolean;
  exchangeClientId?: string;
  exchangeClientSecret?: string;
  clearExchange?: boolean;
  sharePointAdminUrl?: string;
}

export interface TenantSettingsResult {
  tenant: Tenant;
}

/** Admin-only global MSP parent ThreatLocker configuration. The API token is
 * never returned; tokenConfigured only indicates that one is stored. */
export interface ThreatLockerGlobalConfiguration {
  configured: boolean;
  tokenConfigured: boolean;
  source: "database" | "environment" | "none";
  instance: string;
  parentOrganizationId: string;
}

export interface UpdateThreatLockerGlobalConfiguration {
  instance: string;
  token: string;
  parentOrganizationId: string;
}

/** POST /tenants/{id}/test response. `error` explains a failure in
 * operator terms (includes Microsoft's own error code/message). */
export interface TenantTestResult {
  status: TenantConnectionStatus;
  error?: string;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  user: Principal;
}

export type JobStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "partial_success";

export type TenantConnectionStatus =
  | "Connected"
  | "Degraded"
  | "Disconnected";

/** Source of authority for a directory object. Objects synced from on-prem
 * Active Directory ("on_prem") are mastered there — RTM only edits their
 * cloud-authoritative facets. */
export type SourceOfAuthority = "cloud" | "on_prem" | "unknown";

/** A tenant's hybrid identity classification, derived from its objects. */
export type IdentityMode = "cloud" | "hybrid" | "mixed" | "unknown";

export interface Tenant {
  id: string;
  name: string;
  domain: string;
  microsoftTenantId: string;
  status: TenantConnectionStatus;
  users: number;
  lastGraphTest: string;
  modules: string[];
  connections: TenantConnections;
  /** Hybrid identity summary — present on the tenant detail response only
   * (the list endpoint omits it). */
  identityMode?: IdentityMode;
  syncedUsers?: number;
  cloudUsers?: number;
  syncedGroups?: number;
  cloudGroups?: number;
}

export interface User {
  id: string;
  name: string;
  givenName: string;
  surname: string;
  upn: string;
  mail: string;
  userType: string;
  department: string;
  jobTitle: string;
  companyName: string;
  officeLocation: string;
  employeeId: string;
  employeeType: string;
  businessPhones: string[];
  mobilePhone: string;
  streetAddress: string;
  city: string;
  state: string;
  postalCode: string;
  country: string;
  usageLocation: string;
  preferredLanguage: string;
  createdDateTime: string;
  onPremisesSamAccountName: string;
  onPremisesLastSyncDateTime: string;
  license: string;
  licenses: string[];
  mfa: "Enforced" | "Enabled" | "Disabled" | "Unknown";
  status: "Active" | "Disabled" | "Guest";
  lastSignIn: string;
  lastSignInAvailable: boolean;
  /** Whether this user is cloud-managed or synced from on-prem AD. */
  sourceOfAuthority?: SourceOfAuthority;
}

export interface Group {
  id: string;
  name: string;
  type:
    | "M365"
    | "Security"
    | "Distribution"
    | "Dynamic Distribution"
    | "Mail-enabled Sec.";
  membership: "Assigned" | "Dynamic";
  members: number;
  mail: "Yes" | "No";
  service?: "Graph" | "Exchange";
  source: "Cloud" | "On-prem sync";
}

export interface GroupMember {
  id: string;
  name: string;
  upn: string;
  role: "Owner" | "Member";
  added: string;
}

export interface License {
  skuId: string;
  sku: string;
  product: string;
  assigned: number;
  available: number;
  total: number;
  utilization: number;
  pool: "OK" | "Low" | "Full";
}

export interface Mailbox {
  id: string;
  name: string;
  email: string;
  userPrincipalName: string;
  aliases: string[];
  type: "User" | "Shared" | "Room" | "Equipment" | "Unknown";
  accountStatus: "Enabled" | "Disabled" | "Unknown";
  sourceOfAuthority: "cloud" | "on_prem" | "unknown";
  createdAt: string;
  licenseCount: number;
  size: string;
  items: number;
  archive: "On" | "Off" | "—";
  litigationHold: "Yes" | "No" | "—";
  usageAvailable: boolean;
  usageAsOf: string;
  lastActivityAt: string;
  deletedItems: number;
  deletedSize: string;
  warningQuota: string;
  sendQuota: string;
  sendReceiveQuota: string;
  usageDetail: string;
}

/** Exchange mailbox detail: auto-reply + forwarding state
 * (GET /tenants/{id}/exchange/mailboxes/{mailboxId}/settings). */
export interface MailboxSettings {
  mailboxId: string;
  autoReply: boolean;
  autoReplyStatus: string;
  autoReplyMessage: string;
  externalAutoReplyMessage: string;
  externalAudience: string;
  autoReplyStart: string;
  autoReplyEnd: string;
  forwardingTo: string; // empty = no forwarding
  forwardingRules: MailboxForwardingRule[];
  rulesAvailable: boolean;
  rulesDetail: string;
  timeZone: string;
  language: string;
  dateFormat: string;
  timeFormat: string;
  workingDays: string[];
  workingHoursStart: string;
  workingHoursEnd: string;
  workingHoursTimeZone: string;
  userPurpose: string;
  delegateMeetingMessageDelivery: string;
}

export interface MailboxForwardingRule {
  id: string;
  name: string;
  enabled: boolean;
  hasError: boolean;
  readOnly: boolean;
  mode: "Forward" | "Redirect" | "Forward as attachment";
  recipients: string[];
  managedByRtm: boolean;
}

/** One delegate entry on a mailbox
 * (GET /tenants/{id}/exchange/mailboxes/{mailboxId}/permissions). */
export interface MailboxPermission {
  id: string;
  delegate: string;
  delegateUpn: string;
  permission: "Full Access" | "Send As" | "Send on Behalf";
  granted: string;
}

export interface MailboxPermissionCoverage {
  permission: MailboxPermission["permission"];
  status: "collected" | "not_supported";
  source: string;
  detail?: string;
}

export interface MailboxPermissionFeed {
  permissions: MailboxPermission[];
  coverage: MailboxPermissionCoverage[];
}

/** One principal's access to a SharePoint site
 * (GET /tenants/{id}/sharepoint/sites/{siteId}/permissions). */
export interface SitePermission {
  id: string;
  principal: string;
  principalUpn: string;
  type: "User" | "Group" | "External" | "App" | "Link";
  role: "Read" | "Edit" | "Full Control";
  source: "Owners" | "Members" | "Visitors" | "Direct" | "Sharing link";
}

export interface Site {
  id: string;
  name: string;
  url: string;
  template: string;
  storage: string;
  files: number;
  externalSharing: "Internal" | "External" | "Anyone";
}

export type SharePointInventoryScope = "sites" | "onedrive" | "file_permissions";

export interface SharePointScan {
  id: string;
  tenantId: string;
  scope: SharePointInventoryScope;
  siteId?: string;
  nodeId?: string;
  status: "queued" | "running" | "completed" | "partial" | "failed";
  trigger: "manual" | "nightly" | "on_demand";
  startedBy: string;
  startedAt: string;
  completedAt?: string;
  coverage: "pending" | "complete" | "partial" | "failed";
  siteCount: number;
  libraryCount: number;
  folderCount: number;
  fileCount: number;
  totalBytes: number;
  uniquePermissionCount: number;
  warnings: string[];
  error?: string;
}

export interface SharePointInventoryNode {
  id: string;
  tenantId: string;
  scanId: string;
  parentId?: string;
  siteId?: string;
  driveId?: string;
  itemId?: string;
  kind: "site" | "library" | "folder" | "file";
  name: string;
  path: string;
  webUrl?: string;
  sizeBytes: number;
  fileCount: number;
  hasUniquePermissions: boolean;
  externalSharing?: string;
  lastScannedAt: string;
}

export interface SharePointInventory {
  scan: SharePointScan;
  nodes: SharePointInventoryNode[];
}

export interface SharePointPermissionTarget {
  siteId: string;
  driveId?: string;
  itemId?: string;
  kind: SharePointInventoryNode["kind"];
  path: string;
}

export interface SharePointScopePermission {
  id: string;
  principalId: string;
  principal: string;
  principalUpn?: string;
  type: "User" | "Guest" | "Security Group" | "Microsoft 365 Group" | "SharePoint Group" | "Link";
  role: string;
  source: string;
  inherited: boolean;
  expandable: boolean;
  memberCount?: number;
  sourceTarget?: SharePointPermissionTarget;
}

export interface SharePointPermissionRequest {
  target: SharePointPermissionTarget;
  principalId: string;
  principalUpn?: string;
  principalType?: SharePointScopePermission["type"];
  role: string;
  operation: "grant" | "revoke" | "restore_inheritance";
  breakInheritance?: boolean;
  copyAssignments?: boolean;
  approvalToken?: string;
}

export interface SharePointPermissionPreview {
  target: SharePointPermissionTarget;
  effectiveTarget?: SharePointPermissionTarget;
  principal: string;
  operation: SharePointPermissionRequest["operation"];
  role: string;
  before: SharePointScopePermission[];
  warnings: string[];
  blocked: string[];
  breaksInheritance: boolean;
  risk: "Low" | "Medium" | "High";
  approvalToken: string;
}

export interface SharePointPermissionResult {
  status: string;
  changeId: string;
}

/** One ThreatLocker-protected endpoint
 * (GET /threatlocker/devices). "secured" is full protection;
 * every other mode is a temporary state managed by the device write actions. */
export interface Device {
  id: string;
  organizationId?: string;
  hostname: string;
  group: string;
  os: "windows" | "mac" | "linux";
  agentVersion: string;
  mode:
    | "secured"
    | "monitor_only"
    | "learning"
    | "installation"
    | "maintenance"
    | "lockdown"
    | "isolated";
  /** RFC3339; empty = no scheduled end. */
  modeExpires: string;
  tamperProtection: boolean;
  lastCheckIn: string;
  online: boolean;
}

export interface DeviceGroup {
  id: string;
  name: string;
  deviceCount: number;
}

/** A ThreatLocker application-control request
 * (GET /threatlocker/approval-requests). Approving one creates a
 * ThreatLocker policy — RTM presents it as the policy write it is. */
export interface ApprovalRequest {
  id: string;
  organizationId?: string;
  deviceId: string;
  deviceName: string;
  requester: string;
  application: string;
  path: string;
  hash: string;
  requestType: "execution" | "elevation" | "storage";
  status: "pending" | "approved" | "denied";
  requestedAt: string;
}

/** A ThreatLocker policy row (GET /threatlocker/policies). */
export interface TLPolicy {
  id: string;
  name: string;
  action: string; // "permit" | "deny" | "ringfence" | "elevate" | …
  policyActionId: number;
  appliesTo: string;
  status: string; // "Enabled" | "Disabled"
  applicationCount: number;
  userCount: number;
  allUsers?: boolean;
  lastMatchedAt: string;
  monitorMode: number;
  organizationId?: string;
}

export interface TLPolicyApplication {
  id: string;
  name: string;
  path: string;
}

export interface TLPolicyDetail extends TLPolicy {
  description: string;
  comments: string;
  policyActionId: number;
  isEnabled: boolean;
  monitorMode: number;
  orderBy: number;
  neverExpires: boolean;
  endDate: string;
  logAction: boolean;
  notifyOnMatch: boolean;
  notifyOnRequest: boolean;
  killRunningProcesses: boolean;
  applicationSelection: number;
  applicationIds: string[];
  applications: TLPolicyApplication[];
  organizationId: string;
}

export interface TLPolicyPatch {
	approvalToken?: string;
  name?: string;
  description?: string;
  comments?: string;
  isEnabled?: boolean;
  policyActionId?: number;
  monitorMode?: number;
  orderBy?: number;
  neverExpires?: boolean;
  endDate?: string;
  logAction?: boolean;
  notifyOnMatch?: boolean;
  notifyOnRequest?: boolean;
  killRunningProcesses?: boolean;
  applicationSelection?: number;
  applicationIds?: string[];
}

export interface TLPolicyConsolidateResult {
  policyId: string;
  name: string;
  status: "Completed" | "Partial" | "Failed";
  mergedPolicyIds: string[];
  disabledPolicyIds: string[];
  failed: string[];
}

export interface TLApplication {
  id: string;
  name: string;
  description: string;
  organizationId: string;
  organization: string;
  source: "parent" | "tenant";
  osType: number;
  os: string;
  status: string;
  builtIn: boolean;
  hidden: boolean;
  policyCount: number;
  fileCount: number;
  updatedAt: string;
}

export interface TLApplicationFile {
  id: string;
  applicationFileId: number;
  applicationId: string;
  name: string;
  fullPath: string;
  processPath: string;
  cert: string;
  hash: string;
  notes: string;
  installedBy: string;
  osType: number;
  keyFile: boolean;
  isHashOnly: boolean;
}

export interface TLApplicationDetail extends TLApplication {
  files: TLApplicationFile[];
}

export interface TLApplicationPatch {
	approvalToken?: string;
  name?: string;
  description?: string;
}

export interface TLAppCleanupRequest {
	approvalToken?: string;
  appIds: string[];
  retainedAppId?: string;
  retainedPolicyId?: string;
  name?: string;
  confirmDelete?: boolean;
}

export interface TLAppParentPromotion {
  approvalToken?: string;
  applicationId: string;
  applicationName: string;
  applicationOrganizationId: string;
  sourceOrganizationId: string;
  policyId: string;
  policyName: string;
  destinationGroupId: string;
  destinationGroupName: string;
  parentOrganizationId: string;
  osType: number;
}

export interface TLComputerGroup {
  id: string;
  name: string;
  organizationId: string;
}

export interface TLAppCleanupPreview {
	approvalToken?: string;
  fingerprint: string;
  tenantId: string;
  retainedApp: TLApplication;
  retainedPolicy: TLPolicy;
  sourceApps: TLApplication[];
  fileRuleCount: number;
  policyCount: number;
  deleteAppIds: string[];
  deletePolicyIds: string[];
  /** Full rows behind deletePolicyIds; organizationId names the owning org. */
  deletePolicies: TLPolicy[];
  preservedPolicies: TLPolicy[];
  parentPromotion?: TLAppParentPromotion;
  globalDestination: TLComputerGroup;
  warnings: string[];
  blocked: string[];
}

export interface TLAppCleanupResult {
  status: "Completed" | "Partial" | "Failed";
  stage?: "parent_promotion" | "application_merge" | "policy_review";
  operationId?: string;
  verificationStatus?: TLAppCleanupOperationStatus;
  verification: TLAppCleanupVerification;
  retainedAppId: string;
  retainedPolicyId: string;
  copiedFileRules: number;
  expectedFileRules: number;
  deletedAppIds: string[];
  deletedPolicyIds: string[];
  preservedPolicies: TLPolicy[];
  promotedPolicyIds: string[];
  parentPromotion?: TLAppParentPromotion;
  retainedAppName?: string;
  retainedAppOsType?: number;
  failed: string[];
}

export interface TLAppCleanupVerificationCheck {
  key: string;
  label: string;
  passed: boolean;
  details: string;
}

export interface TLAppCleanupVerification {
  passed: boolean;
  checkedAt: string;
  checks: TLAppCleanupVerificationCheck[];
}

export interface TLAppCleanupCandidate {
  id: string;
  name: string;
  osType: number;
  os: string;
  score: number;
  confidence: "high" | "review";
  parentReady: boolean;
  recommendedRetainedAppId: string;
  organizationCount: number;
  totalFileRules: number;
  totalPolicies: number;
  applications: TLApplication[];
  reasons: string[];
}

export type TLAppCleanupOperationStatus =
  | "submitted"
  | "verification_pending"
  | "needs_reconciliation"
  | "verified"
  | "failed";

export interface TLAppCleanupOperation {
  id: string;
  tenantId: string;
  status: TLAppCleanupOperationStatus;
  requestedBy: string;
  result: TLAppCleanupResult;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

export interface TLPolicyTemplate {
  id: string;
  name: string;
  description: string;
  source: string;
  policy: TLPolicyDetail;
  updatedAt: string;
}

export interface TLPolicyDeployResult {
  templateId: string;
  status: "Completed" | "Partial" | "Failed";
  succeeded: string[];
  failed: string[];
}

export interface WorkingSet {
  id: string;
  name: string;
  description: string;
  type: "Users" | "Mailboxes" | "Groups";
  items: number;
  tenantId: string;
  tenant: string;
  userIds: string[];
  createdBy: string;
  lastUsed: string;
}

export interface NewWorkingSet {
  name: string;
  description: string;
  tenantId: string;
  userIds: string[];
}

export interface WorkingSetUpdate {
  name: string;
  description: string;
  userIds: string[];
}

export interface Job {
  id: string;
  type: string;
  tenant: string;
  status: "Running" | "Completed" | "Queued" | "Failed" | "Partial";
  progress: number;
  started: string;
  duration: string;
  triggeredBy: string;
  acknowledged?: boolean;
}

export interface ChangeRecord {
  id: string;
  timestamp: string;
  technician: string;
  tenant: string;
  action: string;
  target: string;
  status: "Completed" | "Partial" | "Failed" | "Reverted";
  revert: "Available" | "Reverted" | "Not supported" | "—";
}

export interface ChangeDetail extends ChangeRecord {
  graphRequestId: string;
  revertEligible: boolean;
  before: string[];
  after: string[];
  executionLog: string[];
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource: string;
  result: "Success" | "Denied" | "Failed";
  correlationId: string;
}

export interface Technician {
  id: string;
  name: string;
  email: string;
  role: string;
  tenants: string;
  status: "Active" | "Invited" | "Disabled";
  lastActive: string;
  mustChangePassword: boolean;
}

export interface Role {
  name: string;
  description: string;
  permissions: string;
  permissionKeys: string[];
  lockedPermissionKeys?: string[];
  level: string;
  levelTone: StatusTone;
  assigned: number;
}

export interface AppSetting {
  key: string;
  label: string;
  description: string;
  enabled: boolean;
  locked?: boolean;
  value?: string;
}

export interface DashboardStat {
  label: string;
  value: string;
  delta: string;
  tone: StatusTone;
}

export interface Approval {
  id: string;
  action: string;
  tenant: string;
  by: string;
  risk: "Low" | "Medium" | "High";
}

/** Input to POST /changes/preview and /changes/execute.
 * Directory + site-access actions target users (userIds); Exchange actions
 * target mailboxes (mailboxIds); set_site_sharing targets sites (siteIds).
 * Group actions require groupId; license actions skuId; site-access actions
 * siteId + role; mailbox-permission actions delegateId + permission. */
export interface ChangeRequest {
	approvalToken?: string;
  action:
    | "add_to_group"
    | "remove_from_group"
    | "assign_license"
    | "remove_license"
    | "block_signin"
    | "unblock_signin"
    | "revoke_sessions"
    | "reset_password"
    | "revoke_user_access"
    | "set_forwarding"
    | "clear_forwarding"
    | "enable_auto_reply"
    | "disable_auto_reply"
    | "grant_mailbox_permission"
    | "revoke_mailbox_permission"
    | "grant_site_access"
    | "revoke_site_access"
    | "set_site_sharing"
    | "enter_maintenance_mode"
    | "secure_device"
    | "lockdown_device"
    | "release_lockdown"
    | "isolate_device"
    | "release_isolation"
    | "enable_tamper_protection"
    | "disable_tamper_protection"
    | "restart_agent"
    | "approve_request"
    | "deny_request";
  tenantId: string;
  groupId?: string;
  skuId?: string;
  userIds?: string[];
  mailboxIds?: string[];
  forwardTo?: string;
  autoReplyMessage?: string;
  permission?: MailboxPermission["permission"];
  delegateId?: string;
  siteIds?: string[];
  siteId?: string;
  role?: SitePermission["role"];
  sharingLevel?: Site["externalSharing"];
  /** ThreatLocker: device actions target devices; approval actions target
   * approval requests. */
  deviceIds?: string[];
  maintenanceType?: MaintenanceType;
  durationMinutes?: number;
  approvalRequestIds?: string[];
  scope?: "computer" | "group" | "organization";
  expiresAt?: string;
  reason?: string;
}

/** enter_maintenance_mode types; disable_protection is the highest-risk state. */
export type MaintenanceType =
  | "monitor_only"
  | "learning"
  | "installation"
  | "disable_protection";

/** POST /admin/technicians response — the temp password is shown exactly
 * once; the account must rotate it on first login. */
export interface CreatedTechnician {
  technician: Technician;
  tempPassword: string;
}

/** POST /admin/technicians/{id}/reset-password. The temporary password is
 * returned once and every prior session for the account is revoked. */
export interface PasswordResetResult {
  status: "reset";
  tempPassword: string;
}

/** Input to POST /tenants/{id}/groups. v1 creates the two Graph-creatable
 * group types; distribution, dynamic distribution, and mail-enabled security
 * group creation is Exchange-managed and not offered here. */
export interface NewGroup {
  name: string;
  description: string;
  type: "M365" | "Security";
  mailNickname?: string;
}

/** Input to POST /admin/technicians. Role is Admin or Technician; every
 * account has access to all tenants. */
export interface NewTechnician {
  name: string;
  email: string;
  role: "Admin" | "Technician";
}

/** What-If preview payload (UX Spec → What If Preview Dialog). */
export interface WhatIfPreview {
	approvalToken?: string;
  action: string;
  tenant: string;
  risk: "Low" | "Medium" | "High";
  requiredPermission: string;
  targetCount: number;
  /** Plural object type ("users", "mailboxes", "sites") for the count label. */
  targetNoun: string;
  changes: { object: string; detail: string; change: string }[];
  moreCount: number;
  warnings: string[];
  skipped: { object: string; reason: string }[];
  /** Targets refused because they are mastered by on-prem AD. The write is
   * never queued; `resolution` says where to make the change instead. */
  blocked: { object: string; reason: string; resolution: string }[];
}

/** One capability row from POST /tenants/{id}/preflight. Microsoft-issued
 * token roles confirm exact and documented broader application grants. */
export interface PreflightCheck {
  category: "Security Operations" | "SharePoint" | "Exchange" | "Directory & Identity" | "Licensing" | string;
  area: string;
  resource: "Microsoft Graph" | "SharePoint Online" | string;
  permission: string;
  status: "ok" | "missing" | "error" | "not_provisioned" | "sample" | "unchecked";
  detail?: string;
  grantedVia?: string;
}

/** Cached GET and diagnostic POST /tenants/{id}/preflight response. */
export interface Preflight {
  mode: "sample" | "live";
  ranAt: string;
  checks: PreflightCheck[];
}

/** POST /tenants/{id}/exchange/bootstrap — an exact, one-use authorization
 * preview plus the Microsoft OAuth URL. No Microsoft token reaches the UI. */
export interface ExchangeBootstrapStart {
  authorizationUrl: string;
  expiresAt: string;
  preview: {
    delegatedPermission: string;
    runtimePermission: string;
    exchangeRole: string;
    scope: string;
    tokenRetention: string;
    apiVersion: string;
  };
}

export interface ExchangeBootstrapPreview {
  approvalToken: string;
  preview: ExchangeBootstrapStart["preview"];
  callbackUrl: string;
  httpsReady: boolean;
}

/** GET /tenants/{id}/users/{userId}/raw — the full directory object, every
 * attribute the app can read (extension attributes, identities, …). */
export interface UserRaw {
  id: string;
  attributes: Record<string, unknown>;
}

/** How a Share Detective finding grants the subject access. Only confirmed
 * direct grants are safely revocable per subject. */
export type ShareClassification =
  | "direct_user"
  | "specific_people_link"
  | "broad_link"
  | "group_based"
  | "site_membership"
  | "inherited";

export interface ShareSubject {
  id: string;
  name: string;
  upn: string;
  type: "Member" | "Guest";
}

/** Per-site scan honesty: a skipped site is a visible coverage gap. */
export interface ShareCoverage {
  siteId: string;
  siteName: string;
  status: "scanned" | "partial" | "skipped";
  itemsScanned: number;
  reason?: string;
}

export interface ShareFinding {
  id: string;
  siteId: string;
  siteName: string;
  driveId?: string;
  itemId?: string;
  itemPath: string;
  itemType: "site" | "folder" | "file";
  webUrl?: string;
  classification: ShareClassification;
  role: string;
  permissionId?: string;
  via?: string;
  revocable: boolean;
  revoked: boolean;
  detail?: string;
}

export interface ShareSummary {
  sitesDiscovered: number;
  sitesScanned: number;
  sitesSkipped: number;
  itemsScanned: number;
  findings: number;
  revocable: number;
}

/** A tenant-wide scan for everything shared with a subject
 * (POST/GET /tenants/{id}/share-detective/investigations). Ephemeral —
 * export or act on findings; a fresh scan beats trusting a stale one. */
export interface ShareInvestigation {
  id: string;
  tenantId: string;
  tenantName: string;
  subject: ShareSubject;
  status: "running" | "completed" | "failed";
  startedAt: string;
  completedAt?: string;
  startedBy: string;
  error?: string;
  summary: ShareSummary;
  coverage: ShareCoverage[];
  findings: ShareFinding[];
}

export interface ShareRevokeAction {
  findingId: string;
  siteName: string;
  itemPath: string;
  action: "delete_permission" | "manual_review";
  reason?: string;
}

/** What-If plan for revoking selected findings. */
export interface ShareRevokePreview {
  approvalToken?: string;
  subject: ShareSubject;
  tenant: string;
  risk: "Low" | "Medium" | "High";
  revocableCount: number;
  actions: ShareRevokeAction[];
  warnings: string[];
}

export interface ShareRevokeResult {
  status: "Completed" | "Partial" | "Failed";
  revoked: string[];
  failed: string[];
}

/** RTM's local SOC workflow state. Microsoft Defender remains the incident
 * source of truth; these values are an RTM-only owner/status overlay. */
export type SecurityTriageStatus =
  | "New"
  | "In Progress"
  | "Resolved"
  | "Dismissed";

export type SecuritySeverity =
  | "Critical"
  | "High"
  | "Medium"
  | "Low"
  | "Informational"
  | "Unknown";

export interface SecurityEntity {
  type: string;
  label: string;
  key?: string;
}

export interface SecurityEvidenceChange {
  field: string;
  before?: string;
  after?: string;
}

export interface SecurityEvidenceSummary {
  eventId: string;
  operation: string;
  actor?: string;
  target?: string;
  relatedResource?: string;
  workload?: string;
  clientIp?: string;
  resultStatus?: string;
  occurredAt: string;
  changes?: SecurityEvidenceChange[];
}

export interface SecurityIncident {
  id: string;
  tenantId: string;
  tenantName: string;
  title: string;
  description?: string;
  severity: SecuritySeverity | string;
  status: SecurityTriageStatus;
  providerStatus: string;
  classification?: string;
  determination?: string;
  providerOwner?: string;
  owner?: string;
  source: string;
  detectionType?: "direct" | "threshold" | "correlation" | "heuristic" | string;
  confidence?: "high" | "medium" | "low" | string;
  ruleId?: string;
  ruleVersion?: number;
  alertCount: number;
  entityCount: number;
  entities?: SecurityEntity[];
  evidence?: SecurityEvidenceSummary;
  rtmReceivedAt?: string;
  createdAt: string;
  updatedAt: string;
  incidentWebUrl?: string;
  sample?: boolean;
}

export interface SecurityAlert {
  id: string;
  title: string;
  severity: string;
  status: string;
  serviceSource: string;
  detectionSource?: string;
  createdAt: string;
  updatedAt: string;
}

export interface SecurityTimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  description?: string;
  source: string;
}

export interface SecurityIncidentDetail extends SecurityIncident {
  alerts: SecurityAlert[];
  timeline: SecurityTimelineEvent[];
  remediation: SecurityRemediationPlan;
}

export interface SecurityStorylineEntity {
  type: string;
  key: string;
  label: string;
  tenantId?: string;
  primary?: boolean;
}

export interface SecurityStoryline {
  id: string;
  packId: string;
  title: string;
  summary: string;
  severity: SecuritySeverity | string;
  riskScore: number;
  confidence: "high" | "medium" | "low";
  status: SecurityTriageStatus;
  owner?: string;
  firstSeen: string;
  lastSeen: string;
  updatedAt: string;
  tenantIds: string[];
  tenantNames: string[];
  entities: SecurityStorylineEntity[];
  stages: string[];
  workloads: string[];
  detectionIds: string[];
  eventIds: string[];
  signalCount: number;
  affectedUsers: number;
  affectedResources: number;
  reasons: string[];
  weakEvidence?: string[];
  recommendedActions: string[];
  sample?: boolean;
}

export interface SecurityStorylineEvidence {
  detectionId: string;
  ruleId: string;
  title: string;
  severity: string;
  confidence: string;
  stage: string;
  occurredAt: string;
  tenantId: string;
  tenantName: string;
  events: SecurityEvidenceSummary[];
}

export interface SecurityStorylineDetail extends SecurityStoryline {
  evidence: SecurityStorylineEvidence[];
}

export interface SecurityRemediationPlan {
  category: string;
  summary: string;
  steps: SecurityRemediationStep[];
  completionCriteria: string[];
}

export interface SecurityRemediationStep {
  phase: "Contain" | "Investigate" | "Eradicate" | "Recover" | "Validate" | string;
  urgency: "Immediate" | "High" | "Standard" | string;
  title: string;
  description: string;
  rtmAction?: string;
}

export interface SecuritySummary {
  open: number;
  critical: number;
  high: number;
  tenantsCovered: number;
  tenantsTotal: number;
  liveTenants: number;
  sampleTenants: number;
  ingestionHealth: number;
}

export interface SecuritySeverityCount {
  severity: SecuritySeverity | string;
  count: number;
}

export interface SecurityConnectorSummary {
  key: string;
  name: string;
  status: "healthy" | "degraded" | "sample" | "planned" | string;
  healthyTenants: number;
  attentionTenants: number;
  sampleTenants: number;
  requiredPermission?: string;
}

export interface SecurityCoverage {
  tenantId: string;
  tenantName: string;
  connectorKey: string;
  connectorName: string;
  status: "healthy" | "missing_permission" | "not_provisioned" | "degraded" | "sample" | string;
  detail?: string;
  requiredPermission: string;
  checkedAt: string;
}

export interface SecurityHistoryImport {
	tenantId: string;
	tenantName?: string;
	jobId?: string;
	requestedWindow: "start_now" | "last_24h" | "last_7d" | "maximum_available";
	windowHours: number;
	historicalIncidentMode: "recent_24h" | "all" | "baseline_only";
	status: "queued" | "running" | "completed" | "partial" | "failed";
	progress: number;
	feedsCompleted: number;
	feedsTotal: number;
	eventsReceived: number;
	eventsInserted: number;
	detectionsCreated: number;
	detail?: string;
	requestedAt: string;
	startedAt?: string;
	completedAt?: string;
	incidentCutoffAt?: string;
}

/** One bounded-concurrency, cross-tenant monitoring snapshot. */
export interface SecurityOperationsSnapshot {
  generatedAt: string;
  summary: SecuritySummary;
  severity: SecuritySeverityCount[];
  connectors: SecurityConnectorSummary[];
	coverage: SecurityCoverage[];
	historyImports: SecurityHistoryImport[];
	storylines: SecurityStoryline[];
  incidents: SecurityIncident[];
  warnings: string[];
}

export interface SecurityTriageRequest {
  status?: SecurityTriageStatus;
  assignment?: "me" | "unassigned";
}

export interface SecurityIncidentReference {
  tenantId: string;
  incidentId: string;
}

export type SecurityBulkTriageRequest =
  | {
      action: "accept";
      incidents: SecurityIncidentReference[];
    }
  | {
      action: "set_status";
      status: SecurityTriageStatus;
      incidents: SecurityIncidentReference[];
    };

export interface SecurityBulkTriageFailure extends SecurityIncidentReference {
  message: string;
}

export interface SecurityBulkTriageIncident extends SecurityIncidentReference {
  status: SecurityTriageStatus;
  owner?: string;
}

export interface SecurityBulkTriageResult {
  requested: number;
  updated: number;
  failed: number;
  incidents: SecurityBulkTriageIncident[];
  failures: SecurityBulkTriageFailure[];
}

export interface SecurityAuditEvent {
  id: string;
  tenantId: string;
  tenantName: string;
  providerRecordId: string;
  contentType: string;
  workload: string;
  operation: string;
  actor?: string;
  clientIp?: string;
  objectId?: string;
  resultStatus?: string;
  occurredAt: string;
  availableAt: string;
  ingestedAt: string;
  sources: string[];
  sample?: boolean;
	historicalImport?: boolean;
}

export interface SecurityAuditEventSearch {
  query?: string;
  tenantId?: string;
  workload?: string;
  operation?: string;
  actor?: string;
  clientIp?: string;
  result?: string;
  from: string;
  to: string;
  limit?: number;
  offset?: number;
}

export interface SecurityAuditEventPage {
  events: SecurityAuditEvent[];
  offset: number;
  nextOffset?: number;
  limit: number;
  limited: boolean;
  windowDays: number;
}

export interface SecurityNativeDetection {
  id: string;
  tenantId: string;
  eventId: string;
  eventIds?: string[];
  ruleId: string;
  ruleVersion: number;
  title: string;
  description: string;
  severity: SecuritySeverity | string;
  detectionType: "direct" | "threshold" | "correlation" | "heuristic" | string;
  confidence: "high" | "medium" | "low" | string;
  entities?: SecurityEntity[];
  occurredAt: string;
  createdAt: string;
  sample?: boolean;
}

export type OfflineInvestigationStatus =
  | "draft"
  | "ready"
  | "queued"
  | "analyzing"
  | "complete"
  | "failed";

export interface OfflineEvidenceCoverage {
  key: "entra_sign_ins" | "entra_directory_audits" | "m365_activity" | string;
  label: string;
  status: "present" | "partial" | "missing";
  records: number;
  detail: string;
  fields?: string[];
  missingFields?: string[];
}

export interface OfflineInvestigation {
  id: string;
  name: string;
  tenantLabel: string;
  status: OfflineInvestigationStatus;
  progress: number;
  detail?: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  analyzedAt?: string;
  periodStart?: string;
  periodEnd?: string;
  eventCount: number;
  detectionCount: number;
  highPriorityCount: number;
  storylineCount: number;
  coverage: OfflineEvidenceCoverage[];
}

export interface OfflineInvestigationFile {
  id: string;
  investigationId: string;
  name: string;
  mediaType: string;
  evidenceType: string;
  sizeBytes: number;
  sha256: string;
  status: string;
  recordCount: number;
  uploadedAt: string;
}

export interface OfflineTimelineEvent {
  id: string;
  evidenceType: string;
  source: string;
  workload: string;
  operation: string;
  actor?: string;
  clientIp?: string;
  objectId?: string;
  resultStatus?: string;
  severity?: SecuritySeverity | string;
  occurredAt: string;
  facts: OfflineTimelineFact[];
  signals: OfflineTimelineSignal[];
}

export interface OfflineTimelineFact {
  label: string;
  value: string;
}

export interface OfflineTimelineSignal {
  ruleId: string;
  title: string;
  severity: SecuritySeverity | string;
}

export interface OfflineInvestigationDetail extends OfflineInvestigation {
  files: OfflineInvestigationFile[];
  timeline: OfflineTimelineEvent[];
  detections: SecurityNativeDetection[];
  storylines: SecurityStoryline[];
}

export interface SecurityAuditEventDetail extends SecurityAuditEvent {
  raw: unknown;
  rawTruncated: boolean;
  sourceEvidence: SecurityAuditEventEvidence[];
  relatedDetections: SecurityNativeDetection[];
}

export interface SecurityAuditEventEvidence {
  source: string;
  providerRecordId: string;
  contentType: string;
  availableAt: string;
  ingestedAt: string;
  raw: unknown;
  rawTruncated: boolean;
}

export interface SecurityRuleExclusion {
  field: "actor" | "clientIp" | "objectId" | "tenantId";
  match: "exact" | "contains";
  value: string;
}

export interface SecurityRuleDefinition {
  triggerMode?: "builtIn" | "custom";
  workloads?: string[];
  operations?: string[];
  operationMatch?: "exact" | "contains";
  actors?: string[];
  clientIps?: string[];
  results?: string[];
  objectContains?: string[];
  rawContains?: string[];
  threshold?: number;
  windowMinutes?: number;
  groupBy?: "actor" | "clientIp" | "objectId" | "tenant";
  exclusions?: SecurityRuleExclusion[];
}

export interface SecurityDetectionRule {
  id: string;
  ruleId: string;
  baseRuleId?: string;
  name: string;
  description: string;
  builtIn: boolean;
  override: boolean;
  locked: boolean;
  detectionType: "direct" | "threshold" | "correlation" | "heuristic" | string;
  severity: SecuritySeverity | string;
  confidence: "high" | "medium" | "low" | string;
  enabled: boolean;
  scope: "global" | "tenant";
  tenantId?: string;
  tenantName?: string;
  definition: SecurityRuleDefinition;
  revision: number;
  updatedBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface SecurityDetectionRuleRevision {
  ruleId: string;
  revision: number;
  snapshot: SecurityDetectionRule;
  actor: string;
  createdAt: string;
}

export interface SecurityRulePreview {
  matchedEvents: number;
  eventsScanned: number;
  tenantsMatched: Record<string, number>;
  sampleEvents: SecurityAuditEvent[];
  warnings: string[];
  approvalToken: string;
}

/** Safe, bounded choices for the detection-rule editor. Dynamic choices are
 * projected from normalized audit columns; raw provider values are excluded. */
export interface SecurityRuleConditionOptions {
  workloads: string[];
  operations: string[];
  actors: string[];
  clientIps: string[];
  results: string[];
  objects: string[];
  rawEvidenceTerms: string[];
  eventsScanned: number;
  evidenceWindowDays: number;
  limited: boolean;
}

export interface SecurityRuleMutation {
  rule: SecurityDetectionRule;
  approvalToken?: string;
}

/** Cross-tenant global report (UX Spec → Global Reports). */
export interface GlobalReport {
  columns: string[];
  rows: GlobalReportCell[][];
}

export type GlobalReportCell =
  | { text: string }
  | { badge: string; tone: StatusTone };
