/**
 * In-memory mock dataset. Mirrors the realistic placeholder data from the
 * design prototype and conforms to the API model types. The mock client
 * (src/api/client.ts) serves these until the Go API at /api/v1 is available.
 */
import type {
  ApiError,
  Approval,
  ApprovalRequest,
  AppSetting,
  AuditEntry,
  ChangeDetail,
  ChangeRecord,
  DashboardStat,
  Device,
  DeviceGroup,
  GlobalReport,
  Group,
  GroupMember,
  Job,
  License,
  Mailbox,
  MailboxPermission,
  MailboxPermissionFeed,
  MailboxSettings,
  OfflineInvestigation,
  OfflineInvestigationDetail,
  OfflineInvestigationFile,
  Role,
  Site,
  SitePermission,
  Technician,
  Tenant,
  TenantSettingsUpdate,
  TLAppCleanupCandidate,
  TLAppCleanupOperation,
  TLAppCleanupPreview,
  TLAppCleanupRequest,
  TLAppCleanupResult,
  TLAppParentPromotion,
  TLApplication,
  TLApplicationDetail,
  TLApplicationFile,
  TLApplicationPatch,
  TLPolicy,
  TLPolicyConsolidateResult,
  TLPolicyDeployResult,
  TLPolicyDetail,
  TLPolicyPatch,
  TLPolicyTemplate,
  Preflight,
  ShareFinding,
  ShareInvestigation,
  ShareRevokePreview,
  ShareRevokeResult,
  SharePointInventory,
  SharePointInventoryNode,
  SharePointInventoryScope,
  SharePointPermissionPreview,
  SharePointPermissionRequest,
  SharePointPermissionResult,
  SharePointScan,
  SharePointScopePermission,
  SecurityIncidentDetail,
  SecurityRemediationPlan,
  SecurityAuditEventDetail,
  SecurityAuditEventPage,
  SecurityAuditEventSearch,
  SecurityDetectionRule,
  SecurityDetectionRuleRevision,
  SecurityRuleConditionOptions,
  SecurityOperationsSnapshot,
  SecurityStoryline,
  SecurityStorylineDetail,
  SecurityBulkTriageRequest,
  SecurityBulkTriageResult,
  SecurityRulePreview,
  SecurityTriageRequest,
  User,
  UserRaw,
  WhatIfPreview,
  WorkingSet,
} from "@/types";
import {
  OFFLINE_EVIDENCE_MAX_CASE_BYTES,
  OFFLINE_EVIDENCE_MAX_CASE_RECORDS,
  OFFLINE_EVIDENCE_MAX_FILE_BYTES,
  OFFLINE_EVIDENCE_MAX_FILE_RECORDS,
} from "@/lib/offline-investigation-limits";
import type { ExportGenerateRequest } from "@/lib/csv";
import { normalizeWorkingSetUserIds } from "@/features/working-sets/workingSet";

// Single seeded example tenant, mirroring the backend seeds. Mutable so the
// mock createTenant/removeTenant behave like the real API.
export const tenants: Tenant[] = [
  {
    id: "ten_1",
    name: "Contoso Ltd",
    domain: "contoso.onmicrosoft.com",
    status: "Connected",
    users: 482,
    lastGraphTest: "2m ago",
    microsoftTenantId: "a1f4c9d2-7b3e-4a18-9f8d-2c4e7a1b6d05",
    modules: ["Users", "Groups", "Exchange", "SharePoint", "Licensing"],
    connections: { graph: false, exchange: false, sharePoint: false },
    identityMode: "mixed",
    syncedUsers: 2,
    cloudUsers: 10,
    syncedGroups: 2,
    cloudGroups: 6,
  },
];

let tenantSeq = 1;

/** Mock for POST /tenants — appends a Connected tenant (secret is discarded,
 * matching the real API which never returns it). */
export function createTenant(body: {
  name: string;
  domain: string;
  microsoftTenantId: string;
  clientId?: string;
  exchangeClientId?: string;
  sharePointAdminUrl?: string;
	historyWindow?: "start_now" | "last_24h" | "last_7d" | "maximum_available";
	historicalIncidentMode?: "recent_24h" | "all" | "baseline_only";
}): Tenant {
  tenantSeq += 1;
  const t: Tenant = {
    id: `ten_new_${tenantSeq}`,
    name: body.name,
    domain: body.domain,
    microsoftTenantId: body.microsoftTenantId,
    status: "Connected",
    users: 0,
    lastGraphTest: "just now",
    modules: ["Users", "Groups", "Exchange", "SharePoint", "Licensing"],
    connections: {
      graph: !!body.clientId,
      exchange: !!body.exchangeClientId,
      sharePoint: !!body.sharePointAdminUrl,
    },
  };
  tenants.push(t);
  return t;
}

/** Mock for DELETE /tenants/{id}. Returns false when the tenant is unknown. */
export function removeTenant(id: string): boolean {
  const i = tenants.findIndex((t) => t.id === id);
  if (i < 0) return false;
  tenants.splice(i, 1);
  return true;
}

export function updateTenant(id: string, body: TenantSettingsUpdate): Tenant {
  const tenant = tenants.find((item) => item.id === id);
  if (!tenant) throw new Error("Tenant not found");
  if (body.name !== undefined) tenant.name = body.name;
  if (body.domain !== undefined) tenant.domain = body.domain;
  if (body.microsoftTenantId !== undefined) tenant.microsoftTenantId = body.microsoftTenantId;
  if (body.clearGraph) tenant.connections.graph = false;
  else if (body.clientId && body.clientSecret) tenant.connections.graph = true;
  if (body.clearExchange) tenant.connections.exchange = false;
  else if (body.exchangeClientId && body.exchangeClientSecret) tenant.connections.exchange = true;
  if (body.sharePointAdminUrl !== undefined) tenant.connections.sharePoint = !!body.sharePointAdminUrl;
  return tenant;
}

// Contoso is a "mixed" tenant: the IT staff (Caleb, Julia) are synced from
// on-prem AD, so the What-If gate blocks on-prem-mastered directory writes
// against them (sign-in block, synced-group membership). They keep every
// cloud action. Everyone else is cloud-only.
export const users: User[] = [
  ["Avery Quinn", "avery.quinn@contoso.com", "Sales", "E5", "Enabled", "Active", "1h ago", "cloud"],
  ["Bianca Lopez", "bianca.lopez@contoso.com", "Finance", "E5", "Enforced", "Active", "22m ago", "cloud"],
  ["Caleb Stone", "caleb.stone@contoso.com", "IT", "E5", "Enabled", "Active", "5m ago", "on_prem"],
  ["Dana White", "dana.white@contoso.com", "Marketing", "E3", "Disabled", "Active", "3d ago", "cloud"],
  ["Ethan Park", "ethan.park@contoso.com", "Sales", "E3", "Enabled", "Active", "2h ago", "cloud"],
  ["Farah Noor", "farah.noor@contoso.com", "HR", "E5", "Enforced", "Active", "40m ago", "cloud"],
  ["Gavin Reed", "gavin.reed@contoso.com", "Sales", "—", "Disabled", "Disabled", "60d ago", "cloud"],
  ["Hana Kim", "hana.kim@contoso.com", "Finance", "E5", "Enabled", "Active", "12m ago", "cloud"],
  ["Ivan Petrov", "ivan.petrov@partner.com", "External", "—", "Disabled", "Guest", "8d ago", "cloud"],
  ["Julia Sanz", "julia.sanz@contoso.com", "IT", "E5", "Enforced", "Active", "just now", "on_prem"],
  ["Kemal Yilmaz", "kemal.yilmaz@contoso.com", "Operations", "E3", "Enabled", "Active", "1d ago", "cloud"],
  ["Lena Vogt", "lena.vogt@contoso.com", "Marketing", "E3", "Disabled", "Active", "4h ago", "cloud"],
].map((u, i) => ({
  id: `usr_${i + 1}`,
  name: u[0],
  givenName: String(u[0]).split(" ")[0],
  surname: String(u[0]).split(" ").slice(1).join(" "),
  upn: u[1],
  mail: u[1],
  userType: u[5] === "Guest" ? "Guest" : "Member",
  department: u[2],
  jobTitle: `${u[2]} Specialist`,
  companyName: u[5] === "Guest" ? "Partner organization" : "Contoso",
  officeLocation: i % 3 === 0 ? "Seattle HQ" : i % 3 === 1 ? "New York" : "Remote",
  employeeId: u[5] === "Guest" ? "" : `CT-${String(i + 1).padStart(4, "0")}`,
  employeeType: u[5] === "Guest" ? "Contractor" : "Employee",
  businessPhones: u[5] === "Guest" ? [] : [`+1 206 555 ${String(1000 + i)}`],
  mobilePhone: i % 2 === 0 ? `+1 425 555 ${String(2000 + i)}` : "",
  streetAddress: u[5] === "Guest" ? "" : "1 Contoso Way",
  city: u[5] === "Guest" ? "" : i % 3 === 1 ? "New York" : "Seattle",
  state: u[5] === "Guest" ? "" : i % 3 === 1 ? "NY" : "WA",
  postalCode: u[5] === "Guest" ? "" : i % 3 === 1 ? "10001" : "98101",
  country: u[5] === "Guest" ? "" : "United States",
  usageLocation: u[5] === "Guest" ? "" : "US",
  preferredLanguage: "en-US",
  createdDateTime: `202${i % 5}-0${(i % 8) + 1}-15T12:00:00Z`,
  onPremisesSamAccountName: u[7] === "on_prem" ? String(u[1]).split("@")[0] : "",
  onPremisesLastSyncDateTime: u[7] === "on_prem" ? "2026-08-26T10:45:00Z" : "",
  license: u[3] === "E5" ? "Microsoft 365 E5" : u[3] === "E3" ? "Microsoft 365 E3" : "Unlicensed",
  licenses: u[3] === "—" ? [] : [u[3] === "E5" ? "Microsoft 365 E5" : "Microsoft 365 E3"],
  mfa: u[4] as User["mfa"],
  status: u[5] as User["status"],
  lastSignIn: new Date(Date.UTC(2026, 7, 26, 12) - [60, 22, 5, 4320, 120, 40, 86400, 12, 11520, 0, 1440, 240][i] * 60_000).toISOString(),
  lastSignInAvailable: true,
  sourceOfAuthority: u[7] as User["sourceOfAuthority"],
}));

export const groups: Group[] = [
  ["Sales — All Staff", "M365", "Assigned", 86, "Yes", "Graph", "Cloud"],
  ["Finance", "Security", "Assigned", 22, "No", "Graph", "Cloud"],
  ["All Company", "Dynamic Distribution", "Dynamic", 482, "Yes", "Exchange", "Cloud"],
  ["IT Admins", "Security", "Assigned", 9, "No", "Graph", "On-prem sync"],
  ["Project Falcon", "M365", "Assigned", 14, "Yes", "Graph", "Cloud"],
  ["Marketing", "M365", "Assigned", 31, "Yes", "Graph", "Cloud"],
  ["Helpdesk", "Mail-enabled Sec.", "Assigned", 6, "Yes", "Graph", "Cloud"],
  ["Executives", "Security", "Assigned", 5, "No", "Graph", "On-prem sync"],
  ["Facilities Notices", "Distribution", "Assigned", 118, "Yes", "Exchange", "Cloud"],
].map((g, i) => ({
  id: `grp_${i + 1}`,
  name: g[0] as string,
  type: g[1] as Group["type"],
  membership: g[2] as Group["membership"],
  members: g[3] as number,
  mail: g[4] as Group["mail"],
  service: g[5] as Group["service"],
  source: g[6] as Group["source"],
}));

let groupSeq = groups.length;

/** Mock for POST /tenants/{id}/groups — appends a new Assigned group. */
export function createGroup(body: {
  name: string;
  description: string;
  type: "M365" | "Security";
}): Group {
  groupSeq += 1;
  const g: Group = {
    id: `grp_new_${groupSeq}`,
    name: body.name,
    type: body.type,
    membership: "Assigned",
    members: 0,
    mail: body.type === "M365" ? "Yes" : "No",
    service: "Graph",
    source: "Cloud",
  };
  groups.push(g);
  return g;
}

export const groupMembers: GroupMember[] = [
  ["usr_1", "Avery Quinn", "avery.quinn@contoso.com", "Owner", "2024-03-12"],
  ["usr_2", "Bianca Lopez", "bianca.lopez@contoso.com", "Member", "2024-05-01"],
  ["usr_5", "Ethan Park", "ethan.park@contoso.com", "Member", "2025-01-22"],
  ["usr_8", "Hana Kim", "hana.kim@contoso.com", "Member", "2025-06-14"],
  ["usr_10", "Julia Sanz", "julia.sanz@contoso.com", "Member", "2026-02-09"],
  ["usr_11", "Kemal Yilmaz", "kemal.yilmaz@contoso.com", "Member", "2026-04-30"],
].map((m) => ({
  id: m[0],
  name: m[1],
  upn: m[2],
  role: m[3] as GroupMember["role"],
  added: m[4],
}));

export const licenses: License[] = [
  ["SPE_E5", "Microsoft 365 E5", 200, 182],
  ["SPE_E3", "Microsoft 365 E3", 300, 241],
  ["ENTERPRISEPACK", "Office 365 E3", 150, 150],
  ["EMSPREMIUM", "Enterprise Mobility + Security E5", 120, 77],
  ["POWER_BI_PRO", "Power BI Pro", 80, 52],
  ["PROJECTPROFESSIONAL", "Project Plan 3", 25, 19],
  ["VISIOCLIENT", "Visio Plan 2", 40, 12],
  ["MCOEV", "Teams Phone Standard", 60, 44],
].map((l) => {
  const total = l[2] as number;
  const assigned = l[3] as number;
  const available = total - assigned;
  return {
    skuId: "sku-" + (l[0] as string),
    sku: l[0] as string,
    product: l[1] as string,
    assigned,
    available,
    total,
    utilization: Math.round((assigned / total) * 100),
    pool: available === 0 ? "Full" : available < 5 ? "Low" : "OK",
  };
});

export const mailboxes: Mailbox[] = [
  ["Avery Quinn", "avery.quinn@contoso.com", "User", "14.2 GB", 28411, "On", "No"],
  ["Sales Shared", "sales@contoso.com", "Shared", "42.8 GB", 91200, "On", "Yes"],
  ["Conf Room A", "rooma@contoso.com", "Room", "0.4 GB", 210, "Off", "No"],
  ["Bianca Lopez", "bianca.lopez@contoso.com", "User", "9.7 GB", 18044, "On", "Yes"],
  ["Support", "support@contoso.com", "Shared", "61.1 GB", 140233, "On", "No"],
  ["Projector 01", "equip01@contoso.com", "Equipment", "0.1 GB", 54, "Off", "No"],
  ["Caleb Stone", "caleb.stone@contoso.com", "User", "22.0 GB", 39870, "On", "No"],
].map((m, i) => ({
  id: `mbx_${i + 1}`,
  name: m[0] as string,
  email: m[1] as string,
  userPrincipalName: m[1] as string,
  aliases: i === 0 ? ["avery@contoso.com"] : i === 4 ? ["help@contoso.com", "helpdesk@contoso.com"] : [],
  type: m[2] as Mailbox["type"],
  accountStatus: "Enabled",
  sourceOfAuthority: i === 6 ? "on_prem" : "cloud",
  createdAt: `202${i % 5}-0${(i % 8) + 1}-18T16:20:00Z`,
  licenseCount: m[2] === "User" ? 2 : 0,
  size: m[3] as string,
  items: m[4] as number,
  archive: m[5] as Mailbox["archive"],
  litigationHold: m[6] as Mailbox["litigationHold"],
  usageAvailable: true,
  usageAsOf: "2026-08-24",
  lastActivityAt: i === 2 ? "2026-08-22" : "2026-08-24",
  deletedItems: [318, 1102, 5, 211, 4201, 0, 802][i],
  deletedSize: ["124.0 MB", "1.8 GB", "0 B", "92.4 MB", "6.2 GB", "0 B", "640.0 MB"][i],
  warningQuota: i === 4 ? "98.0 GB" : "49.0 GB",
  sendQuota: i === 4 ? "99.0 GB" : "49.5 GB",
  sendReceiveQuota: i === 4 ? "100.0 GB" : "50.0 GB",
  usageDetail: "Mailbox usage report matched this directory identity.",
}));

function defaultMailboxSettings(mailboxId: string): MailboxSettings {
  return {
    mailboxId,
    autoReply: false,
    autoReplyStatus: "disabled",
    autoReplyMessage: "",
    externalAutoReplyMessage: "",
    externalAudience: "none",
    autoReplyStart: "",
    autoReplyEnd: "",
    forwardingTo: "",
    forwardingRules: [],
    rulesAvailable: true,
    rulesDetail: "",
    timeZone: "Pacific Standard Time",
    language: "English (United States)",
    dateFormat: "M/d/yyyy",
    timeFormat: "h:mm tt",
    workingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
    workingHoursStart: "08:00:00",
    workingHoursEnd: "17:00:00",
    workingHoursTimeZone: "Pacific Standard Time",
    userPurpose: "user",
    delegateMeetingMessageDelivery: "sendToDelegateAndInformationToPrincipal",
  };
}

/** Mailbox settings keyed by mailbox id (mirrors the backend sample data);
 * mailboxes not listed read as defaults. */
const mailboxSettings: Record<string, MailboxSettings> = {
  mbx_4: {
    ...defaultMailboxSettings("mbx_4"),
    autoReply: true,
    autoReplyStatus: "scheduled",
    autoReplyMessage:
      "I am out of the office until Monday, July 6. For urgent matters contact sales@contoso.com.",
    externalAutoReplyMessage: "Bianca is away. Please contact sales@contoso.com.",
    externalAudience: "contactsOnly",
    autoReplyStart: "2026-08-24T17:00:00",
    autoReplyEnd: "2026-08-31T08:00:00",
  },
  mbx_7: {
    ...defaultMailboxSettings("mbx_7"),
    forwardingTo: "it-archive@contoso.com",
    forwardingRules: [
      { id: "rtm_forward", name: "RTM Managed Forwarding", enabled: true, hasError: false, readOnly: false, mode: "Forward", recipients: ["it-archive@contoso.com"], managedByRtm: true },
      { id: "rule_external", name: "Vendor invoices", enabled: true, hasError: false, readOnly: false, mode: "Redirect", recipients: ["processing@accounting-partner.example"], managedByRtm: false },
    ],
  },
};

export function getMailboxSettings(mailboxId: string): MailboxSettings {
  return mailboxSettings[mailboxId] ?? defaultMailboxSettings(mailboxId);
}

const mailboxPermissions: Record<string, MailboxPermission[]> = {
  mbx_2: [
    { id: "mp_1", delegate: "Avery Quinn", delegateUpn: "avery.quinn@contoso.com", permission: "Full Access", granted: "2024-11-02" },
    { id: "mp_2", delegate: "Ethan Park", delegateUpn: "ethan.park@contoso.com", permission: "Send As", granted: "2025-03-18" },
  ],
  mbx_4: [
    { id: "mp_3", delegate: "Hana Kim", delegateUpn: "hana.kim@contoso.com", permission: "Send on Behalf", granted: "2025-09-01" },
  ],
  mbx_5: [
    { id: "mp_4", delegate: "Caleb Stone", delegateUpn: "caleb.stone@contoso.com", permission: "Full Access", granted: "2024-06-27" },
    { id: "mp_5", delegate: "Julia Sanz", delegateUpn: "julia.sanz@contoso.com", permission: "Full Access", granted: "2025-01-15" },
    { id: "mp_6", delegate: "Hana Kim", delegateUpn: "hana.kim@contoso.com", permission: "Send on Behalf", granted: "2025-10-22" },
  ],
};

export function getMailboxPermissions(mailboxId: string): MailboxPermissionFeed {
  return {
    permissions: mailboxPermissions[mailboxId] ?? [],
    coverage: ["Full Access", "Send As", "Send on Behalf"].map((permission) => ({
      permission: permission as MailboxPermission["permission"],
      status: "collected" as const,
      source: "Sample data",
    })),
  };
}

const sitePermissions: Record<string, SitePermission[]> = {
  site_1: [
    { id: "sp_1", principal: "Avery Quinn", principalUpn: "avery.quinn@contoso.com", type: "User", role: "Full Control", source: "Owners" },
    { id: "sp_2", principal: "Ethan Park", principalUpn: "ethan.park@contoso.com", type: "User", role: "Edit", source: "Members" },
    { id: "sp_3", principal: "Sales — All Staff", principalUpn: "grp_1", type: "Group", role: "Edit", source: "Members" },
    { id: "sp_4", principal: "Bianca Lopez", principalUpn: "bianca.lopez@contoso.com", type: "User", role: "Read", source: "Visitors" },
  ],
  site_2: [
    { id: "sp_5", principal: "Julia Sanz", principalUpn: "julia.sanz@contoso.com", type: "User", role: "Full Control", source: "Owners" },
    { id: "sp_6", principal: "All Company", principalUpn: "grp_3", type: "Group", role: "Read", source: "Visitors" },
  ],
  site_3: [
    { id: "sp_7", principal: "Julia Sanz", principalUpn: "julia.sanz@contoso.com", type: "User", role: "Full Control", source: "Owners" },
    { id: "sp_8", principal: "Project Falcon", principalUpn: "grp_5", type: "Group", role: "Edit", source: "Members" },
    { id: "sp_9", principal: "Ivan Petrov", principalUpn: "ivan.petrov@partner.com", type: "External", role: "Edit", source: "Direct" },
  ],
  site_4: [
    { id: "sp_10", principal: "Farah Noor", principalUpn: "farah.noor@contoso.com", type: "User", role: "Full Control", source: "Owners" },
  ],
  site_5: [
    { id: "sp_11", principal: "Dana White", principalUpn: "dana.white@contoso.com", type: "User", role: "Edit", source: "Members" },
    { id: "sp_12", principal: "Anyone with the link", principalUpn: "—", type: "Link", role: "Read", source: "Sharing link" },
  ],
  site_6: [
    { id: "sp_13", principal: "Bianca Lopez", principalUpn: "bianca.lopez@contoso.com", type: "User", role: "Full Control", source: "Owners" },
    { id: "sp_14", principal: "Finance", principalUpn: "grp_2", type: "Group", role: "Edit", source: "Members" },
  ],
};

export function getSitePermissions(siteId: string): SitePermission[] {
  return sitePermissions[siteId] ?? [];
}

export const sites: Site[] = [
  ["Sales Team", "/sites/sales", "Team site", "48 GB", 12044, "Internal"],
  ["Company Intranet", "/sites/intranet", "Communication site", "12 GB", 3120, "Internal"],
  ["Project Falcon", "/sites/falcon", "Team site", "7 GB", 880, "External"],
  ["HR Portal", "/sites/hr", "Communication site", "3 GB", 640, "Internal"],
  ["Customer Files", "/sites/customers", "Team site", "118 GB", 54021, "Anyone"],
  ["Finance", "/sites/finance", "Team site", "22 GB", 4500, "Internal"],
].map((s, i) => ({
  id: `site_${i + 1}`,
  name: s[0] as string,
  url: s[1] as string,
  template: s[2] as string,
  storage: s[3] as string,
  files: s[4] as number,
  externalSharing: s[5] as Site["externalSharing"],
}));

let sharePointScanSeq = 1;
const sharePointScans: SharePointScan[] = [];

function mockInventoryNodes(scope: SharePointInventoryScope): SharePointInventoryNode[] {
  const now = new Date().toISOString();
  if (scope === "onedrive") {
    return [
      { id: "od_usr_3", tenantId: "ten_1", scanId: "", siteId: "od_usr_3", kind: "site", name: "Caleb Stone", path: "/", webUrl: "/personal/caleb", sizeBytes: 734003200, fileCount: 128, hasUniquePermissions: false, externalSharing: "OneDrive", lastScannedAt: now },
      { id: "od_docs_usr_3", tenantId: "ten_1", scanId: "", parentId: "od_usr_3", siteId: "od_usr_3", driveId: "od_drive_usr_3", kind: "library", name: "Files", path: "/Files", sizeBytes: 734003200, fileCount: 128, hasUniquePermissions: false, lastScannedAt: now },
      { id: "od_shared_usr_3", tenantId: "ten_1", scanId: "", parentId: "od_docs_usr_3", siteId: "od_usr_3", driveId: "od_drive_usr_3", itemId: "od_folder_shared", kind: "folder", name: "Shared externally", path: "/Files/Shared externally", sizeBytes: 52428800, fileCount: 9, hasUniquePermissions: true, lastScannedAt: now },
    ];
  }
  const requestedSite = scope === "file_permissions" ? "site_1" : "";
  return sites.flatMap((site, index) => {
    if (requestedSite && site.id !== requestedSite) return [];
    const bytes = (index + 1) * 512 * 1024 * 1024;
    const libraryId = `${site.id}_documents`;
    const folderId = `${site.id}_restricted`;
    const base: SharePointInventoryNode[] = [
      { id: site.id, tenantId: "ten_1", scanId: "", siteId: site.id, kind: "site", name: site.name, path: "/", webUrl: site.url, sizeBytes: bytes, fileCount: site.files, hasUniquePermissions: false, externalSharing: site.externalSharing, lastScannedAt: now },
      { id: libraryId, tenantId: "ten_1", scanId: "", parentId: site.id, siteId: site.id, driveId: `drive_${site.id}`, kind: "library", name: "Documents", path: "/Documents", sizeBytes: bytes, fileCount: site.files, hasUniquePermissions: false, lastScannedAt: now },
      { id: folderId, tenantId: "ten_1", scanId: "", parentId: libraryId, siteId: site.id, driveId: `drive_${site.id}`, itemId: `item_${site.id}_restricted`, kind: "folder", name: "Restricted", path: "/Documents/Restricted", sizeBytes: Math.floor(bytes / 4), fileCount: Math.floor(site.files / 4), hasUniquePermissions: index % 2 === 0, lastScannedAt: now },
    ];
    if (scope === "file_permissions") {
      base.push({ id: `${site.id}_budget`, tenantId: "ten_1", scanId: "", parentId: folderId, siteId: site.id, driveId: `drive_${site.id}`, itemId: `file_${site.id}_budget`, kind: "file", name: "Budget.xlsx", path: "/Documents/Restricted/Budget.xlsx", sizeBytes: 262144, fileCount: 1, hasUniquePermissions: true, lastScannedAt: now });
    }
    return base;
  });
}

const sharePointInventories = new Map<SharePointInventoryScope, SharePointInventory>();

export function startSharePointScan(scope: SharePointInventoryScope, siteId?: string, nodeId?: string): SharePointScan {
  const id = `spscan_mock_${sharePointScanSeq++}`;
  const nodes = mockInventoryNodes(scope).filter((node) => !siteId || node.siteId === siteId);
  const now = new Date().toISOString();
  const scan: SharePointScan = {
    id, tenantId: "ten_1", scope, siteId, nodeId, status: "completed",
    trigger: scope === "file_permissions" ? "on_demand" : "manual",
    startedBy: "Jordan Meyer", startedAt: now, completedAt: now, coverage: "complete",
    siteCount: nodes.filter((n) => n.kind === "site").length,
    libraryCount: nodes.filter((n) => n.kind === "library").length,
    folderCount: nodes.filter((n) => n.kind === "folder").length,
    fileCount: scope === "file_permissions" ? nodes.filter((n) => n.kind === "file").length : nodes.filter((n) => n.kind === "site").reduce((sum, n) => sum + n.fileCount, 0),
    totalBytes: nodes.filter((n) => n.kind === (scope === "file_permissions" ? "file" : "site")).reduce((sum, n) => sum + n.sizeBytes, 0),
    uniquePermissionCount: nodes.filter((n) => n.hasUniquePermissions).length,
    warnings: [],
  };
  nodes.forEach((node) => { node.scanId = id; });
  sharePointScans.unshift(scan);
  sharePointInventories.set(scope, { scan, nodes });
  return scan;
}

export function getSharePointInventory(scope: SharePointInventoryScope): SharePointInventory {
  return sharePointInventories.get(scope) ?? (() => {
    startSharePointScan(scope);
    return sharePointInventories.get(scope)!;
  })();
}

export function getSharePointScans(): SharePointScan[] {
  if (sharePointScans.length === 0) {
    startSharePointScan("sites");
    startSharePointScan("onedrive");
  }
  return [...sharePointScans];
}

export function getSharePointScopePermissions(target: SharePointPermissionRequest["target"]): SharePointScopePermission[] {
  const sourceTarget = { siteId: target.siteId, kind: "site" as const, path: "/" };
  return (sitePermissions[target.siteId] ?? []).map((permission) => ({
    id: permission.id,
    principalId: permission.principalUpn,
    principal: permission.principal,
    principalUpn: permission.principalUpn,
    type: permission.type === "Group" ? "Security Group" : permission.type === "External" ? "Guest" : permission.type as SharePointScopePermission["type"],
    role: permission.role,
    source: target.kind === "site" || permission.source === "Direct" ? "Direct" : "Inherited from site",
    inherited: target.kind !== "site" && permission.source !== "Direct",
    expandable: permission.type === "Group",
    sourceTarget: target.kind !== "site" && permission.source !== "Direct" ? sourceTarget : undefined,
  }));
}

export function previewSharePointPermission(body: SharePointPermissionRequest): SharePointPermissionPreview {
  const before = getSharePointScopePermissions(body.target);
  const matched = before.find((permission) => permission.principalId === body.principalId);
  const guide = body.operation === "revoke" && matched?.inherited && !body.breakInheritance;
  return {
    target: body.target,
    effectiveTarget: guide ? matched?.sourceTarget : body.target,
    principal: matched?.principal ?? body.principalUpn ?? body.principalId,
    operation: body.operation,
    role: body.role || matched?.role || "",
    before,
    warnings: guide
      ? ["Access is inherited. RTM will change the source assignment instead of silently breaking inheritance here."]
      : body.breakInheritance
        ? ["This breaks inheritance locally and copies the current assignments before applying the change."]
        : [],
    blocked: [],
    breaksInheritance: !!body.breakInheritance,
    risk: body.breakInheritance || body.operation === "restore_inheritance" ? "High" : "Medium",
    approvalToken: `sp_approval_${Date.now()}`,
  };
}

export function executeSharePointPermission(_body: SharePointPermissionRequest): SharePointPermissionResult {
  return { status: "Completed", changeId: `chg_sp_mock_${Date.now()}` };
}

// ThreatLocker devices for the example tenant (mixed protection states so the
// What-If skips/warnings are exercised).
export const devices: Device[] = [
  { id: "dev_1", hostname: "WS-AVERY", group: "Workstations", os: "windows", agentVersion: "10.9.1", mode: "secured", modeExpires: "", tamperProtection: true, lastCheckIn: "5m ago", online: true },
  { id: "dev_2", hostname: "WS-BIANCA", group: "Workstations", os: "windows", agentVersion: "10.9.1", mode: "secured", modeExpires: "", tamperProtection: true, lastCheckIn: "12m ago", online: true },
  { id: "dev_3", hostname: "MAC-CALEB", group: "Workstations", os: "mac", agentVersion: "10.8.4", mode: "monitor_only", modeExpires: "2026-07-04T18:00:00Z", tamperProtection: true, lastCheckIn: "3m ago", online: true },
  { id: "dev_4", hostname: "SRV-FILES", group: "Servers", os: "windows", agentVersion: "10.9.1", mode: "secured", modeExpires: "", tamperProtection: true, lastCheckIn: "1m ago", online: true },
  { id: "dev_5", hostname: "SRV-LEGACY", group: "Servers", os: "windows", agentVersion: "10.6.2", mode: "maintenance", modeExpires: "2026-07-04T16:30:00Z", tamperProtection: false, lastCheckIn: "2d ago", online: false },
  { id: "dev_6", hostname: "WS-KIOSK", group: "Kiosks", os: "windows", agentVersion: "10.9.1", mode: "lockdown", modeExpires: "", tamperProtection: true, lastCheckIn: "40m ago", online: true },
];

export const deviceGroups: DeviceGroup[] = [
  { id: "grp_1", name: "Workstations", deviceCount: 3 },
  { id: "grp_2", name: "Servers", deviceCount: 2 },
  { id: "grp_3", name: "Kiosks", deviceCount: 1 },
];

export const approvalRequests: ApprovalRequest[] = [
  {
    id: "req_1", deviceId: "dev_1", deviceName: "WS-AVERY", requester: "avery.quinn@contoso.com",
    application: "putty.exe", path: "C:\\Tools\\putty.exe",
    hash: "7d865e959b2466918c9863afca942d0f", requestType: "execution",
    status: "pending", requestedAt: "2026-07-04 09:12",
  },
  {
    id: "req_2", deviceId: "dev_3", deviceName: "MAC-CALEB", requester: "caleb.stone@contoso.com",
    application: "Homebrew", path: "/opt/homebrew/bin/brew",
    hash: "f3a1c2d4e5b6978877665544332211aa", requestType: "elevation",
    status: "pending", requestedAt: "2026-07-04 08:47",
  },
  {
    id: "req_3", deviceId: "dev_2", deviceName: "WS-BIANCA", requester: "bianca.lopez@contoso.com",
    application: "USB Mass Storage", path: "E:\\", hash: "—", requestType: "storage",
    status: "denied", requestedAt: "2026-07-03 15:20",
  },
];

export const tlApplications: TLApplication[] = [
  {
    id: "app_parent_office", name: "Microsoft Office", description: "Parent-owned Office application",
    organizationId: "org_parent", organization: "Rarity Global", source: "parent",
    osType: 1, os: "Windows", status: "Enabled", builtIn: false, hidden: false,
    policyCount: 1, fileCount: 2, updatedAt: "2026-07-07T12:10:00Z",
  },
  {
    id: "app_office_1", name: "Microsoft Office", description: "Tenant Office app",
    organizationId: "org_mock", organization: "Contoso Ltd", source: "tenant",
    osType: 1, os: "Windows", status: "Enabled", builtIn: false, hidden: false,
    policyCount: 1, fileCount: 2, updatedAt: "2026-07-07T12:05:00Z",
  },
  {
    id: "app_office_2", name: "Microsoft Office Click-to-Run", description: "Duplicate tenant Office app",
    organizationId: "org_mock", organization: "Contoso Ltd", source: "tenant",
    osType: 1, os: "Windows", status: "Enabled", builtIn: false, hidden: false,
    policyCount: 1, fileCount: 1, updatedAt: "2026-07-06T18:35:00Z",
  },
  {
    id: "app_parent_dell", name: "Dell Display Manager", description: "Parent-owned Dell display app",
    organizationId: "org_parent", organization: "Rarity Global", source: "parent",
    osType: 1, os: "Windows", status: "Enabled", builtIn: false, hidden: false,
    policyCount: 1, fileCount: 1, updatedAt: "2026-07-05T20:45:00Z",
  },
  {
    id: "app_dell_1", name: "Dell Display Manager", description: "Tenant Dell display app",
    organizationId: "org_mock", organization: "Contoso Ltd", source: "tenant",
    osType: 1, os: "Windows", status: "Enabled", builtIn: false, hidden: false,
    policyCount: 1, fileCount: 1, updatedAt: "2026-07-05T20:40:00Z",
  },
  {
    id: "app_dell_2", name: "Dell Peripheral Manager", description: "Duplicate Dell helper app",
    organizationId: "org_mock", organization: "Contoso Ltd", source: "tenant",
    osType: 1, os: "Windows", status: "Enabled", builtIn: false, hidden: false,
    policyCount: 1, fileCount: 1, updatedAt: "2026-07-05T20:32:00Z",
  },
  {
    id: "app_putty", name: "PuTTY", description: "Temporary request-created application",
    organizationId: "org_mock", organization: "Contoso Ltd", source: "tenant",
    osType: 1, os: "Windows", status: "Enabled", builtIn: false, hidden: false,
    policyCount: 1, fileCount: 1, updatedAt: "2026-07-04T09:14:00Z",
  },
];

const tlApplicationFiles: Record<string, TLApplicationFile[]> = {
  app_parent_office: [
    { id: "af_parent_office_1", applicationFileId: 101, applicationId: "app_parent_office", name: "WINWORD.EXE", fullPath: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", processPath: "", cert: "Microsoft Corporation", hash: "", notes: "", installedBy: "", osType: 1, keyFile: false, isHashOnly: false },
    { id: "af_parent_office_2", applicationFileId: 102, applicationId: "app_parent_office", name: "EXCEL.EXE", fullPath: "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", processPath: "", cert: "Microsoft Corporation", hash: "", notes: "", installedBy: "", osType: 1, keyFile: false, isHashOnly: false },
  ],
  app_office_1: [
    { id: "af_office_1", applicationFileId: 201, applicationId: "app_office_1", name: "WINWORD.EXE", fullPath: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", processPath: "", cert: "Microsoft Corporation", hash: "", notes: "", installedBy: "", osType: 1, keyFile: false, isHashOnly: false },
    { id: "af_office_2", applicationFileId: 202, applicationId: "app_office_1", name: "POWERPNT.EXE", fullPath: "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE", processPath: "", cert: "Microsoft Corporation", hash: "", notes: "", installedBy: "", osType: 1, keyFile: false, isHashOnly: false },
  ],
  app_office_2: [
    { id: "af_office_ctr", applicationFileId: 203, applicationId: "app_office_2", name: "OfficeClickToRun.exe", fullPath: "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe", processPath: "", cert: "Microsoft Corporation", hash: "", notes: "", installedBy: "", osType: 1, keyFile: false, isHashOnly: false },
  ],
  app_parent_dell: [
    { id: "af_parent_dell", applicationFileId: 301, applicationId: "app_parent_dell", name: "ddm.exe", fullPath: "C:\\Program Files\\Dell\\Dell Display Manager\\ddm.exe", processPath: "", cert: "Dell Inc.", hash: "", notes: "", installedBy: "", osType: 1, keyFile: false, isHashOnly: false },
  ],
  app_dell_1: [
    { id: "af_dell_1", applicationFileId: 302, applicationId: "app_dell_1", name: "ddm.exe", fullPath: "C:\\Program Files\\Dell\\Dell Display Manager\\ddm.exe", processPath: "", cert: "Dell Inc.", hash: "", notes: "", installedBy: "", osType: 1, keyFile: false, isHashOnly: false },
  ],
  app_dell_2: [
    { id: "af_dell_2", applicationFileId: 303, applicationId: "app_dell_2", name: "ddmhelper.exe", fullPath: "C:\\Program Files\\Dell\\Dell Peripheral Manager\\ddmhelper.exe", processPath: "", cert: "Dell Inc.", hash: "", notes: "", installedBy: "", osType: 1, keyFile: false, isHashOnly: false },
  ],
  app_putty: [
    { id: "af_putty", applicationFileId: 401, applicationId: "app_putty", name: "putty.exe", fullPath: "C:\\Tools\\putty.exe", processPath: "", cert: "", hash: "7d865e959b2466918c9863afca942d0f", notes: "Request-created", installedBy: "", osType: 1, keyFile: false, isHashOnly: true },
  ],
};

export const tlPolicies: TLPolicy[] = [
  {
    id: "pol_1", name: "Permit Microsoft Office", action: "permit", policyActionId: 1,
    appliesTo: "Entire Organization", status: "Enabled", applicationCount: 8, userCount: 0, allUsers: true,
    lastMatchedAt: "2026-07-08T02:53:52Z", monitorMode: 0,
  },
  {
    id: "pol_2", name: "Deny unsigned installers", action: "deny", policyActionId: 3,
    appliesTo: "Entire Organization", status: "Enabled", applicationCount: 3, userCount: 0, allUsers: true,
    lastMatchedAt: "2026-07-07T15:10:03Z", monitorMode: 0,
  },
  {
    id: "pol_3", name: "Ringfence PowerShell", action: "ringfence", policyActionId: 1,
    appliesTo: "Workstations", status: "Enabled", applicationCount: 1, userCount: 0,
    lastMatchedAt: "2026-07-07T23:27:07Z", monitorMode: 0,
  },
  {
    id: "pol_4", name: "Permit putty.exe (temp)", action: "permit", policyActionId: 1,
    appliesTo: "WS-AVERY", status: "Disabled", applicationCount: 1, userCount: 1,
    lastMatchedAt: "", monitorMode: 0,
  },
  {
    id: "pol_dell_parent", name: "Dell Display Manager", action: "permit", policyActionId: 2,
    appliesTo: "Global", status: "Enabled", applicationCount: 1, userCount: 0, allUsers: true,
    lastMatchedAt: "2026-07-05T20:50:00Z", monitorMode: 0,
  },
  {
    id: "pol_dell_1", name: "Dell Display Manager", action: "permit", policyActionId: 2,
    appliesTo: "WS-AVERY", status: "Enabled", applicationCount: 1, userCount: 1,
    lastMatchedAt: "2026-07-05T20:42:00Z", monitorMode: 0,
  },
  {
    id: "pol_dell_2", name: "Dell Peripheral Manager", action: "permit", policyActionId: 2,
    appliesTo: "Workstations", status: "Enabled", applicationCount: 1, userCount: 8,
    lastMatchedAt: "2026-07-05T20:31:00Z", monitorMode: 0,
  },
];

const tlPolicyApplicationIds: Record<string, string[]> = {
  pol_1: ["app_parent_office"],
  pol_2: ["app_office_2"],
  pol_3: ["app_office_1"],
  pol_4: ["app_putty"],
  pol_dell_parent: ["app_parent_dell"],
  pol_dell_1: ["app_dell_1"],
  pol_dell_2: ["app_dell_2"],
};

const policyTemplates: TLPolicyTemplate[] = [];

export function getTLApplications(search = ""): TLApplication[] {
  const q = search.trim().toLowerCase();
  const rows = !q
    ? tlApplications
    : tlApplications.filter((app) =>
        [app.name, app.description, app.organization, app.source].some((v) =>
          v.toLowerCase().includes(q),
        ),
      );
  return rows.map((app) => ({ ...app }));
}

export function getTLApplication(appId: string): TLApplicationDetail {
  const app = tlApplications.find((x) => x.id === appId);
  if (!app) throw notFound("Application");
  return { ...app, files: (tlApplicationFiles[appId] ?? []).map((file) => ({ ...file })) };
}

export function updateTLApplication(appId: string, patch: TLApplicationPatch): TLApplicationDetail {
  const app = tlApplications.find((x) => x.id === appId);
  if (!app) throw notFound("Application");
  if (patch.name !== undefined) app.name = patch.name;
  if (patch.description !== undefined) app.description = patch.description;
  app.updatedAt = "just now";
  return getTLApplication(appId);
}

export function getTLPolicy(policyId: string): TLPolicyDetail {
  const p = tlPolicies.find((x) => x.id === policyId);
  if (!p) throw notFound("Policy");
  const applicationIds = tlPolicyApplicationIds[policyId] ?? [`app_${policyId}`];
  return {
    ...p,
    description: `${p.name} policy managed by RTM.`,
    comments: "",
    policyActionId: p.action === "deny" ? 1 : 2,
    isEnabled: p.status === "Enabled",
    monitorMode: 0,
    orderBy: 100,
    neverExpires: true,
    endDate: "",
    logAction: true,
    notifyOnMatch: false,
    notifyOnRequest: false,
    killRunningProcesses: false,
    applicationSelection: 1,
    applicationIds,
    applications: applicationIds.map((id) => {
      const app = tlApplications.find((x) => x.id === id);
      const file = tlApplicationFiles[id]?.[0];
      return { id, name: app?.name ?? id, path: file?.fullPath ?? "" };
    }),
    organizationId: "org_mock",
  };
}

export function updateTLPolicy(policyId: string, patch: TLPolicyPatch): TLPolicyDetail {
  const p = tlPolicies.find((x) => x.id === policyId);
  if (!p) throw notFound("Policy");
  if (patch.name !== undefined) p.name = patch.name;
  if (patch.isEnabled !== undefined) p.status = patch.isEnabled ? "Enabled" : "Disabled";
  return { ...getTLPolicy(policyId), ...patch, id: policyId, status: p.status, isEnabled: p.status === "Enabled" };
}

export function promoteTLPolicyGlobal(policyId: string): TLPolicyConsolidateResult {
  const p = tlPolicies.find((x) => x.id === policyId);
  if (!p) throw notFound("Policy");
  const family = tlPolicies.filter(
    (x) => x.id !== policyId && x.name.trim().toLowerCase() === p.name.trim().toLowerCase() && x.action === p.action,
  );
  p.appliesTo = "Global";
  p.status = "Enabled";
  for (const duplicate of family) duplicate.status = "Disabled";
  return {
    policyId,
    name: p.name,
    status: "Completed",
    mergedPolicyIds: family.map((x) => x.id),
    disabledPolicyIds: family.map((x) => x.id),
    failed: [],
  };
}

export function promoteTLPolicy(body: { tenantId: string; policyId: string; name?: string; description?: string }): TLPolicyTemplate {
  const policy = getTLPolicy(body.policyId);
  if (body.name) policy.name = body.name;
  if (body.description) policy.description = body.description;
  const tpl = {
    id: `tl_tpl_${policyTemplates.length + 1}`,
    name: policy.name,
    description: policy.description,
    source: `promoted:${body.tenantId}:${body.policyId}`,
    policy,
    updatedAt: "just now",
  };
  policyTemplates.push(tpl);
  return tpl;
}

export function mergeTLPolicies(body: { tenantId: string; policyIds: string[]; name?: string; description?: string }): TLPolicyTemplate {
  const policy = getTLPolicy(body.policyIds[0]);
  policy.name = body.name || `Merged ${body.policyIds.length} policies`;
  policy.description = body.description || "Merged policy template";
  policy.applicationIds = Array.from(new Set(body.policyIds.flatMap((id) => getTLPolicy(id).applicationIds)));
  const tpl = {
    id: `tl_tpl_${policyTemplates.length + 1}`,
    name: policy.name,
    description: policy.description,
    source: `merged:${body.tenantId}`,
    policy,
    updatedAt: "just now",
  };
  policyTemplates.push(tpl);
  return tpl;
}

export function deployTLPolicyTemplate(
  templateId: string,
  _body: { tenantIds?: string[]; all?: boolean },
): TLPolicyDeployResult {
  return { templateId, status: "Completed", succeeded: ["ten_1"], failed: [] };
}

export function getTLAppCleanupCandidates(): TLAppCleanupCandidate[] {
  const families = [
    {
      id: "1:dell-display-manager",
      name: "Dell Display Manager",
      score: 93,
      appIds: ["app_parent_dell", "app_dell_1", "app_dell_2"],
      retained: "app_parent_dell",
      reasons: [
        "3 application records span 2 organizations.",
        "A parent-owned canonical application is ready.",
        "The same application name appears in multiple organizations.",
      ],
    },
    {
      id: "1:microsoft-office",
      name: "Microsoft Office",
      score: 88,
      appIds: ["app_parent_office", "app_office_1", "app_office_2"],
      retained: "app_parent_office",
      reasons: [
        "3 application records span 2 organizations.",
        "A parent-owned canonical application is ready.",
        "Names match after conservative family normalization; deep review is required.",
      ],
    },
  ];
  return families.map((family) => {
    const applications = family.appIds
      .map((id) => tlApplications.find((app) => app.id === id))
      .filter((app): app is TLApplication => !!app);
    return {
      id: family.id,
      name: family.name,
      osType: 1,
      os: "Windows",
      score: family.score,
      confidence: "high" as const,
      parentReady: true,
      recommendedRetainedAppId: family.retained,
      organizationCount: new Set(applications.map((app) => app.organizationId)).size,
      totalFileRules: applications.reduce((sum, app) => sum + app.fileCount, 0),
      totalPolicies: applications.reduce((sum, app) => sum + app.policyCount, 0),
      applications,
      reasons: family.reasons,
    };
  }).filter((candidate) => candidate.applications.length >= 2);
}

export function previewTLAppCleanup(body: TLAppCleanupRequest): TLAppCleanupPreview {
  const appIds = Array.from(new Set(body.appIds.map((id) => id.trim()).filter(Boolean)));
  const selected = appIds
    .map((id) => tlApplications.find((app) => app.id === id))
    .filter((app): app is TLApplication => !!app);
  const blocked: string[] = [];
  for (const id of appIds) {
    if (!selected.some((app) => app.id === id)) blocked.push(`Application ${id} was not found.`);
  }
  if (selected.length < 2) blocked.push("At least two selected applications must still exist.");

  const baseName = body.name?.trim() || selected[0]?.name || "";
  let retainedApp =
    (body.retainedAppId && tlApplications.find((app) => app.id === body.retainedAppId)) ||
    tlApplications.find((app) => app.source === "parent" && normalizeTL(app.name) === normalizeTL(baseName));
  const warnings: string[] = [];
  if (!retainedApp) {
    retainedApp = {
      id: "",
      name: baseName,
      description: "",
      organizationId: "org_parent",
      organization: "Rarity Global",
      source: "parent",
      osType: 1,
      os: "Windows",
      status: "Enabled",
      builtIn: false,
      hidden: false,
      policyCount: 0,
      fileCount: 0,
      updatedAt: "",
    };
    warnings.push("A child policy must be promoted to Global before ThreatLocker will create the parent-owned merge target.");
  }

  const fileRuleCount = selected
    .filter((app) => app.id !== retainedApp.id)
    .reduce((count, app) => count + (tlApplicationFiles[app.id]?.length ?? 0), 0);
  const candidateAppIds = Array.from(new Set([retainedApp.id, ...selected.map((app) => app.id)].filter(Boolean)));
  const policyIds = Array.from(
    new Set(
      Object.entries(tlPolicyApplicationIds)
        .filter(([, apps]) => apps.some((id) => candidateAppIds.includes(id)))
        .map(([policyId]) => policyId),
    ),
  );
  let retainedPolicy =
    (body.retainedPolicyId && tlPolicies.find((p) => p.id === body.retainedPolicyId)) ||
    tlPolicies.find((p) => tlPolicyApplicationIds[p.id]?.includes(retainedApp.id)) ||
    tlPolicies.find((p) => policyIds.includes(p.id));
  if (!retainedPolicy) {
    retainedPolicy = {
      id: "",
      name: baseName,
      action: "permit",
      policyActionId: 2,
      appliesTo: "Global",
      status: "Enabled",
      applicationCount: 1,
      userCount: 0,
      allUsers: true,
      lastMatchedAt: "",
      monitorMode: 0,
    };
    warnings.push("A new global permit policy will be created for the retained application.");
  }

  const preservedPolicies = policyIds
    .map((id) => tlPolicies.find((p) => p.id === id))
    .filter((p): p is TLPolicy => !!p)
    .map((p) => ({ ...p }));
  let parentPromotion: TLAppParentPromotion | undefined;
  if (!retainedApp.id) {
    const child = selected.find((app) => app.source !== "parent");
    const policy = preservedPolicies.find((item) => child && tlPolicyApplicationIds[item.id]?.includes(child.id));
    if (child && policy) {
      parentPromotion = {
        approvalToken: "mock-parent-promotion",
        applicationId: child.id,
        applicationName: child.name,
        applicationOrganizationId: child.organizationId,
        sourceOrganizationId: child.organizationId,
        policyId: policy.id,
        policyName: policy.name,
        destinationGroupId: "cg_global",
        destinationGroupName: "Global",
        parentOrganizationId: "org_parent",
        osType: child.osType,
      };
      blocked.push("A parent-owned application is required. Promote the proposed child policy to Global, then refresh this preview.");
    }
  }
  return {
    fingerprint: `cleanup:${appIds.slice().sort().join(",")}:${retainedApp.id || normalizeTL(baseName)}`,
    tenantId: "ten_1",
    retainedApp: { ...retainedApp },
    retainedPolicy: { ...retainedPolicy },
    sourceApps: selected.map((app) => ({ ...app })),
    fileRuleCount,
    policyCount: policyIds.length,
    deleteAppIds: selected.filter((app) => app.id !== retainedApp.id).map((app) => app.id),
    deletePolicyIds: policyIds.filter((id) => id !== retainedPolicy.id),
    deletePolicies: policyIds
      .filter((id) => id !== retainedPolicy.id)
      .map((id) => tlPolicies.find((p) => p.id === id))
      .filter((p): p is TLPolicy => !!p)
      .map((p) => ({ ...p })),
    preservedPolicies,
    parentPromotion,
    globalDestination: { id: "cg_global", name: "Global", organizationId: "org_parent" },
    warnings,
    blocked,
  };
}

export function promoteTLAppCleanupParent(body: TLAppParentPromotion): TLAppCleanupResult {
  const retainedAppId = `app_parent_promoted_${tlApplicationSeq++}`;
  const source = tlApplications.find((app) => app.id === body.applicationId);
  tlApplications.push({
    ...(source ?? {
      name: body.applicationName,
      description: "",
      organization: "Rarity Global",
      source: "parent" as const,
      osType: body.osType,
      os: "Windows",
      status: "Enabled",
      builtIn: false,
      hidden: false,
      policyCount: 1,
      fileCount: 0,
      updatedAt: "just now",
    }),
    id: retainedAppId,
    organizationId: body.parentOrganizationId,
    organization: "Rarity Global",
    source: "parent",
  });
  tlApplicationFiles[retainedAppId] = [];
  tlPolicyApplicationIds[body.policyId] = [retainedAppId];
  const policy = tlPolicies.find((item) => item.id === body.policyId);
  if (policy) policy.appliesTo = "Global";
  return {
    status: "Completed",
    stage: "parent_promotion",
    operationId: `tlop_mock_${tlCleanupOperationSeq++}`,
    verificationStatus: "verification_pending",
    verification: { passed: false, checkedAt: "", checks: [] },
    retainedAppId: "",
    retainedPolicyId: body.policyId,
    copiedFileRules: 0,
    expectedFileRules: 0,
    deletedAppIds: [],
    deletedPolicyIds: [],
    preservedPolicies: policy ? [{ ...policy }] : [],
    promotedPolicyIds: [body.policyId],
    parentPromotion: { ...body, approvalToken: undefined },
    retainedAppName: body.applicationName,
    retainedAppOsType: body.osType,
    failed: [],
  };
}

let tlApplicationSeq = 1;
let tlFileSeq = 900;
let tlPolicySeq = 1;
let tlCleanupOperationSeq = 1;
const tlCleanupOperations: TLAppCleanupOperation[] = [];

export function executeTLAppCleanup(body: TLAppCleanupRequest): TLAppCleanupResult {
  const preview = previewTLAppCleanup(body);
  if (preview.blocked.length) throw new Error(preview.blocked.join(" "));
  let retainedAppId = preview.retainedApp.id;
  if (!retainedAppId) {
    retainedAppId = `app_parent_new_${tlApplicationSeq++}`;
    tlApplications.push({
      ...preview.retainedApp,
      id: retainedAppId,
      organizationId: "org_parent",
      organization: "Rarity Global",
      source: "parent",
      policyCount: 0,
      fileCount: 0,
      updatedAt: "just now",
    });
    tlApplicationFiles[retainedAppId] = [];
  }

  let copiedFileRules = 0;
  for (const app of preview.sourceApps) {
    if (app.id === retainedAppId) continue;
    for (const file of tlApplicationFiles[app.id] ?? []) {
      copiedFileRules += 1;
      const applicationFileId = tlFileSeq++;
      tlApplicationFiles[retainedAppId].push({
        ...file,
        id: `af_${applicationFileId}`,
        applicationFileId,
        applicationId: retainedAppId,
      });
    }
  }

  let retainedPolicyId = preview.retainedPolicy.id;
  if (!retainedPolicyId) {
    retainedPolicyId = `pol_app_cleanup_${tlPolicySeq++}`;
    tlPolicies.push({
      id: retainedPolicyId,
      name: body.name?.trim() || preview.retainedApp.name || "Global application permit",
      action: "permit",
      policyActionId: 2,
      appliesTo: "Global",
      status: "Enabled",
      applicationCount: 1,
      userCount: 0,
      allUsers: true,
      lastMatchedAt: "",
      monitorMode: 0,
    });
  } else {
    const policy = tlPolicies.find((p) => p.id === retainedPolicyId);
    if (policy) {
      policy.appliesTo = "Global";
      policy.status = "Enabled";
      policy.applicationCount = 1;
      policy.allUsers = true;
    }
  }
  tlPolicyApplicationIds[retainedPolicyId] = [retainedAppId];

  for (const policyId of preview.deletePolicyIds) {
    const idx = tlPolicies.findIndex((p) => p.id === policyId);
    if (idx >= 0) tlPolicies.splice(idx, 1);
    delete tlPolicyApplicationIds[policyId];
  }
  for (const appId of preview.deleteAppIds) {
    const idx = tlApplications.findIndex((app) => app.id === appId);
    if (idx >= 0) tlApplications.splice(idx, 1);
    delete tlApplicationFiles[appId];
  }
  const retained = tlApplications.find((app) => app.id === retainedAppId);
  if (retained) {
    retained.fileCount = tlApplicationFiles[retainedAppId]?.length ?? retained.fileCount;
    retained.policyCount = 1;
    retained.updatedAt = "just now";
  }

  const operationId = `tlop_mock_${tlCleanupOperationSeq++}`;
  const result: TLAppCleanupResult = {
    status: "Completed",
    stage: "policy_review",
    operationId,
    verificationStatus: "verification_pending",
    verification: { passed: false, checkedAt: "", checks: [] },
    retainedAppId,
    retainedPolicyId,
    copiedFileRules,
    expectedFileRules: tlApplicationFiles[retainedAppId]?.length ?? copiedFileRules,
    deletedAppIds: preview.deleteAppIds,
    deletedPolicyIds: preview.deletePolicyIds,
    preservedPolicies: preview.preservedPolicies,
    promotedPolicyIds: preview.preservedPolicies.map((policy) => policy.id),
    retainedAppName: preview.retainedApp.name,
    retainedAppOsType: preview.retainedApp.osType,
    failed: [],
  };
  const now = new Date().toISOString();
  tlCleanupOperations.unshift({
    id: operationId,
    tenantId: "ten_1",
    status: "verification_pending",
    requestedBy: "Demo Admin",
    result,
    createdAt: now,
    updatedAt: now,
  });
  return result;
}

export function getTLAppCleanupOperations(): TLAppCleanupOperation[] {
  return tlCleanupOperations.map((operation) => ({ ...operation, result: { ...operation.result } }));
}

export function verifyTLAppCleanupOperation(operationId: string): TLAppCleanupOperation {
  const operation = tlCleanupOperations.find((item) => item.id === operationId);
  if (!operation) throw new Error("Cleanup operation was not found.");
  const checks = [
    { key: "retained_app", label: "Parent application exists", passed: true, details: "Retained parent application is present." },
    { key: "source_apps_removed", label: "Duplicate applications removed", passed: true, details: "All planned duplicate applications are absent." },
    { key: "file_rules", label: "File rules retained", passed: true, details: `${operation.result.expectedFileRules} file rules are present.` },
    { key: "global_policy", label: "Global policy enabled", passed: true, details: "Retained policy is enabled, globally scoped, and bound to the parent application." },
    { key: "duplicate_policies_removed", label: "Duplicate policies removed", passed: true, details: "All planned duplicate policies are absent." },
  ];
  operation.status = "verified";
  operation.result.verificationStatus = "verified";
  operation.result.verification = { passed: true, checkedAt: new Date().toISOString(), checks };
  operation.updatedAt = new Date().toISOString();
  return { ...operation, result: { ...operation.result } };
}

export function reconcileTLAppCleanupOperation(
  operationId: string,
  resolution: "verified" | "not_applied",
): TLAppCleanupOperation {
  const operation = tlCleanupOperations.find((item) => item.id === operationId);
  if (!operation) throw new Error("Cleanup operation was not found.");
  operation.status = resolution === "verified" ? "verified" : "failed";
  operation.updatedAt = new Date().toISOString();
  return { ...operation, result: { ...operation.result } };
}

function normalizeTL(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, " ");
}

// ---- Security Operations -------------------------------------------------
// Provider and RTM-native audit detections exercise the same cross-tenant
// snapshot/detail/triage contract as the live Go API; only local workflow
// fields mutate.

const securityAt = (minutesAgo: number) =>
  new Date(Date.now() - minutesAgo * 60_000).toISOString();

type MockSecurityIncidentDetail = Omit<SecurityIncidentDetail, "remediation"> & {
  remediation?: SecurityRemediationPlan;
};

const securityIncidentDetails: MockSecurityIncidentDetail[] = [
  {
    id: "rta_sample_forwarding",
    tenantId: "ten_1",
    tenantName: "Contoso Ltd",
    title: "Suspicious inbox forwarding rule",
    description: "A mailbox forwarding or inbox-rule redirect setting changed. Verify the destination and administrator intent.",
    severity: "High",
    status: "New",
    providerStatus: "Detected",
    source: "RTM M365 Audit",
    detectionType: "direct",
    confidence: "high",
    ruleId: "suspicious_mail_forwarding",
    ruleVersion: 1,
    alertCount: 1,
    entityCount: 2,
    entities: [
      { type: "User", label: "Megan Bowen" },
      { type: "Mailbox", label: "megan.bowen@contoso.com" },
    ],
    evidence: {
      eventId: "sae_sample_forwarding",
      operation: "Set mailbox forwarding",
      actor: "admin@contoso.com",
      target: "megan.bowen@contoso.com",
      relatedResource: "Exchange Online",
      workload: "Exchange",
      resultStatus: "Succeeded",
      occurredAt: securityAt(190),
      changes: [
        { field: "Forwarding address", before: "Not set", after: "external@example.net" },
        { field: "Keep a local copy", before: "Off", after: "On" },
      ],
    },
    rtmReceivedAt: securityAt(17),
    createdAt: securityAt(190),
    updatedAt: securityAt(17),
    sample: true,
    alerts: [
      {
        id: "rta_sample_forwarding_rule",
        title: "Mailbox forwarding or redirect changed",
        severity: "High",
        status: "Detected",
        serviceSource: "RTM M365 Audit",
        detectionSource: "suspicious_mail_forwarding",
        createdAt: securityAt(190),
        updatedAt: securityAt(17),
      },
    ],
    timeline: [
      {
        id: "sae_sample_forwarding",
        timestamp: securityAt(190),
        title: "Microsoft 365 audit event matched suspicious_mail_forwarding",
        description: "Messages are being forwarded to an external address.",
        source: "RTM M365 Audit",
      },
    ],
  },
  {
    id: "sec_1002",
    tenantId: "ten_1",
    tenantName: "Contoso Ltd",
    title: "Risky sign-in followed by MFA change",
    description:
      "A high-risk sign-in was followed by registration of a new authentication method.",
    severity: "High",
    status: "In Progress",
    owner: "Jordan Meyer",
    providerStatus: "active",
    source: "Entra ID Protection",
    alertCount: 2,
    entityCount: 2,
    entities: [
      { type: "User", label: "Avery Quinn" },
      { type: "IP address", label: "198.51.100.24" },
    ],
    rtmReceivedAt: securityAt(415),
    createdAt: securityAt(420),
    updatedAt: securityAt(52),
    incidentWebUrl: "https://security.microsoft.com/incidents/sec_1002",
    sample: true,
    alerts: [
      {
        id: "alert_1003",
        title: "Unfamiliar sign-in properties",
        severity: "High",
        status: "Active",
        serviceSource: "Entra ID Protection",
        createdAt: securityAt(420),
        updatedAt: securityAt(52),
      },
      {
        id: "alert_1004",
        title: "Authentication method registered",
        severity: "Medium",
        status: "Active",
        serviceSource: "Entra ID Protection",
        createdAt: securityAt(380),
        updatedAt: securityAt(75),
      },
    ],
    timeline: [
      {
        id: "evt_1004",
        timestamp: securityAt(420),
        title: "Risky sign-in detected",
        description: "The user signed in from an unfamiliar network and device.",
        source: "Entra ID Protection",
      },
      {
        id: "evt_1005",
        timestamp: securityAt(380),
        title: "MFA method changed",
        description: "A new Microsoft Authenticator method was registered.",
        source: "Microsoft 365 Audit",
      },
    ],
  },
  {
    id: "sec_1003",
    tenantId: "ten_1",
    tenantName: "Contoso Ltd",
    title: "Conditional Access policy disabled",
    description: "A policy protecting privileged roles was disabled outside the approved window.",
    severity: "High",
    status: "New",
    providerStatus: "active",
    source: "Entra ID Protection",
    alertCount: 1,
    entityCount: 1,
    entities: [{ type: "Policy", label: "Require MFA for administrators" }],
    rtmReceivedAt: securityAt(605),
    createdAt: securityAt(610),
    updatedAt: securityAt(110),
    incidentWebUrl: "https://security.microsoft.com/incidents/sec_1003",
    sample: true,
    alerts: [
      {
        id: "alert_1005",
        title: "High-impact Conditional Access change",
        severity: "High",
        status: "Active",
        serviceSource: "Entra ID Protection",
        createdAt: securityAt(610),
        updatedAt: securityAt(110),
      },
    ],
    timeline: [
      {
        id: "evt_1006",
        timestamp: securityAt(610),
        title: "Policy disabled",
        description: "The administrator MFA policy was disabled.",
        source: "Microsoft 365 Audit",
      },
    ],
  },
  {
    id: "sec_1004",
    tenantId: "ten_1",
    tenantName: "Contoso Ltd",
    title: "Multiple failed sign-ins followed by success",
    description: "The account recorded five failed logins in the 15 minutes before a successful login.",
    severity: "High",
    status: "In Progress",
    owner: "Aisha Rivera",
    providerStatus: "Detected",
    source: "RTM M365 Audit",
    detectionType: "correlation",
    confidence: "high",
    ruleId: "failed_logins_then_success",
    ruleVersion: 1,
    alertCount: 1,
    entityCount: 2,
    entities: [
      { type: "User", label: "Dana White" },
      { type: "IP address", label: "203.0.113.42" },
    ],
    rtmReceivedAt: securityAt(245),
    createdAt: securityAt(850),
    updatedAt: securityAt(245),
    sample: true,
    alerts: [
      {
        id: "alert_1006",
        title: "Repeated failed logins followed by success",
        severity: "High",
        status: "Detected",
        serviceSource: "RTM M365 Audit",
        detectionSource: "failed_logins_then_success",
        createdAt: securityAt(850),
        updatedAt: securityAt(245),
      },
    ],
    timeline: [
      {
        id: "evt_1007",
        timestamp: securityAt(245),
        title: "Successful sign-in",
        description: "A successful sign-in followed repeated failures from the same network.",
        source: "RTM M365 Audit",
      },
    ],
  },
  {
    id: "sec_1005",
    tenantId: "ten_1",
    tenantName: "Contoso Ltd",
    title: "Defender phishing campaign",
    description: "Twelve recipients received messages sharing the same credential-phishing URL.",
    severity: "Medium",
    status: "New",
    providerStatus: "active",
    source: "Defender for Office 365",
    alertCount: 4,
    entityCount: 2,
    entities: [
      { type: "Mailbox", label: "finance@contoso.com" },
      { type: "URL", label: "login-document.example" },
    ],
    rtmReceivedAt: securityAt(1_205),
    createdAt: securityAt(1_210),
    updatedAt: securityAt(390),
    incidentWebUrl: "https://security.microsoft.com/incidents/sec_1005",
    sample: true,
    alerts: [
      {
        id: "alert_1007",
        title: "Credential phishing messages delivered",
        severity: "Medium",
        status: "Active",
        serviceSource: "Defender for Office 365",
        createdAt: securityAt(1_210),
        updatedAt: securityAt(390),
      },
    ],
    timeline: [
      {
        id: "evt_1008",
        timestamp: securityAt(390),
        title: "Campaign correlated",
        description: "Defender grouped messages with a shared malicious URL.",
        source: "Defender for Office 365",
      },
    ],
  },
  {
    id: "sec_1006",
    tenantId: "ten_1",
    tenantName: "Contoso Ltd",
    title: "New service principal with high privileges",
    description: "A newly consented application can read directory data across the tenant.",
    severity: "Low",
    status: "New",
    providerStatus: "active",
    source: "App Governance",
    alertCount: 1,
    entityCount: 1,
    entities: [{ type: "Application", label: "Legacy Importer" }],
    rtmReceivedAt: securityAt(1_635),
    createdAt: securityAt(1_640),
    updatedAt: securityAt(710),
    incidentWebUrl: "https://security.microsoft.com/incidents/sec_1006",
    sample: true,
    alerts: [
      {
        id: "alert_1008",
        title: "Application granted directory privileges",
        severity: "Low",
        status: "Active",
        serviceSource: "App Governance",
        createdAt: securityAt(1_640),
        updatedAt: securityAt(710),
      },
    ],
    timeline: [
      {
        id: "evt_1009",
        timestamp: securityAt(1_640),
        title: "Admin consent granted",
        description: "The application received tenant-wide directory read permissions.",
        source: "Microsoft 365 Audit",
      },
    ],
  },
  {
    id: "sec_1007",
    tenantId: "ten_1",
    tenantName: "Contoso Ltd",
    title: "Unexpected external SharePoint access",
    description: "An external user accessed a finance site from a new country.",
    severity: "Low",
    status: "Resolved",
    owner: "David Chen",
    providerStatus: "resolved",
    classification: "Informational, expected activity",
    determination: "Not malicious",
    source: "Defender for Cloud Apps",
    alertCount: 1,
    entityCount: 2,
    entities: [
      { type: "User", label: "Ivan Petrov" },
      { type: "Site", label: "Finance Operations" },
    ],
    rtmReceivedAt: securityAt(2_525),
    createdAt: securityAt(2_530),
    updatedAt: securityAt(1_810),
    incidentWebUrl: "https://security.microsoft.com/incidents/sec_1007",
    sample: true,
    alerts: [
      {
        id: "alert_1009",
        title: "External user accessed finance site",
        severity: "Low",
        status: "Resolved",
        serviceSource: "Defender for Cloud Apps",
        createdAt: securityAt(2_530),
        updatedAt: securityAt(1_810),
      },
    ],
    timeline: [
      {
        id: "evt_1010",
        timestamp: securityAt(1_810),
        title: "Incident resolved",
        description: "The site owner confirmed the external access was expected.",
        source: "RTM sample",
      },
    ],
  },
];

const securityStorylineDetails: SecurityStorylineDetail[] = [
  {
    id: "story_sample_takeover",
    packId: "account_takeover_bec",
    title: "Probable account takeover and mailbox persistence",
    summary: "Suspicious identity activity progressed into authentication-method and mailbox persistence changes.",
    severity: "Critical",
    riskScore: 92,
    confidence: "high",
    status: "New",
    firstSeen: securityAt(46),
    lastSeen: securityAt(8),
    updatedAt: securityAt(8),
    tenantIds: ["ten_1"],
    tenantNames: ["Contoso Ltd"],
    entities: [
      { type: "account", key: "ten_1|account|avery.quinn@contoso.com", label: "Avery Quinn", tenantId: "ten_1", primary: true },
      { type: "mailbox", key: "ten_1|mailbox|avery.quinn@contoso.com", label: "avery.quinn@contoso.com", tenantId: "ten_1" },
      { type: "ip", key: "ten_1|ip|198.51.100.24", label: "198.51.100.24", tenantId: "ten_1" },
    ],
    stages: ["Initial Access", "Credential Access", "Persistence", "Collection"],
    workloads: ["Entra", "Exchange", "SharePoint"],
    detectionIds: ["story_det_login", "story_det_mfa", "story_det_forward", "story_det_download"],
    eventIds: ["story_evt_login", "story_evt_mfa", "story_evt_forward", "story_evt_download"],
    signalCount: 4,
    affectedUsers: 1,
    affectedResources: 48,
    reasons: [
      "Four independent detection types affected the same normalized identity.",
      "Activity progressed across four attack stages over 38 minutes.",
      "Connected evidence spans three Microsoft 365 workloads.",
      "Three contributing detections have high-confidence evidence.",
    ],
    weakEvidence: ["The initial unfamiliar-network signal is contextual; validate the user's device and travel."],
    recommendedActions: [
      "Revoke active sessions through RTM What-If",
      "Inspect and remove unapproved authentication methods",
      "Review mailbox forwarding, delegates, inbox rules, and transport rules",
      "Reset the password and validate recent sign-ins",
      "Review external sharing and downloaded resources",
    ],
    sample: true,
    evidence: [
      { detectionId: "story_det_login", ruleId: "failed_logins_then_success", title: "Failed sign-ins followed by success", severity: "High", confidence: "high", stage: "Initial Access", occurredAt: securityAt(46), tenantId: "ten_1", tenantName: "Contoso Ltd", events: [{ eventId: "story_evt_login", operation: "UserLoggedIn", actor: "avery.quinn@contoso.com", clientIp: "198.51.100.24", workload: "Entra", resultStatus: "Succeeded", occurredAt: securityAt(46) }] },
      { detectionId: "story_det_mfa", ruleId: "authentication_method_change", title: "Authentication method changed", severity: "High", confidence: "high", stage: "Credential Access", occurredAt: securityAt(31), tenantId: "ten_1", tenantName: "Contoso Ltd", events: [{ eventId: "story_evt_mfa", operation: "Update authentication method", actor: "avery.quinn@contoso.com", target: "Avery Quinn", workload: "Entra", resultStatus: "Succeeded", occurredAt: securityAt(31), changes: [{ field: "Authentication method", after: "Microsoft Authenticator" }] }] },
      { detectionId: "story_det_forward", ruleId: "suspicious_mail_forwarding", title: "Mailbox forwarding changed", severity: "High", confidence: "high", stage: "Persistence", occurredAt: securityAt(19), tenantId: "ten_1", tenantName: "Contoso Ltd", events: [{ eventId: "story_evt_forward", operation: "Set-Mailbox", actor: "avery.quinn@contoso.com", target: "avery.quinn@contoso.com", workload: "Exchange", resultStatus: "Succeeded", occurredAt: securityAt(19), changes: [{ field: "Forwarding address", after: "archive@external.example" }] }] },
      { detectionId: "story_det_download", ruleId: "bulk_file_download", title: "Bulk SharePoint downloads", severity: "High", confidence: "medium", stage: "Collection", occurredAt: securityAt(8), tenantId: "ten_1", tenantName: "Contoso Ltd", events: [{ eventId: "story_evt_download", operation: "FileDownloaded", actor: "avery.quinn@contoso.com", target: "Finance", workload: "SharePoint", resultStatus: "Succeeded", occurredAt: securityAt(8) }] },
    ],
  },
  {
    id: "story_sample_msp",
    packId: "msp_admin_compromise",
    title: "Possible MSP administrator compromise across tenants",
    summary: "The same RTM administrator performed connected high-impact changes across two managed tenants.",
    severity: "High",
    riskScore: 76,
    confidence: "medium",
    status: "In Progress",
    owner: "Jordan Meyer",
    firstSeen: securityAt(95),
    lastSeen: securityAt(61),
    updatedAt: securityAt(55),
    tenantIds: ["ten_1", "ten_2"],
    tenantNames: ["Contoso Ltd", "Adventure Works"],
    entities: [{ type: "account", key: "global|account|msp-admin@rarity.io", label: "msp-admin@rarity.io", primary: true }],
    stages: ["Initial Access", "Cross-tenant Activity"],
    workloads: ["Entra"],
    detectionIds: ["story_det_admin_ip", "story_det_app", "story_det_role"],
    eventIds: ["story_evt_admin_ip", "story_evt_app", "story_evt_role"],
    signalCount: 3,
    affectedUsers: 1,
    affectedResources: 2,
    reasons: [
      "Three independent detection types affected the same normalized administrator identity.",
      "The same authenticated actor affected two managed tenants; IP address was not used as the grouping key.",
    ],
    recommendedActions: ["Protect the global storyline and assign an incident commander", "Revoke the MSP identity's active sessions and rotate its credentials", "Review the per-tenant blast radius before making changes"],
    sample: true,
    evidence: [
      { detectionId: "story_det_admin_ip", ruleId: "unusual_administrator_ip", title: "Administrator used a newly observed IP", severity: "Medium", confidence: "low", stage: "Initial Access", occurredAt: securityAt(95), tenantId: "ten_1", tenantName: "Contoso Ltd", events: [{ eventId: "story_evt_admin_ip", operation: "Update application", actor: "msp-admin@rarity.io", clientIp: "203.0.113.77", workload: "Entra", occurredAt: securityAt(95) }] },
      { detectionId: "story_det_app", ruleId: "application_registration", title: "Application registered", severity: "Medium", confidence: "high", stage: "Cross-tenant Activity", occurredAt: securityAt(72), tenantId: "ten_1", tenantName: "Contoso Ltd", events: [{ eventId: "story_evt_app", operation: "Add application", actor: "msp-admin@rarity.io", target: "Remote Admin Helper", workload: "Entra", occurredAt: securityAt(72) }] },
      { detectionId: "story_det_role", ruleId: "privileged_role_change", title: "Privileged role membership changed", severity: "High", confidence: "high", stage: "Cross-tenant Activity", occurredAt: securityAt(61), tenantId: "ten_2", tenantName: "Adventure Works", events: [{ eventId: "story_evt_role", operation: "Add member to role", actor: "msp-admin@rarity.io", target: "Global Administrator", workload: "Entra", occurredAt: securityAt(61) }] },
    ],
  },
];

export function getSecurityOperations(): SecurityOperationsSnapshot {
  const incidents = securityIncidentDetails.map(({ alerts: _alerts, timeline: _timeline, remediation: _remediation, ...item }) => ({
    ...item,
    rtmReceivedAt: item.rtmReceivedAt ?? item.updatedAt,
    entities: item.entities?.map((entity) => ({ ...entity })),
  }));
  const open = incidents.filter(
    (incident) => incident.status !== "Resolved" && incident.status !== "Dismissed",
  );
  const severities = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"];
  return {
    generatedAt: new Date().toISOString(),
    summary: {
      open: open.length,
      critical: open.filter((incident) => incident.severity === "Critical").length,
      high: open.filter((incident) => incident.severity === "High").length,
      tenantsCovered: 1,
      tenantsTotal: 1,
      liveTenants: 0,
      sampleTenants: 1,
      ingestionHealth: 100,
    },
    severity: severities.map((severity) => ({
      severity,
      count: open.filter((incident) => incident.severity === severity).length,
    })),
    connectors: [
      {
        key: "defender_xdr",
        name: "Microsoft Defender XDR",
        status: "sample",
        healthyTenants: 0,
        attentionTenants: 0,
        sampleTenants: 1,
        requiredPermission: "SecurityIncident.Read.All",
      },
      {
        key: "entra_fast_identity",
        name: "Entra fast identity",
        status: "sample",
        healthyTenants: 0,
        attentionTenants: 0,
        sampleTenants: 1,
        requiredPermission: "AuditLog.Read.All",
      },
      {
		key: "m365_audit",
        name: "Microsoft 365 Audit",
        status: "sample",
        healthyTenants: 0,
        attentionTenants: 0,
        sampleTenants: 1,
        requiredPermission: "ActivityFeed.Read",
      },
      {
        key: "entra_id_protection",
        name: "Entra ID Protection",
        status: "planned",
        healthyTenants: 0,
        attentionTenants: 0,
        sampleTenants: 0,
        requiredPermission: "IdentityRiskEvent.Read.All",
      },
    ],
    coverage: [
      {
        tenantId: "ten_1",
        tenantName: "Contoso Ltd",
        connectorKey: "entra_fast_identity",
        connectorName: "Entra fast identity",
        status: "sample",
        detail: "RTM sample Graph identity events are active; no live connection is configured.",
        requiredPermission: "AuditLog.Read.All",
        checkedAt: new Date().toISOString(),
      },
      {
		tenantId: "ten_1",
        tenantName: "Contoso Ltd",
        connectorKey: "defender_xdr",
        connectorName: "Microsoft Defender XDR",
        status: "sample",
        detail: "Sample Defender incidents — no live security connection is active for this tenant.",
        requiredPermission: "SecurityIncident.Read.All",
        checkedAt: new Date().toISOString(),
      },
      {
        tenantId: "ten_1",
        tenantName: "Contoso Ltd",
        connectorKey: "m365_audit",
        connectorName: "Microsoft 365 Audit",
        status: "sample",
        detail: "RTM sample audit events are active; no live Management Activity connection is configured.",
        requiredPermission: "ActivityFeed.Read",
        checkedAt: new Date().toISOString(),
      },
    ],
		historyImports: [
	  {
		tenantId: "ten_1",
		tenantName: "Contoso Ltd",
		jobId: "job_history_sample",
		requestedWindow: "last_7d",
		windowHours: 168,
		historicalIncidentMode: "recent_24h",
		status: "completed",
		progress: 100,
		feedsCompleted: 42,
		feedsTotal: 42,
		eventsReceived: 1842,
		eventsInserted: 1764,
		detectionsCreated: 7,
		detail: "History import complete · 1,764 events retained · 7 detections created.",
		requestedAt: new Date(Date.now() - 3_600_000).toISOString(),
		completedAt: new Date(Date.now() - 3_000_000).toISOString(),
		incidentCutoffAt: new Date(Date.now() - 25 * 3_600_000).toISOString(),
	  },
	],
    storylines: securityStorylineDetails.map(({ evidence: _evidence, ...storyline }) => ({
      ...storyline,
      tenantIds: [...storyline.tenantIds],
      tenantNames: [...storyline.tenantNames],
      entities: storyline.entities.map((entity) => ({ ...entity })),
      stages: [...storyline.stages],
      workloads: [...storyline.workloads],
      detectionIds: [...storyline.detectionIds],
      eventIds: [...storyline.eventIds],
      reasons: [...storyline.reasons],
      recommendedActions: [...storyline.recommendedActions],
    })),
    incidents,
    warnings: [],
  };
}

export function getSecurityStoryline(storylineId: string): SecurityStorylineDetail | null {
  const storyline = securityStorylineDetails.find((item) => item.id === storylineId);
  if (!storyline) return null;
  return {
    ...storyline,
    tenantIds: [...storyline.tenantIds],
    tenantNames: [...storyline.tenantNames],
    entities: storyline.entities.map((entity) => ({ ...entity })),
    stages: [...storyline.stages],
    workloads: [...storyline.workloads],
    detectionIds: [...storyline.detectionIds],
    eventIds: [...storyline.eventIds],
    reasons: [...storyline.reasons],
    weakEvidence: [...(storyline.weakEvidence ?? [])],
    recommendedActions: [...storyline.recommendedActions],
    evidence: storyline.evidence.map((item) => ({
      ...item,
      events: item.events.map((event) => ({ ...event, changes: event.changes?.map((change) => ({ ...change })) })),
    })),
  };
}

export function triageSecurityStoryline(storylineId: string, body: SecurityTriageRequest): SecurityStoryline | null {
  const storyline = securityStorylineDetails.find((item) => item.id === storylineId);
  if (!storyline) return null;
  if (body.status) storyline.status = body.status;
  if (body.assignment === "me") storyline.owner = "Jordan Meyer";
  if (body.assignment === "unassigned") delete storyline.owner;
  storyline.updatedAt = new Date().toISOString();
  const { evidence: _evidence, ...summary } = getSecurityStoryline(storylineId)!;
  return summary;
}

export function getSecurityIncident(tenantId: string, incidentId: string) {
  const incident = securityIncidentDetails.find(
    (item) => item.tenantId === tenantId && item.id === incidentId,
  );
  if (!incident) return null;
  return {
    ...incident,
    rtmReceivedAt: incident.rtmReceivedAt ?? incident.updatedAt,
    remediation: incident.remediation ?? mockSecurityRemediation(incident),
    entities: incident.entities?.map((entity) => ({ ...entity })),
    alerts: incident.alerts.map((item) => ({ ...item })),
    timeline: incident.timeline.map((item) => ({ ...item })),
  };
}

function mockSecurityRemediation(incident: MockSecurityIncidentDetail): SecurityRemediationPlan {
  const text = [incident.ruleId, incident.title, incident.description, incident.source]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (/forward|inbox rule|mailbox/.test(text)) {
    return {
      category: "Mailbox persistence or mail-flow change",
      summary: "Contain unauthorized mail access or routing without destroying the audit evidence needed to scope the incident.",
      steps: [
        { phase: "Contain", urgency: "Immediate", title: "Disable the unapproved change", description: "Confirm the owner and destination. If unapproved, remove or disable the forwarding address, inbox rule, connector, or delegate permission while preserving its values as evidence.", rtmAction: "Exchange → run the matching What-If action" },
        { phase: "Contain", urgency: "Immediate", title: "Secure the actor and mailbox", description: "If the actor or mailbox owner did not authorize the change, block the identity, revoke sessions, reset the password, and review registered MFA methods.", rtmAction: "Users → Revoke user access (What-If)" },
        { phase: "Investigate", urgency: "High", title: "Determine exposure", description: "Review mailbox activity from the first suspicious access through containment, including sent items, delegates, rules, message access, and external destinations.", rtmAction: "Raw Event Explorer → search mailbox, actor, and destination" },
        { phase: "Eradicate", urgency: "High", title: "Remove alternate persistence", description: "Inspect all inbox rules, forwarding settings, delegates, transport rules, connectors, and application consents; remove only unauthorized entries.", rtmAction: "Exchange → Mail Flow and Access" },
        { phase: "Validate", urgency: "Standard", title: "Verify normal mail flow", description: "Test approved delivery and forwarding behavior, then monitor for the rule or destination being recreated before resolving.", rtmAction: "Exchange → refresh mailbox details" },
      ],
      completionCriteria: ["The mail-flow change has an approved owner or has been removed.", "The initiating identity has been verified or contained.", "The exposure window is documented.", "No unauthorized persistence remains."],
    };
  }
  if (/sign-in|password spray|mfa|authentication|session/.test(text)) {
    return {
      category: "Identity compromise",
      summary: "Treat the identity as potentially compromised until the user and sign-in evidence establish otherwise.",
      steps: [
        { phase: "Contain", urgency: "Immediate", title: "Stop active access", description: "If the activity is not immediately verified, block sign-in, revoke sessions, reset the password, and remove unrecognized authentication methods.", rtmAction: "Users → Revoke user access (What-If)" },
        { phase: "Investigate", urgency: "High", title: "Validate the sign-in sequence", description: "Compare IP, country, device, client app, protocol, session, and Conditional Access results, and contact the user through a trusted channel.", rtmAction: "Raw Event Explorer → search the user and client IP" },
        { phase: "Investigate", urgency: "High", title: "Look for post-compromise activity", description: "Search for new MFA methods, mailbox rules, app consents, privilege changes, and unusual file access after the suspicious sign-in.", rtmAction: "Security Operations → related incidents" },
        { phase: "Recover", urgency: "Standard", title: "Restore trusted access", description: "Require fresh credentials and trusted MFA registration, and re-enable access only after persistence is removed.", rtmAction: "Users → review account and MFA state" },
        { phase: "Validate", urgency: "Standard", title: "Monitor for recurrence", description: "Confirm there are no new suspicious events from the same identity, IP, session, or device before resolving.", rtmAction: "Raw Event Explorer → repeat the evidence search" },
      ],
      completionCriteria: ["The user confirmed legitimate activity.", "Sessions and authentication methods are addressed.", "No unauthorized follow-on changes remain.", "Monitoring shows no recurrence."],
    };
  }
  return {
    category: "General Microsoft 365 investigation",
    summary: "Verify the activity, contain credible ongoing risk, and document evidence before changing tenant state.",
    steps: [
      { phase: "Investigate", urgency: "High", title: "Confirm the event and business context", description: "Validate the actor, target, time, client IP, exact change, and associated approval record.", rtmAction: "Raw Event Explorer → search incident entities" },
      { phase: "Contain", urgency: "High", title: "Limit credible ongoing risk", description: "If unauthorized or unverifiable, block affected identities or remove the narrowest unsafe permission through What-If.", rtmAction: "Use the relevant tenant tool → What-If" },
      { phase: "Investigate", urgency: "High", title: "Determine scope", description: "Review related sign-ins, directory changes, mailbox activity, application grants, and file access before and after the event.", rtmAction: "Security Operations → filter related incidents" },
      { phase: "Recover", urgency: "Standard", title: "Restore the approved state", description: "Remove persistence, rotate exposed credentials, and restore only verified access or configuration.", rtmAction: "Use the relevant tenant inventory" },
      { phase: "Validate", urgency: "Standard", title: "Prove the response worked", description: "Refresh affected inventory and repeat the evidence search before resolving.", rtmAction: "Raw Event Explorer → repeat the evidence search" },
    ],
    completionCriteria: ["The actor and business purpose are verified.", "Credible ongoing access is contained.", "Persistence paths are reviewed.", "The approved state is restored and monitoring is clean."],
  };
}

export function triageSecurityIncident(
  tenantId: string,
  incidentId: string,
  body: SecurityTriageRequest,
) {
  const incident = securityIncidentDetails.find(
    (item) => item.tenantId === tenantId && item.id === incidentId,
  );
  if (!incident) return null;
  if (body.status) incident.status = body.status;
  if (body.assignment === "me") incident.owner = "Jordan Meyer";
  if (body.assignment === "unassigned") delete incident.owner;
  return getSecurityIncident(tenantId, incidentId);
}

export function bulkTriageSecurityIncidents(
  body: SecurityBulkTriageRequest,
): SecurityBulkTriageResult {
  const incidents: SecurityBulkTriageResult["incidents"] = [];
  const failures: SecurityBulkTriageResult["failures"] = [];
  for (const reference of body.incidents) {
    const incident = securityIncidentDetails.find(
      (item) => item.tenantId === reference.tenantId && item.id === reference.incidentId,
    );
    if (!incident) {
      failures.push({
        ...reference,
        message: "Incident is no longer available. Refresh the queue.",
      });
      continue;
    }
    if (body.action === "accept") {
      incident.owner = "Jordan Meyer";
      if (incident.status === "New") incident.status = "In Progress";
    } else {
      incident.status = body.status;
    }
    incidents.push({
      ...reference,
      status: incident.status,
      owner: incident.owner,
    });
  }
  return {
    requested: body.incidents.length,
    updated: incidents.length,
    failed: failures.length,
    incidents,
    failures,
  };
}

export const workingSets: WorkingSet[] = [
  ["Sales Dept — No MFA", "Users", 14, "Contoso Ltd", "A. Rivera", "3d ago"],
  ["Offboarding — Q2", "Users", 8, "Adventure Works", "M. Okoro", "1d ago"],
  ["E5 License Audit", "Users", 182, "Contoso Ltd", "J. Meyer", "5h ago"],
  ["Inactive > 90 days", "Users", 37, "Fabrikam, Inc.", "D. Chen", "2d ago"],
  ["Exec Team", "Users", 5, "Contoso Ltd", "A. Rivera", "1w ago"],
  ["Shared Mailboxes", "Mailboxes", 23, "Northwind", "S. Patel", "4d ago"],
].map((w, i) => ({
  id: `ws_${i + 1}`,
  name: w[0] as string,
  description: "",
  type: w[1] as WorkingSet["type"],
  items: w[2] as number,
  tenantId: w[3] === "Contoso Ltd" ? "ten_1" : "",
  tenant: w[3] as string,
  userIds: [],
  createdBy: w[4] as string,
  lastUsed: w[5] as string,
}));

export function createWorkingSet(body: { name: string; description: string; tenantId: string; userIds: string[] }): WorkingSet {
  const tenantId = body.tenantId.trim();
  const userIds = normalizeWorkingSetUserIds(body.userIds);
  const tenant = tenants.find((candidate) => candidate.id === tenantId);
  const created: WorkingSet = {
    id: `ws_mock_${Date.now()}`,
    name: body.name.trim(),
    description: body.description.trim(),
    type: "Users",
    items: userIds.length,
    tenantId,
    tenant: tenant?.name ?? "Unknown tenant",
    userIds,
    createdBy: "Jordan Meyer",
    lastUsed: "just now",
  };
  workingSets.unshift(created);
  return created;
}

export function updateWorkingSet(id: string, body: { name: string; description: string; userIds: string[] }): WorkingSet {
  const workingSet = workingSets.find((candidate) => candidate.id === id);
  if (!workingSet) throw new Error("Working set not found");
  const userIds = normalizeWorkingSetUserIds(body.userIds);
  workingSet.name = body.name.trim();
  workingSet.description = body.description.trim();
  workingSet.userIds = userIds;
  workingSet.items = userIds.length;
  return { ...workingSet, userIds: [...workingSet.userIds] };
}

export const jobs: Job[] = [
  ["job_8f3a2c", "User Sync", "Fabrikam, Inc.", "Running", 62, "14:31", "—", "System"],
  ["job_7d1b90", "Group Membership Change", "Contoso Ltd", "Completed", 100, "14:27", "3.2s", "A. Rivera"],
  ["job_6c0a55", "License Assignment", "Wingtip Toys", "Queued", 0, "—", "—", "S. Patel"],
  ["job_5b9f12", "Global User Report", "All tenants", "Completed", 100, "14:20", "41s", "J. Meyer"],
  ["job_4a8e77", "Mailbox Permission", "Adventure Works", "Failed", 38, "14:09", "—", "M. Okoro"],
  ["job_3f7d10", "What If Preview", "Contoso Ltd", "Completed", 100, "14:02", "1.1s", "A. Rivera"],
  ["job_2e6c44", "Revert — Sign-in Block", "Adventure Works", "Partial", 80, "11:31", "12s", "M. Okoro"],
  ["job_1d5b22", "CSV Export", "Fabrikam, Inc.", "Completed", 100, "10:55", "5.4s", "D. Chen"],
].map((j) => ({
  id: j[0] as string,
  type: j[1] as string,
  tenant: j[2] as string,
  status: j[3] as Job["status"],
  progress: j[4] as number,
  started: j[5] as string,
  duration: j[6] as string,
  triggeredBy: j[7] as string,
  acknowledged: false,
}));

export function acknowledgeJob(jobId: string): { status: string } {
  const job = jobs.find((j) => j.id === jobId);
  if (!job) throw notFound("Job");
  job.acknowledged = true;
  audit.unshift({
    id: `aud_job_ack_${jobId}`,
    timestamp: "now",
    actor: "Jordan Meyer",
    action: "jobs.acknowledge",
    resource: jobId,
    result: "Success",
    correlationId: "cor_mock_ack",
  });
  return { status: "acknowledged" };
}

export const changes: ChangeRecord[] = [
  ["2026-06-28 14:02", "A. Rivera", "Contoso Ltd", "Added 12 members", "Sales — All Staff", "Completed", "Available"],
  ["2026-06-28 13:40", "D. Chen", "Fabrikam, Inc.", "Removed license E5", "4 users", "Completed", "Available"],
  ["2026-06-28 12:55", "S. Patel", "Northwind", "Set MFA enforced", "Finance (22)", "Partial", "Available"],
  ["2026-06-28 11:30", "M. Okoro", "Adventure Works", "Blocked sign-in", "8 users", "Completed", "Reverted"],
  ["2026-06-28 10:12", "A. Rivera", "Contoso Ltd", "Created group", "Project Falcon", "Completed", "Not supported"],
  ["2026-06-28 09:48", "J. Meyer", "Proseware", "Reset MFA methods", "k.lewis@…", "Completed", "Available"],
  ["2026-06-27 17:20", "D. Chen", "Fabrikam, Inc.", "Assigned license", "18 users · E3", "Failed", "—"],
  ["2026-06-27 16:05", "S. Patel", "Wingtip Toys", "Converted mailbox", "support@…", "Completed", "Available"],
].map((c, i) => ({
  id: `chg_${i + 1}`,
  timestamp: c[0],
  technician: c[1],
  tenant: c[2],
  action: c[3],
  target: c[4],
  status: c[5] as ChangeRecord["status"],
  revert: c[6] as ChangeRecord["revert"],
}));

export const changeDetail: Record<string, ChangeDetail> = Object.fromEntries(
  changes.map((c) => [
    c.id,
    {
      ...c,
      graphRequestId: "req_" + c.id.replace("chg_", "") + "a1b2c3d4e5",
      revertEligible: c.revert === "Available",
      before: ["members: 74", "modified: 2026-05-30T09:11Z", "owner: avery.quinn@contoso.com"],
      after: ["members: 86", "modified: 2026-06-28T14:02Z", "owner: avery.quinn@contoso.com"],
      executionLog: [
        "14:02:01  Preview generated · 12 targets · 0 errors",
        "14:02:03  Approval granted by M. Okoro",
        "14:02:03  Executing via Microsoft Graph (batch)",
        "14:02:06  200 OK · 12 added · 0 failed",
        "14:02:06  Change recorded · revert snapshot saved",
      ],
    },
  ]),
);

export const audit: AuditEntry[] = [
  ["14:35:12", "A. Rivera", "threatlocker.enter_maintenance_mode", "Contoso Ltd", "Success", "cor_tl_maint"],
  ["14:34:01", "A. Rivera", "threatlocker.approve_request", "Contoso Ltd", "Success", "cor_tl_approve"],
  ["14:31:02", "system", "sync.refresh", "Fabrikam, Inc.", "Success", "cor_9f2a31"],
  ["14:27:44", "A. Rivera", "changes.execute", "Contoso Ltd", "Success", "cor_8b1c02"],
  ["14:20:10", "J. Meyer", "global-reports.generate", "All tenants", "Success", "cor_7a0d55"],
  ["14:09:33", "M. Okoro", "changes.execute", "Adventure Works", "Failed", "cor_6c9e18"],
  ["13:58:21", "S. Patel", "exports.generate", "Northwind", "Success", "cor_5d8f77"],
  ["13:40:09", "D. Chen", "changes.execute", "Fabrikam, Inc.", "Success", "cor_4e7a90"],
  ["13:22:55", "unknown", "auth.login", "—", "Denied", "cor_3f6b12"],
  ["13:01:40", "A. Rivera", "working_set.create", "Contoso Ltd", "Success", "cor_2a5c44"],
].map((a, i) => ({
  id: `aud_${i + 1}`,
  timestamp: a[0],
  actor: a[1],
  action: a[2],
  resource: a[3],
  result: a[4] as AuditEntry["result"],
  correlationId: a[5],
}));

export function recordExport(body: ExportGenerateRequest): { status: "recorded" } {
  const tenant = body.tenantId
    ? tenants.find((candidate) => candidate.id === body.tenantId)?.name ?? body.tenantId
    : "global";
  audit.unshift({
    id: `aud_export_${audit.length + 1}`,
    timestamp: new Date().toLocaleTimeString(),
    actor: "Current operator",
    action: "exports.generate",
    resource: `${body.kind} export · ${tenant} · ${body.filename} · ${body.rowCount} rows`,
    result: "Success",
    correlationId: `cor_export_${audit.length + 1}`,
  });
  return { status: "recorded" };
}

export const technicians: Technician[] = [
  ["Jordan Meyer", "jordan.meyer@rarity.io", "Admin", "All", "Active", "now"],
  ["Aisha Rivera", "aisha.rivera@rarity.io", "Technician", "All", "Active", "12m ago"],
  ["David Chen", "david.chen@rarity.io", "Technician", "All", "Active", "5m ago"],
  ["Nina Wells", "nina.wells@rarity.io", "Technician", "All", "Invited", "—"],
].map((t, i) => ({
  id: `tech_${i + 1}`,
  name: t[0],
  email: t[1],
  role: t[2],
  tenants: t[3],
  status: t[4] as Technician["status"],
  lastActive: t[5],
  mustChangePassword: t[4] === "Invited",
}));

export const roles: Role[] = [
  { name: "Admin", description: "Everything across all tenants, plus platform administration: connect/remove tenants, manage technicians, execute write actions, change settings.", permissions: "All permissions", permissionKeys: ["tenants.manage", "technicians.manage", "roles.manage", "settings.manage", "changes.execute", "security.manage", "threatlocker.manage"], lockedPermissionKeys: ["tenants.manage", "technicians.manage", "roles.manage", "settings.manage", "changes.execute", "security.manage", "threatlocker.manage"], level: "Privileged", levelTone: "danger", assigned: 1 },
  { name: "Technician", description: "Work across all tenants: inventory, Exchange/SharePoint/ThreatLocker detail, reports, jobs, and change history.", permissions: "Read across all tenants", permissionKeys: [], level: "Read", levelTone: "warning", assigned: 3 },
];

export function updateRole(
  name: string,
  body: { description: string; permissionKeys: string[] },
): Role {
  const role = roles.find((item) => item.name === name);
  if (!role) throw new Error("Role not found");
  role.description = body.description.trim();
  role.permissionKeys = [...body.permissionKeys];
  const count = role.permissionKeys.length;
  if (count === 0) {
    role.permissions = "Read across all tenants";
    role.level = "Read";
    role.levelTone = "warning";
  } else if (count === 1) {
    role.permissions = "1 elevated capability";
    role.level = "Custom";
    role.levelTone = "info";
  } else if (count === 7) {
    role.permissions = "All permissions";
    role.level = "Privileged";
    role.levelTone = "danger";
  } else {
    role.permissions = `${count} elevated capabilities`;
    role.level = "Custom";
    role.levelTone = "info";
  }
  return { ...role, permissionKeys: [...role.permissionKeys] };
}

export const appSettings: AppSetting[] = [
  { key: "require_whatif", label: "Require What If preview for all write actions", description: "No change executes without a generated preview.", enabled: true, locked: true },
  { key: "require_approval", label: "Require approval before execution", description: "A second authorized user must approve each change.", enabled: true },
  { key: "tenant_isolation", label: "Enforce tenant isolation on every request", description: "Server-side tenant authorization check.", enabled: true, locked: true },
  { key: "audit_exports", label: "Audit all report exports", description: "Log actor, tenant, and correlation ID on export.", enabled: true },
  { key: "engineer_export", label: "Allow CSV export for Engineers", description: "Read-Only and Auditor roles can always export.", enabled: false },
  { key: "session_timeout", label: "Session timeout", description: "Access tokens expire after the selected duration. Changes apply to new sign-ins and refreshed sessions.", enabled: true, value: "30" },
];

export const dashboardStats: DashboardStat[] = [
  { label: "Assigned Tenants", value: "12", delta: "All connected", tone: "success" },
  { label: "Active Jobs", value: "3", delta: "2 running · 1 queued", tone: "info" },
  { label: "Pending Approvals", value: "5", delta: "2 high risk", tone: "warning" },
  { label: "Failed Jobs (24h)", value: "2", delta: "Needs attention", tone: "danger" },
  { label: "Changes Today", value: "28", delta: "+6 vs yesterday", tone: "neutral" },
];

export const approvals: Approval[] = [
  { id: "apr_1", action: "Add 12 members to “Sales — All Staff”", tenant: "Contoso Ltd", by: "A. Rivera", risk: "Medium" },
  { id: "apr_2", action: "Remove Microsoft 365 E5 from 4 users", tenant: "Fabrikam, Inc.", by: "D. Chen", risk: "High" },
  { id: "apr_3", action: "Enforce MFA for Finance group", tenant: "Contoso Ltd", by: "A. Rivera", risk: "Medium" },
  { id: "apr_4", action: "Convert 3 mailboxes to shared", tenant: "Northwind", by: "S. Patel", risk: "Low" },
  { id: "apr_5", action: "Block sign-in for offboarded users (8)", tenant: "Adventure Works", by: "M. Okoro", risk: "High" },
];

/** Mock for POST /changes/preview — computed from the mock dataset the same
 * way the real API computes it from live Graph state. Mirrors the backend's
 * per-action skip rules, labels, and risk scoring for all write actions
 * (directory, Exchange, and SharePoint). */
export function buildWhatIfPreview(body: {
  action: string;
  groupId?: string;
  skuId?: string;
  userIds?: string[];
  mailboxIds?: string[];
  forwardTo?: string;
  autoReplyMessage?: string;
  permission?: string;
  delegateId?: string;
  siteIds?: string[];
  siteId?: string;
  role?: string;
  sharingLevel?: string;
  deviceIds?: string[];
  maintenanceType?: string;
  durationMinutes?: number;
  approvalRequestIds?: string[];
  scope?: string;
  expiresAt?: string;
  reason?: string;
}): WhatIfPreview {
  const group = groups.find((g) => g.id === body.groupId);
  const license = licenses.find((l) => l.skuId === body.skuId);
  const site = sites.find((s) => s.id === body.siteId);
  const delegate = users.find((u) => u.id === body.delegateId);
  const memberIds = new Set(groupMembers.map((m) => m.id));

  const isGroupAction = body.action === "add_to_group" || body.action === "remove_from_group";
  const isMailboxAction = [
    "set_forwarding",
    "clear_forwarding",
    "enable_auto_reply",
    "disable_auto_reply",
    "grant_mailbox_permission",
    "revoke_mailbox_permission",
  ].includes(body.action);
  const isSiteSharing = body.action === "set_site_sharing";
  const isDeviceAction = [
    "enter_maintenance_mode",
    "secure_device",
    "lockdown_device",
    "release_lockdown",
    "isolate_device",
    "release_isolation",
    "enable_tamper_protection",
    "disable_tamper_protection",
    "restart_agent",
  ].includes(body.action);
  const isApprovalAction = body.action === "approve_request" || body.action === "deny_request";

  let label: string;
  let title: string;
  const warnings: string[] = [];
  switch (body.action) {
    case "add_to_group":
      label = "Add as Member";
      title = `Add N members to “${group?.name ?? body.groupId}”`;
      break;
    case "remove_from_group":
      label = "Remove as Member";
      title = `Remove N members from “${group?.name ?? body.groupId}”`;
      break;
    case "block_signin":
      label = "Block sign-in";
      title = "Block sign-in for N users";
      warnings.push("Blocked users cannot sign in to any Microsoft 365 service until unblocked.");
      break;
    case "unblock_signin":
      label = "Unblock sign-in";
      title = "Unblock sign-in for N users";
      break;
    case "assign_license":
      label = "Assign license";
      title = `Assign ${license?.product ?? body.skuId} to N users`;
      break;
    case "remove_license":
      label = "Remove license";
      title = `Remove ${license?.product ?? body.skuId} from N users`;
      break;
    case "revoke_sessions":
      label = "Revoke sessions";
      title = "Revoke sessions for N users";
      warnings.push("This cannot be reverted — users must sign in again on every device.");
      break;
    case "reset_password":
      label = "Reset password";
      title = "Reset passwords for N users";
      warnings.push("This cannot be reverted. One-time passwords are shown only after execution.");
      break;
    case "revoke_user_access":
      label = "Reset password + MFA + sessions";
      title = "Contain N compromised user account(s)";
      warnings.push("This resets passwords, removes registered authentication methods, and revokes sessions. It cannot be reverted.");
      break;
    case "set_forwarding":
      label = "Set forwarding";
      title = `Forward N mailbox(es) to ${body.forwardTo}`;
      warnings.push(`All new mail arriving in these mailboxes will be forwarded to ${body.forwardTo}.`);
      warnings.push("Verify the forwarding address — forwarding to an external mailbox can exfiltrate mail.");
      break;
    case "clear_forwarding":
      label = "Clear forwarding";
      title = "Clear forwarding on N mailbox(es)";
      warnings.push("The previous forwarding address is not snapshotted — this cannot be reverted automatically.");
      break;
    case "enable_auto_reply":
      label = "Enable auto-reply";
      title = "Enable auto-reply on N mailbox(es)";
      break;
    case "disable_auto_reply":
      label = "Disable auto-reply";
      title = "Disable auto-reply on N mailbox(es)";
      warnings.push("The previous auto-reply message is not snapshotted — this cannot be reverted automatically.");
      break;
    case "grant_mailbox_permission":
      label = "Grant permission";
      title = `Grant ${body.permission} to ${delegate?.name ?? body.delegateId} on N mailbox(es)`;
      if (body.permission === "Full Access")
        warnings.push(`${delegate?.name ?? "The delegate"} will be able to open these mailboxes and read all content.`);
      break;
    case "revoke_mailbox_permission":
      label = "Revoke permission";
      title = `Revoke ${body.permission} from ${delegate?.name ?? body.delegateId} on N mailbox(es)`;
      break;
    case "grant_site_access":
      label = "Grant site access";
      title = `Grant ${body.role} on “${site?.name ?? body.siteId}” to N users`;
      if (body.role === "Full Control")
        warnings.push("Full Control includes permission management on the site.");
      break;
    case "revoke_site_access":
      label = "Revoke site access";
      title = `Revoke ${body.role} on “${site?.name ?? body.siteId}” from N users`;
      break;
    case "set_site_sharing":
      label = "Change sharing level";
      title = `Set external sharing to ${body.sharingLevel} on N site(s)`;
      if (body.sharingLevel === "Anyone")
        warnings.push("“Anyone” enables anonymous sharing links — content can be accessed without signing in.");
      else if (body.sharingLevel === "External")
        warnings.push("External guests will be able to access shared content on these sites.");
      warnings.push("The previous sharing level is not snapshotted — this cannot be reverted automatically.");
      break;
    case "enter_maintenance_mode":
      label = "Enter maintenance";
      title = `Enter ${body.maintenanceType} maintenance on N device(s)`;
      warnings.push(
        `Protection is reduced while these devices are in ${body.maintenanceType} maintenance (ends after ${body.durationMinutes} minutes).`,
      );
      if (body.maintenanceType === "disable_protection")
        warnings.push("Disable Protection turns ThreatLocker enforcement off entirely — the highest-risk maintenance state.");
      break;
    case "secure_device":
      label = "Secure device";
      title = "Secure N device(s)";
      warnings.push("The previous mode and its scheduled end are not snapshotted — this cannot be reverted automatically.");
      break;
    case "lockdown_device":
      label = "Lock down";
      title = "Lock down N device(s)";
      warnings.push("Locked-down devices can only communicate with ThreatLocker — users cannot run anything until the lockdown is released.");
      break;
    case "release_lockdown":
      label = "Release lockdown";
      title = "Release lockdown on N device(s)";
      warnings.push("Releasing clears the device's active alerts in ThreatLocker.");
      break;
    case "isolate_device":
      label = "Isolate";
      title = "Isolate N device(s)";
      warnings.push("Isolated devices lose all network access except to ThreatLocker until the isolation is released.");
      break;
    case "release_isolation":
      label = "Release isolation";
      title = "Release isolation on N device(s)";
      warnings.push("Releasing clears the device's active alerts in ThreatLocker.");
      break;
    case "enable_tamper_protection":
      label = "Enable tamper protection";
      title = "Enable tamper protection on N device(s)";
      break;
    case "disable_tamper_protection":
      label = "Disable tamper protection";
      title = "Disable tamper protection on N device(s)";
      warnings.push("With tamper protection off, the ThreatLocker agent can be modified or removed locally.");
      break;
    case "restart_agent":
      label = "Restart agent";
      title = "Restart the ThreatLocker agent on N device(s)";
      warnings.push("This cannot be reverted — the agent service restarts on each device.");
      break;
    case "approve_request":
      label = "Approve request";
      title = `Approve N application request(s) at ${body.scope} scope`;
      warnings.push(
        `Approving creates a ThreatLocker permit policy at ${body.scope} scope — it cannot be reverted from RTM (manage the policy in ThreatLocker).`,
      );
      if (body.expiresAt) warnings.push(`The permit is temporary and expires at ${body.expiresAt}.`);
      break;
    case "deny_request":
      label = "Deny request";
      title = "Deny N application request(s)";
      warnings.push("This cannot be reverted — the requester must submit a new request.");
      break;
    default:
      label = body.action;
      title = `${body.action} for N users`;
  }

  const changes: WhatIfPreview["changes"] = [];
  const skipped: WhatIfPreview["skipped"] = [];
  // Blocked: on-prem-mastered targets the write gate refuses (mirrors backend).
  const blocked: WhatIfPreview["blocked"] = [];
  const onPremResolution =
    "Make this change in on-prem Active Directory, then allow Entra sync to update Microsoft 365.";
  const groupBlocked = isGroupAction && group?.source === "On-prem sync";
  let targets = 0;
  let more = 0;
  const addTarget = (object: string, detail: string) => {
    targets += 1;
    if (changes.length < 5) {
      changes.push({ object, detail, change: label });
    } else {
      more += 1;
    }
  };

  if (isDeviceAction) {
    for (const did of body.deviceIds ?? []) {
      const d = devices.find((x) => x.id === did);
      if (!d) {
        skipped.push({ object: did, reason: "Device not found in this tenant" });
        continue;
      }
      let skipReason: string | null = null;
      if (body.action === "secure_device" && d.mode === "secured") {
        skipReason = "Already secured";
      } else if (
        body.action === "enter_maintenance_mode" &&
        d.mode === (body.maintenanceType === "disable_protection" ? "maintenance" : body.maintenanceType)
      ) {
        skipReason = "Already in this maintenance mode";
      } else if (body.action === "lockdown_device" && d.mode === "lockdown") {
        skipReason = "Already locked down";
      } else if (body.action === "release_lockdown" && d.mode !== "lockdown") {
        skipReason = "Not locked down";
      } else if (body.action === "isolate_device" && d.mode === "isolated") {
        skipReason = "Already isolated";
      } else if (body.action === "release_isolation" && d.mode !== "isolated") {
        skipReason = "Not isolated";
      } else if (body.action === "enable_tamper_protection" && d.tamperProtection) {
        skipReason = "Tamper protection is already enabled";
      } else if (body.action === "disable_tamper_protection" && !d.tamperProtection) {
        skipReason = "Tamper protection is already disabled";
      }
      if (skipReason) {
        skipped.push({ object: d.hostname, reason: skipReason });
        continue;
      }
      addTarget(d.hostname, d.group);
    }
    const offline = (body.deviceIds ?? []).filter((did) => {
      const d = devices.find((x) => x.id === did);
      return d && !d.online;
    }).length;
    if (offline > 0)
      warnings.push(`${offline} device(s) are offline — the change applies when they next check in.`);
  } else if (isApprovalAction) {
    for (const rid of body.approvalRequestIds ?? []) {
      const q = approvalRequests.find((x) => x.id === rid);
      if (!q) {
        skipped.push({ object: rid, reason: "Approval request not found in this tenant" });
      } else if (q.status !== "pending") {
        skipped.push({ object: q.application, reason: "Request is no longer pending" });
      } else {
        addTarget(q.application, `${q.deviceName} · ${q.requester}`);
      }
    }
  } else if (isMailboxAction) {
    for (const mid of body.mailboxIds ?? []) {
      const m = mailboxes.find((x) => x.id === mid);
      if (!m) {
        skipped.push({ object: mid, reason: "Mailbox not found in this tenant" });
        continue;
      }
      addTarget(m.name, m.email);
    }
  } else if (isSiteSharing) {
    for (const sid of body.siteIds ?? []) {
      const s = sites.find((x) => x.id === sid);
      if (!s) {
        skipped.push({ object: sid, reason: "Site not found in this tenant" });
      } else if (s.externalSharing === body.sharingLevel) {
        skipped.push({ object: s.name, reason: "Already at this sharing level" });
      } else {
        addTarget(s.name, s.url);
      }
    }
  } else {
    for (const uid of body.userIds ?? []) {
      const u = users.find((x) => x.id === uid);
      if (!u) {
        skipped.push({ object: uid, reason: "User not found in this tenant" });
        continue;
      }
      if (groupBlocked) {
        blocked.push({
          object: u.name,
          reason: `“${group?.name}” is synced from on-prem AD — its membership is mastered in Active Directory.`,
          resolution: onPremResolution,
        });
        continue;
      }
      if (
        (body.action === "block_signin" || body.action === "unblock_signin") &&
        u.sourceOfAuthority === "on_prem"
      ) {
        blocked.push({
          object: u.name,
          reason: "This user is synced from on-prem AD — sign-in state is mastered in Active Directory.",
          resolution: onPremResolution,
        });
        continue;
      }
      let skipReason: string | null = null;
      if (body.action === "add_to_group" && memberIds.has(uid)) {
        skipReason = "Already a member";
      } else if (body.action === "remove_from_group" && !memberIds.has(uid)) {
        skipReason = "Not a member of this group";
      } else if (body.action === "block_signin" && u.status === "Disabled") {
        skipReason = "Sign-in is already blocked";
      } else if (body.action === "unblock_signin" && u.status !== "Disabled") {
        skipReason = "Sign-in is not blocked";
      }
      if (skipReason) {
        skipped.push({ object: u.name, reason: skipReason });
        continue;
      }
      addTarget(u.name, u.upn);
    }
  }

  title = title.replace("N", String(targets));

  if (skipped.length > 0)
    warnings.push(`${skipped.length} selected target(s) are skipped and will not be changed.`);
  if (blocked.length > 0) {
    warnings.push(
      `${blocked.length} target(s) are mastered by on-prem Active Directory and cannot be changed from RTM — make the change in on-prem AD.`,
    );
    if (body.action === "block_signin")
      warnings.push(
        "To stop cloud access for synced users immediately without editing on-prem AD, revoke their sessions instead.",
      );
  }
  if (targets === 0) warnings.push("Nothing to do — no changes would be applied.");

  const destructive =
    body.action === "block_signin" ||
    body.action === "revoke_sessions" ||
    body.action === "reset_password" ||
    body.action === "revoke_user_access" ||
    body.action === "remove_license" ||
    body.action === "set_forwarding" ||
    (body.action === "set_site_sharing" && body.sharingLevel !== "Internal") ||
    (body.action === "grant_mailbox_permission" && body.permission === "Full Access") ||
    (body.action === "grant_site_access" && body.role === "Full Control") ||
    body.action === "lockdown_device" ||
    body.action === "isolate_device" ||
    body.action === "disable_tamper_protection" ||
    (body.action === "enter_maintenance_mode" && body.maintenanceType === "disable_protection") ||
    (body.action === "approve_request" && body.scope === "organization");
  const risk: WhatIfPreview["risk"] =
    targets >= 25 || (destructive && targets >= 10)
      ? "High"
      : targets >= 5 || destructive
        ? "Medium"
        : "Low";

  const requiredPermission = isDeviceAction || isApprovalAction
    ? "ThreatLocker API token (organization access)"
    : isGroupAction
    ? "GroupMember.ReadWrite.All"
    : ["set_forwarding", "clear_forwarding", "enable_auto_reply", "disable_auto_reply"].includes(body.action)
      ? "MailboxSettings.ReadWrite"
      : ["grant_mailbox_permission", "revoke_mailbox_permission"].includes(body.action)
        ? "Exchange Online — Exchange.ManageAsApp"
        : ["grant_site_access", "revoke_site_access", "set_site_sharing"].includes(body.action)
          ? "Sites.FullControl.All"
          : body.action === "reset_password"
            ? "User-PasswordProfile.ReadWrite.All + applicable Entra directory role"
            : body.action === "revoke_user_access"
              ? "User-PasswordProfile.ReadWrite.All + UserAuthenticationMethod.ReadWrite.All + User.RevokeSessions.All + applicable Entra directory role"
              : body.action === "revoke_sessions"
                ? "User.RevokeSessions.All"
                : "User.ReadWrite.All";

  return {
    action: title,
    tenant: "Contoso Ltd",
    risk,
    requiredPermission,
    targetCount: targets,
    targetNoun: isDeviceAction
      ? "devices"
      : isApprovalAction
        ? "approval requests"
        : isMailboxAction
          ? "mailboxes"
          : isSiteSharing
            ? "sites"
            : "users",
    changes,
    moreCount: more,
    warnings,
    skipped,
    blocked,
  };
}

let techSeq = 0;

/** Mock for POST /admin/technicians. */
export function createTechnician(body: {
  name: string;
  email: string;
  role: string;
}): { technician: Technician; tempPassword: string } {
  techSeq += 1;
  const t: Technician = {
    id: `tech_new_${techSeq}`,
    name: body.name,
    email: body.email,
    role: body.role,
    tenants: "All",
    status: "Active",
    lastActive: "—",
    mustChangePassword: true,
  };
  technicians.push(t);
  return { technician: t, tempPassword: "Rtm-mock-temp-password" };
}

export function updateTechnician(
  id: string,
  body: { role?: string; status?: string },
): { status: string } {
  const t = technicians.find((x) => x.id === id);
  if (t) {
    if (body.role) t.role = body.role;
    if (body.status) t.status = body.status as Technician["status"];
  }
  return { status: "updated" };
}

export function deleteTechnician(id: string): { status: string } {
  const i = technicians.findIndex((x) => x.id === id);
  if (i >= 0) technicians.splice(i, 1);
  return { status: "deleted" };
}

export function resetTechnicianPassword(id: string): { status: "reset"; tempPassword: string } {
  const technician = technicians.find((candidate) => candidate.id === id);
  if (!technician) throw new Error("Technician not found");
  technician.mustChangePassword = true;
  return { status: "reset", tempPassword: "Rtm-mock-reset-password" };
}

export function updateSetting(key: string, enabled: boolean): { status: string } {
  const s = appSettings.find((x) => x.key === key);
  if (s && !s.locked) s.enabled = enabled;
  return { status: "updated" };
}

export function updateSettingValue(key: string, value: string): { status: string } {
  const setting = appSettings.find((item) => item.key === key);
  if (setting) setting.value = value;
  return { status: "updated" };
}

let threatLockerGlobalConfiguration = {
  configured: false,
  tokenConfigured: false,
  source: "none" as "database" | "environment" | "none",
  instance: "",
  parentOrganizationId: "",
};

export function getThreatLockerGlobalConfiguration() {
  return { ...threatLockerGlobalConfiguration };
}

export function updateThreatLockerGlobalConfiguration(body: {
  instance: string;
  token: string;
  parentOrganizationId: string;
}) {
  threatLockerGlobalConfiguration = {
    configured: true,
    tokenConfigured: true,
    source: "database",
    instance: body.instance,
    parentOrganizationId: body.parentOrganizationId,
  };
  return getThreatLockerGlobalConfiguration();
}

export const globalReports: Record<string, GlobalReport> = {
  threatlocker: {
    columns: ["Tenant", "Devices", "Secured", "Reduced Protection", "Pending Approvals", "Offline > 7d"],
    rows: [
      [{ text: "Contoso Ltd" }, { text: "6" }, { text: "4" }, { badge: "2", tone: "warning" }, { badge: "2", tone: "warning" }, { text: "0" }],
      [{ text: "Fabrikam, Inc." }, { text: "48" }, { text: "48" }, { badge: "0", tone: "success" }, { badge: "0", tone: "success" }, { text: "1" }],
      [{ text: "Northwind" }, { badge: "Not connected", tone: "neutral" }, { text: "—" }, { text: "—" }, { text: "—" }, { text: "—" }],
    ],
  },
  mfa: {
    columns: ["Tenant", "Display Name", "UPN", "MFA State", "Method", "Last Sign-in"],
    rows: [
      [{ text: "Contoso Ltd" }, { text: "Avery Quinn" }, { text: "avery.quinn@contoso.com" }, { badge: "Enabled", tone: "info" }, { text: "Authenticator" }, { text: "1h ago" }],
      [{ text: "Contoso Ltd" }, { text: "Gavin Reed" }, { text: "gavin.reed@contoso.com" }, { badge: "Disabled", tone: "danger" }, { text: "None" }, { text: "60d ago" }],
      [{ text: "Fabrikam, Inc." }, { text: "Omar Haddad" }, { text: "omar@fabrikam.com" }, { badge: "Enforced", tone: "success" }, { text: "FIDO2" }, { text: "12m ago" }],
      [{ text: "Northwind" }, { text: "Rosa Diaz" }, { text: "rosa@northwind.com" }, { badge: "Disabled", tone: "danger" }, { text: "None" }, { text: "5d ago" }],
      [{ text: "Adventure Works" }, { text: "Tom Black" }, { text: "tom@adventure-works.com" }, { badge: "Enabled", tone: "info" }, { text: "SMS" }, { text: "3h ago" }],
      [{ text: "Proseware" }, { text: "Kira Lin" }, { text: "kira@proseware.com" }, { badge: "Enforced", tone: "success" }, { text: "Authenticator" }, { text: "30m ago" }],
    ],
  },
  license: {
    columns: ["Tenant", "SKU", "Product", "Assigned", "Total", "Utilization"],
    rows: [
      [{ text: "Contoso Ltd" }, { text: "SPE_E5" }, { text: "Microsoft 365 E5" }, { text: "182" }, { text: "200" }, { text: "91%" }],
      [{ text: "Fabrikam, Inc." }, { text: "SPE_E5" }, { text: "Microsoft 365 E5" }, { text: "640" }, { text: "700" }, { text: "91%" }],
      [{ text: "Northwind" }, { text: "SPE_E3" }, { text: "Microsoft 365 E3" }, { text: "88" }, { text: "96" }, { text: "92%" }],
      [{ text: "Adventure Works" }, { text: "ENTERPRISEPACK" }, { text: "Office 365 E3" }, { text: "280" }, { text: "310" }, { text: "90%" }],
      [{ text: "Wingtip Toys" }, { text: "SPE_E3" }, { text: "Microsoft 365 E3" }, { text: "50" }, { text: "54" }, { text: "93%" }],
      [{ text: "Proseware" }, { text: "EMSPREMIUM" }, { text: "EM+S E5" }, { text: "77" }, { text: "120" }, { text: "64%" }],
    ],
  },
  inactive: {
    columns: ["Tenant", "Display Name", "UPN", "Last Sign-in", "License", "Status"],
    rows: [
      [{ text: "Contoso Ltd" }, { text: "Gavin Reed" }, { text: "gavin.reed@contoso.com" }, { text: "60d ago" }, { text: "E5" }, { badge: "Disabled", tone: "neutral" }],
      [{ text: "Fabrikam, Inc." }, { text: "Nia Cole" }, { text: "nia@fabrikam.com" }, { text: "124d ago" }, { text: "E3" }, { badge: "Active", tone: "success" }],
      [{ text: "Northwind" }, { text: "Sam Tan" }, { text: "sam@northwind.com" }, { text: "98d ago" }, { text: "E3" }, { badge: "Active", tone: "success" }],
      [{ text: "Adventure Works" }, { text: "Lee Park" }, { text: "lee@adventure-works.com" }, { text: "201d ago" }, { text: "—" }, { badge: "Disabled", tone: "neutral" }],
    ],
  },
  guests: {
    columns: ["Tenant", "Display Name", "UPN", "Invited By", "Status", "Last Sign-in"],
    rows: [
      [{ text: "Contoso Ltd" }, { text: "Ivan Petrov" }, { text: "ivan.petrov@partner.com" }, { text: "A. Rivera" }, { badge: "Accepted", tone: "success" }, { text: "8d ago" }],
      [{ text: "Fabrikam, Inc." }, { text: "Mara Vide" }, { text: "mara@vendor.io" }, { text: "D. Chen" }, { badge: "Pending", tone: "warning" }, { text: "—" }],
      [{ text: "Northwind" }, { text: "Carl Ode" }, { text: "carl@agency.co" }, { text: "S. Patel" }, { badge: "Accepted", tone: "success" }, { text: "2d ago" }],
    ],
  },
  // ---- Entra readiness reports ----
  "license-readiness": {
    columns: ["Tenant", "Display Name", "UPN", "Issue", "Status"],
    rows: [
      [{ text: "Contoso Ltd" }, { text: "Kemal Yilmaz" }, { text: "kemal.yilmaz@contoso.com" }, { badge: "Unlicensed", tone: "info" }, { text: "Active" }],
      [{ text: "Contoso Ltd" }, { text: "Lena Vogt" }, { text: "lena.vogt@contoso.com" }, { badge: "Missing usage location", tone: "warning" }, { text: "Active" }],
      [{ text: "Fabrikam, Inc." }, { text: "Nia Cole" }, { text: "nia@fabrikam.com" }, { badge: "Missing usage location", tone: "warning" }, { text: "Active" }],
    ],
  },
  "mfa-gaps": {
    columns: ["Tenant", "Display Name", "UPN", "Admin", "Methods Registered", "SSPR"],
    rows: [
      [{ text: "Contoso Ltd" }, { text: "Dana White" }, { text: "dana.white@contoso.com" }, { badge: "Admin", tone: "danger" }, { text: "None" }, { badge: "Not registered", tone: "neutral" }],
      [{ text: "Contoso Ltd" }, { text: "Gavin Reed" }, { text: "gavin.reed@contoso.com" }, { text: "—" }, { text: "None" }, { badge: "Not registered", tone: "neutral" }],
      [{ text: "Contoso Ltd" }, { text: "Lena Vogt" }, { text: "lena.vogt@contoso.com" }, { text: "—" }, { text: "None" }, { badge: "Registered", tone: "success" }],
      [{ text: "Northwind" }, { text: "Rosa Diaz" }, { text: "rosa@northwind.com" }, { text: "—" }, { text: "None" }, { badge: "Not registered", tone: "neutral" }],
    ],
  },
  "stale-guests": {
    columns: ["Tenant", "Display Name", "Email", "Invite State", "Created", "Last Sign-in"],
    rows: [
      [{ text: "Contoso Ltd" }, { text: "Priya Patel" }, { text: "priya.patel@vendor.io" }, { badge: "Pending acceptance", tone: "warning" }, { text: "150 days ago" }, { text: "Never" }],
      [{ text: "Contoso Ltd" }, { text: "Marco Ruiz" }, { text: "marco.ruiz@freelance.example" }, { badge: "Accepted", tone: "neutral" }, { text: "1.4 years ago" }, { text: "120 days ago" }],
      [{ text: "Fabrikam, Inc." }, { text: "Mara Vide" }, { text: "mara@vendor.io" }, { badge: "Pending acceptance", tone: "warning" }, { text: "210 days ago" }, { text: "Never" }],
    ],
  },
  "privileged-roles": {
    columns: ["Tenant", "Role", "Member", "UPN", "Type"],
    rows: [
      [{ text: "Contoso Ltd" }, { badge: "Global Administrator", tone: "danger" }, { text: "Caleb Stone" }, { text: "caleb.stone@contoso.com" }, { text: "User" }],
      [{ text: "Contoso Ltd" }, { badge: "Global Administrator", tone: "danger" }, { text: "Julia Sanz" }, { text: "julia.sanz@contoso.com" }, { text: "User" }],
      [{ text: "Contoso Ltd" }, { badge: "User Administrator", tone: "info" }, { text: "Dana White" }, { text: "dana.white@contoso.com" }, { text: "User" }],
      [{ text: "Contoso Ltd" }, { badge: "Exchange Administrator", tone: "info" }, { text: "Hana Kim" }, { text: "hana.kim@contoso.com" }, { text: "User" }],
      [{ text: "Fabrikam, Inc." }, { badge: "Global Administrator", tone: "danger" }, { text: "Omar Haddad" }, { text: "omar@fabrikam.com" }, { text: "User" }],
    ],
  },
  "ca-exclusions": {
    columns: ["Tenant", "Policy", "State", "Exclusion", "Target"],
    rows: [
      [{ text: "Contoso Ltd" }, { text: "Require MFA for all users" }, { badge: "enabled", tone: "success" }, { text: "Excluded user" }, { text: "Caleb Stone (break-glass)" }],
      [{ text: "Contoso Ltd" }, { text: "Require MFA for all users" }, { badge: "enabled", tone: "success" }, { text: "Excluded group" }, { text: "IT Admins" }],
      [{ text: "Contoso Ltd" }, { text: "Block legacy authentication" }, { badge: "reportOnly", tone: "warning" }, { text: "Excluded app" }, { text: "Legacy Importer" }],
    ],
  },
  "app-credentials": {
    columns: ["Tenant", "Application", "Type", "Expires", "Status"],
    rows: [
      [{ text: "Contoso Ltd" }, { text: "Payroll Sync" }, { text: "Secret" }, { text: "2026-07-01" }, { badge: "Expired", tone: "danger" }],
      [{ text: "Contoso Ltd" }, { text: "CRM Connector" }, { text: "Secret" }, { text: "2026-08-05" }, { badge: "Expiring soon", tone: "warning" }],
      [{ text: "Contoso Ltd" }, { text: "Legacy Importer" }, { text: "Secret" }, { text: "2026-09-29" }, { badge: "Expiring soon", tone: "warning" }],
      [{ text: "Fabrikam, Inc." }, { text: "Ticket Bridge" }, { text: "Certificate" }, { text: "2026-08-19" }, { badge: "Expiring soon", tone: "warning" }],
    ],
  },
};

/** Sample technician × tenant access matrix (maps to the tenant_access table). */
export function notFound(resource: string): ApiError {
  return {
    error: {
      code: "OBJECT_NOT_FOUND",
      message: `${resource} was not found.`,
      correlation_id: "cor_" + Math.random().toString(16).slice(2, 10),
    },
  };
}

// ---- Preflight (mirrors the backend sample provider) ----

export function buildPreflight(): Preflight {
  const readAreas: [string, string, string][] = [
    ["Directory & Identity", "Directory — users", "User.Read.All"],
    ["Directory & Identity", "Directory — groups", "Group.Read.All"],
    ["SharePoint", "SharePoint group expansion", "GroupMember.Read.All"],
    ["Licensing", "Licensing", "Organization.Read.All"],
    ["Directory & Identity", "MFA registration report", "AuditLog.Read.All"],
    ["SharePoint", "SharePoint sites", "Sites.Read.All"],
    ["Directory & Identity", "Directory roles", "RoleManagement.Read.Directory"],
    ["Directory & Identity", "Conditional Access", "Policy.Read.All"],
    ["Directory & Identity", "App registrations", "Application.Read.All"],
    ["Security Operations", "Security Operations incidents", "SecurityIncident.Read.All"],
    ["Exchange", "Exchange mailbox usage", "Reports.Read.All"],
  ];
  const writeAreas: [string, string, string][] = [
    ["Directory & Identity", "Directory writes (sign-in and licensing)", "User.ReadWrite.All"],
    ["Directory & Identity", "Password reset", "User-PasswordProfile.ReadWrite.All"],
    ["Directory & Identity", "Compromised-user MFA reset", "UserAuthenticationMethod.ReadWrite.All"],
    ["Directory & Identity", "Compromised-user session revocation", "User.RevokeSessions.All"],
    ["Directory & Identity", "Group membership writes", "GroupMember.ReadWrite.All"],
    ["Exchange", "Mailbox settings writes (forwarding, auto-reply)", "MailboxSettings.ReadWrite"],
    ["SharePoint", "SharePoint drive-item permission management", "Sites.ReadWrite.All"],
    ["SharePoint", "SharePoint direct permission management", "Sites.FullControl.All"],
  ];
  return {
    mode: "sample",
    ranAt: new Date().toISOString(),
    checks: [
      ...readAreas.map(([category, area, permission]) => ({
        category,
        area,
        resource: "Microsoft Graph",
        permission,
        status: "sample" as const,
        detail: "Sample data — this tenant has no live Microsoft connection.",
      })),
      ...writeAreas.map(([category, area, permission]) => ({
        category,
        area,
        resource: "Microsoft Graph",
        permission,
        status: "unchecked" as const,
        detail: "Write permissions can't be probed without making a change — verify admin consent in Entra.",
      })),
      {
        category: "SharePoint",
        area: "SharePoint role assignments and inheritance",
        resource: "SharePoint Online",
        permission: "Sites.FullControl.All",
        status: "unchecked",
        detail: "Certificate-backed SharePoint REST probe runs when the central app is configured.",
      },
    ],
  };
}

let cachedPreflight: Preflight | undefined;

function copyPreflight(preflight: Preflight): Preflight {
  return { ...preflight, checks: preflight.checks.map((check) => ({ ...check })) };
}

export function getPreflight(): Preflight {
  if (!cachedPreflight) cachedPreflight = buildPreflight();
  return copyPreflight(cachedPreflight);
}

export function runPreflight(): Preflight {
  cachedPreflight = buildPreflight();
  return copyPreflight(cachedPreflight);
}

// ---- Raw user view (User Blowout) ----

export function buildUserRaw(userId: string): UserRaw | null {
  const u = users.find((x) => x.id === userId);
  if (!u) return null;
  const onPrem = u.sourceOfAuthority === "on_prem";
  const attributes: Record<string, unknown> = {
    id: u.id,
    displayName: u.name,
    userPrincipalName: u.upn,
    mail: u.upn,
    mailNickname: u.id,
    proxyAddresses: [`SMTP:${u.upn}`],
    department: u.department,
    jobTitle: `${u.department} Specialist`,
    companyName: "Contoso Ltd",
    officeLocation: "HQ / Floor 3",
    usageLocation: "US",
    preferredLanguage: "en-US",
    accountEnabled: u.status !== "Disabled",
    userType: u.status === "Guest" ? "Guest" : "Member",
    createdDateTime: "2023-05-14T09:30:00Z",
    businessPhones: ["+1 425 555 0100"],
    onPremisesSyncEnabled: onPrem,
    identities: [
      { signInType: "userPrincipalName", issuer: "contoso.com", issuerAssignedId: u.upn },
    ],
  };
  if (onPrem) {
    attributes.onPremisesSamAccountName = u.id;
    attributes.onPremisesDomainName = "corp.contoso.com";
    attributes.onPremisesDistinguishedName = `CN=${u.name},OU=Staff,DC=corp,DC=contoso,DC=com`;
    attributes.onPremisesExtensionAttributes = {
      extensionAttribute1: "IT-OPS",
      extensionAttribute2: "COST-4410",
    };
  }
  if (u.status === "Guest") {
    attributes.externalUserState = "Accepted";
    attributes.creationType = "Invitation";
  }
  return { id: u.id, attributes };
}

// ---- Share Detective (mirrors the backend sample scanner) ----

const shareInvestigations: ShareInvestigation[] = [];
let sdSeq = 0;

/** Findings the sample scanner produces per subject, mirroring the backend
 * seeded shared items (Ivan Petrov is the interesting offboarding case). */
function buildShareFindings(subjectId: string): ShareFinding[] {
  let seq = 0;
  const next = () => `f_${++seq}`;
  const findings: ShareFinding[] = [];
  if (subjectId === "usr_9") {
    findings.push(
      {
        id: next(), siteId: "site_3", siteName: "Project Falcon", itemPath: "/sites/falcon",
        itemType: "site", webUrl: "/sites/falcon", classification: "direct_user", role: "Edit",
        permissionId: "sp_9", revocable: true, revoked: false,
        detail: "Direct site grant — revocable for this subject only.",
      },
      {
        id: next(), siteId: "site_3", siteName: "Project Falcon", driveId: "drive_3", itemId: "item_31",
        itemPath: "/Shared Documents/Contracts/Falcon-Contract.docx", itemType: "file",
        webUrl: "/sites/falcon/Shared%20Documents/Contracts/Falcon-Contract.docx",
        classification: "direct_user", role: "write", permissionId: "perm_311", revocable: true, revoked: false,
        detail: "Direct permission — revocable for this subject only.",
      },
      {
        id: next(), siteId: "site_3", siteName: "Project Falcon", driveId: "drive_3", itemId: "item_31",
        itemPath: "/Shared Documents/Contracts/Falcon-Contract.docx", itemType: "file",
        classification: "group_based", role: "write", via: "Project Falcon", revocable: false, revoked: false,
        detail: "Access via group membership — use the remove-from-group action to revoke.",
      },
      {
        id: next(), siteId: "site_3", siteName: "Project Falcon", driveId: "drive_3", itemId: "item_32",
        itemPath: "/Shared Documents/Design", itemType: "folder",
        classification: "broad_link", role: "read", via: "anonymous link", revocable: false, revoked: false,
        detail: "Broad sharing link — the subject may use it, but deleting it affects everyone with the link. Manual review.",
      },
      {
        id: next(), siteId: "site_3", siteName: "Project Falcon", driveId: "drive_3", itemId: "item_32",
        itemPath: "/Shared Documents/Design", itemType: "folder",
        classification: "direct_user", role: "read", permissionId: "perm_322", revocable: true, revoked: false,
        detail: "Direct permission — revocable for this subject only.",
      },
      {
        id: next(), siteId: "site_5", siteName: "Customer Files", driveId: "drive_5", itemId: "item_51",
        itemPath: "/Shared Documents/Client Uploads", itemType: "folder",
        classification: "broad_link", role: "write", via: "anonymous link", revocable: false, revoked: false,
        detail: "Broad sharing link — the subject may use it, but deleting it affects everyone with the link. Manual review.",
      },
    );
  } else if (subjectId === "usr_2") {
    findings.push({
      id: next(), siteId: "site_1", siteName: "Sales Team", driveId: "drive_1", itemId: "item_11",
      itemPath: "/Shared Documents/Q3-Pipeline.xlsx", itemType: "file",
      classification: "specific_people_link", role: "read", permissionId: "perm_111", revocable: true, revoked: false,
      detail: "Specific-people sharing link that includes the subject.",
    });
  }
  return findings;
}

export function startShareInvestigation(tenantId: string, subjectId: string): ShareInvestigation | null {
  const u = users.find((x) => x.id === subjectId);
  const t = tenants.find((x) => x.id === tenantId) ?? tenants[0];
  if (!u || !t) return null;
  const findings = buildShareFindings(subjectId);
  const inv: ShareInvestigation = {
    id: `sdi_${++sdSeq}`,
    tenantId: t.id,
    tenantName: t.name,
    subject: { id: u.id, name: u.name, upn: u.upn, type: u.status === "Guest" ? "Guest" : "Member" },
    status: "completed",
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    startedBy: "Jordan Meyer",
    summary: {
      sitesDiscovered: sites.length,
      sitesScanned: sites.length,
      sitesSkipped: 0,
      itemsScanned: 4,
      findings: findings.length,
      revocable: findings.filter((f) => f.revocable).length,
    },
    coverage: sites.map((s) => ({
      siteId: s.id,
      siteName: s.name,
      status: "scanned" as const,
      itemsScanned: findings.some((f) => f.siteId === s.id && f.itemId) ? 2 : 0,
    })),
    findings,
  };
  shareInvestigations.unshift(inv);
  return inv;
}

export function listShareInvestigations(tenantId: string): ShareInvestigation[] {
  return shareInvestigations.filter((i) => i.tenantId === tenantId);
}

export function getShareInvestigation(invId: string): ShareInvestigation | null {
  return shareInvestigations.find((i) => i.id === invId) ?? null;
}

export function previewShareRevoke(invId: string, findingIds: string[]): ShareRevokePreview | null {
  const inv = getShareInvestigation(invId);
  if (!inv) return null;
  const actions = findingIds.map((id) => {
    const f = inv.findings.find((x) => x.id === id);
    if (!f) return null;
    if (f.revocable && !f.revoked && f.permissionId) {
      return {
        findingId: f.id, siteName: f.siteName, itemPath: f.itemPath,
        action: "delete_permission" as const,
        reason: `Confirmed direct grant — deleting affects only ${inv.subject.name}.`,
      };
    }
    return {
      findingId: f.id, siteName: f.siteName, itemPath: f.itemPath,
      action: "manual_review" as const, reason: f.revoked ? "Already revoked." : f.detail,
    };
  }).filter((a): a is NonNullable<typeof a> => a !== null);
  const revocableCount = actions.filter((a) => a.action === "delete_permission").length;
  const warnings: string[] = [];
  if (revocableCount === 0) warnings.push("Nothing to do — none of the selected findings can be revoked directly.");
  const manual = actions.length - revocableCount;
  if (manual > 0)
    warnings.push(`${manual} selected finding(s) need another path (group membership, parent folder, or broad-link review) and will not be changed.`);
  warnings.push("Deleted permissions and sharing links cannot be recreated exactly — this cannot be reverted.");
  return {
    approvalToken: "mock",
    subject: inv.subject,
    tenant: inv.tenantName,
    risk: revocableCount >= 10 ? "High" : "Medium",
    revocableCount,
    actions,
    warnings,
  };
}

export function executeShareRevoke(invId: string, findingIds: string[]): ShareRevokeResult | null {
  const inv = getShareInvestigation(invId);
  if (!inv) return null;
  const revoked: string[] = [];
  for (const id of findingIds) {
    const f = inv.findings.find((x) => x.id === id);
    if (f && f.revocable && !f.revoked && f.permissionId) {
      f.revoked = true;
      revoked.push(f.id);
    }
  }
  return { status: revoked.length > 0 ? "Completed" : "Failed", revoked, failed: [] };
}

const securityEvents: SecurityAuditEventDetail[] = [
  ["evt_a1", "Exchange", "Set-Mailbox", "admin@contoso.com", "198.51.100.24", "finance@contoso.com", "Succeeded"],
  ["evt_a2", "AzureActiveDirectory", "Add member to role", "cloudadmin@contoso.com", "203.0.113.81", "Global Administrator", "Success"],
  ["evt_a3", "SharePoint", "FileDownloaded", "lee@contoso.com", "192.0.2.14", "/Finance/FY26.xlsx", "Success"],
  ["evt_a4", "Exchange", "New-InboxRule", "support@contoso.com", "198.51.100.24", "ceo@contoso.com", "Succeeded"],
  ["evt_a5", "AzureActiveDirectory", "UserLoggedIn", "alex@contoso.com", "203.0.113.42", "session:7f2c", "Success"],
  ["evt_a6", "AzureActiveDirectory", "UserLoginFailed", "alex@contoso.com", "203.0.113.42", "alex@contoso.com", "Failed"],
  ["evt_a7", "Exchange", "New-OutboundConnector", "admin@contoso.com", "198.51.100.24", "Partner Relay", "Succeeded"],
  ["evt_a8", "AzureActiveDirectory", "Add service principal credentials", "appadmin@contoso.com", "203.0.113.15", "Finance Export App", "Success"],
].map((row, index) => {
  const [id, workload, operation, actor, clientIp, objectId, resultStatus] = row;
  const occurredAt = securityAt(8 + index * 19);
  return {
    id, tenantId: "ten_1", tenantName: "Contoso Ltd", providerRecordId: `provider-${id}`,
    contentType: workload === "Exchange" ? "Audit.Exchange" : workload === "SharePoint" ? "Audit.SharePoint" : "Audit.AzureActiveDirectory",
    workload, operation, actor, clientIp, objectId, resultStatus, occurredAt,
    availableAt: occurredAt, ingestedAt: occurredAt, sources: ["m365_audit"], sample: true,
    raw: {
      CreationTime: occurredAt, Workload: workload, Operation: operation,
      UserId: actor, ClientIP: clientIp, ObjectId: objectId, ResultStatus: resultStatus,
      Parameters: operation.includes("Mailbox") || operation.includes("InboxRule")
        ? [{ Name: "ForwardingSmtpAddress", Value: "outside@example.net" }]
        : [],
      AccessToken: "[REDACTED]",
    },
    rawTruncated: false,
    relatedDetections: operation.includes("Mailbox") || operation.includes("InboxRule")
      ? [{
          id: `det-${id}`, tenantId: "ten_1", eventId: id,
          ruleId: "suspicious_mail_forwarding", ruleVersion: 1,
          title: "Mailbox forwarding or redirect changed",
          description: "Verify the destination and administrator intent.", severity: "High",
          detectionType: "direct", confidence: "high", occurredAt, createdAt: occurredAt, sample: true,
        }]
      : [],
  } as SecurityAuditEventDetail;
});

const builtinSecurityRuleNames: Array<[string, string, string, string, "high" | "medium" | "low"]> = [
  ["suspicious_mail_forwarding", "Mailbox forwarding or redirect changed", "direct", "High", "high"],
  ["mailbox_delegation_change", "Mailbox delegation or permission changed", "direct", "High", "high"],
  ["transport_rule_change", "Exchange transport rule changed", "direct", "High", "high"],
  ["inbox_rule_change", "Inbox rule changed", "direct", "Medium", "high"],
  ["privileged_role_change", "Privileged administrative role membership changed", "direct", "High", "high"],
  ["privileged_role_policy_change", "Privileged role or PIM policy changed", "direct", "High", "high"],
  ["guest_invitation", "Guest user invited or created", "direct", "Low", "high"],
  ["guest_privilege_escalation", "Guest account received privileged access", "direct", "High", "medium"],
  ["group_owner_change", "Group ownership changed", "direct", "Medium", "high"],
  ["group_membership_change", "Group membership changed", "direct", "Low", "high"],
  ["account_lifecycle_change", "User account lifecycle changed", "direct", "Medium", "high"],
  ["password_reset", "User password reset or changed", "direct", "Medium", "high"],
  ["authentication_method_change", "User authentication method changed", "direct", "High", "high"],
  ["suspicious_authentication_reported", "Suspicious authentication activity reported", "direct", "High", "high"],
  ["conditional_access_change", "Conditional Access policy changed", "direct", "High", "high"],
  ["named_location_change", "Conditional Access named location changed", "direct", "High", "high"],
  ["security_defaults_change", "Entra security defaults changed", "direct", "High", "high"],
  ["authorization_policy_change", "Tenant authorization policy changed", "direct", "High", "high"],
  ["cross_tenant_access_policy_change", "Cross-tenant access policy changed", "direct", "High", "high"],
  ["domain_federation_change", "Domain federation or authentication changed", "direct", "Critical", "high"],
  ["tenant_domain_change", "Tenant domain added, removed, or verified", "direct", "High", "high"],
  ["hybrid_authentication_change", "Hybrid authentication configuration changed", "direct", "High", "high"],
  ["application_registration", "Application or service principal registered", "direct", "Medium", "high"],
  ["application_configuration_change", "Application or service-principal configuration changed", "direct", "Medium", "high"],
  ["application_owner_change", "Application or service-principal owner changed", "direct", "High", "high"],
  ["oauth_consent", "OAuth consent or app-role assignment changed", "direct", "High", "high"],
  ["high_risk_app_permission", "High-risk application permission granted", "direct", "High", "medium"],
  ["application_secret_change", "Application credential created or changed", "direct", "High", "high"],
  ["application_secret_expiring", "New application credential expires soon", "direct", "Low", "medium"],
  ["sharepoint_permission_change", "SharePoint permission or administrator changed", "direct", "Medium", "high"],
  ["external_sharing_change", "External or anonymous sharing changed", "direct", "Medium", "high"],
  ["outlook_connector_change", "Exchange Online connector changed", "direct", "High", "high"],
  ["mail_protection_policy_change", "Exchange mail-protection policy changed", "direct", "High", "high"],
  ["mailbox_audit_bypass_change", "Mailbox audit bypass changed", "direct", "High", "high"],
  ["mailbox_auditing_disabled", "Organization-wide mailbox auditing disabled", "direct", "Critical", "high"],
  ["audit_log_search", "Audit log search executed or changed", "direct", "Low", "high"],
  ["audit_configuration_change", "Audit configuration changed", "direct", "High", "high"],
  ["single_factor_authentication", "Single-factor authentication sign-in observed", "direct", "High", "high"],
  ["legacy_authentication", "Legacy authentication activity observed", "direct", "Medium", "medium"],
  ["mass_mailbox_forwarding", "Mass mailbox forwarding changes", "threshold", "Critical", "high"],
  ["new_forwarding_domain", "Forwarding to a newly observed domain", "heuristic", "High", "medium"],
  ["large_group_membership_change", "Large group membership change", "threshold", "Medium", "high"],
  ["bulk_file_download", "Bulk SharePoint/OneDrive downloads", "threshold", "High", "medium"],
  ["bulk_file_deletion", "Bulk SharePoint/OneDrive deletions", "threshold", "High", "medium"],
  ["bulk_external_sharing", "Bulk SharePoint/OneDrive sharing", "threshold", "High", "medium"],
  ["repeated_administrative_failures", "Repeated administrative failures", "threshold", "Medium", "high"],
  ["administrator_object_burst", "Administrator changed many objects rapidly", "threshold", "High", "medium"],
  ["cross_tenant_administrator_burst", "Administrator activity burst across tenants", "correlation", "High", "medium"],
  ["unusual_administrator_ip", "Administrator used a newly observed IP", "heuristic", "Medium", "low"],
  ["unusual_administrator_country", "Administrator active from a newly observed country", "heuristic", "Medium", "low"],
  ["unusual_administrator_time", "Administrator active at an unusual UTC hour", "heuristic", "Low", "low"],
  ["failed_logins_then_success", "Repeated failed logins followed by success", "correlation", "High", "high"],
  ["possible_impossible_travel", "Possible impossible-travel login", "heuristic", "High", "medium"],
  ["possible_session_token_reuse", "Possible stolen-session or token reuse", "correlation", "High", "medium"],
];

const builtinSecurityRules: SecurityDetectionRule[] = builtinSecurityRuleNames.map(([ruleId, name, detectionType, severity, confidence]) => ({
  id: `builtin:${ruleId}`, ruleId, name,
  description: `RTM built-in detection for ${name.toLowerCase()}.`,
  builtIn: true, override: false, locked: true, detectionType,
  severity, confidence,
  enabled: true, scope: "global", definition: detectionType === "threshold" ? { triggerMode: "builtIn", threshold: 5, windowMinutes: 15 } : { triggerMode: "builtIn" },
  revision: 1, updatedBy: "System", createdAt: "", updatedAt: "",
}));

let customSecurityRules: SecurityDetectionRule[] = [];
const securityRuleRevisions: Record<string, SecurityDetectionRuleRevision[]> = {};

export function searchSecurityEvents(query: SecurityAuditEventSearch): SecurityAuditEventPage {
  const needle = query.query?.toLowerCase();
  const from = new Date(query.from).getTime(), to = new Date(query.to).getTime();
  const filtered = securityEvents.filter((event) => {
    const haystack = [event.operation, event.workload, event.actor, event.clientIp, event.objectId, event.resultStatus].join(" ").toLowerCase();
    return new Date(event.occurredAt).getTime() >= from && new Date(event.occurredAt).getTime() <= to &&
      (!query.tenantId || event.tenantId === query.tenantId) &&
      (!query.workload || event.workload.toLowerCase().includes(query.workload.toLowerCase())) &&
      (!query.operation || event.operation.toLowerCase().includes(query.operation.toLowerCase())) &&
      (!query.actor || event.actor?.toLowerCase().includes(query.actor.toLowerCase())) &&
      (!query.clientIp || event.clientIp?.toLowerCase().includes(query.clientIp.toLowerCase())) &&
      (!query.result || event.resultStatus?.toLowerCase().includes(query.result.toLowerCase())) &&
      (!needle || haystack.includes(needle));
  });
  const offset = query.offset ?? 0, limit = query.limit ?? 50;
  return { events: filtered.slice(offset, offset + limit).map(({ raw: _raw, sourceEvidence: _sourceEvidence, relatedDetections: _related, rawTruncated: _truncated, ...event }) => event), offset, limit, limited: false, windowDays: 7, nextOffset: offset + limit < filtered.length ? offset + limit : undefined };
}

export function getSecurityEvent(tenantId: string, eventId: string): SecurityAuditEventDetail | null {
  return securityEvents.find((event) => event.tenantId === tenantId && event.id === eventId) ?? null;
}

const offlineCaseNow = "2026-08-28T10:04:00Z";
let offlineInvestigationSeq = 1;
let offlineFileSeq = 3;
let offlineInvestigationDetails: OfflineInvestigationDetail[] = [
  {
    id: "offinv_demo_1",
    name: "Contoso suspicious sign-in review",
    tenantLabel: "Contoso Ltd",
    status: "complete",
    progress: 100,
    detail: "Analysis complete",
    createdBy: "Jordan Meyer",
    createdAt: "2026-08-28T09:58:00Z",
    updatedAt: offlineCaseNow,
    analyzedAt: offlineCaseNow,
    periodStart: "2026-08-28T09:11:00Z",
    periodEnd: "2026-08-28T09:46:00Z",
    eventCount: 186,
    detectionCount: 4,
    highPriorityCount: 3,
    storylineCount: 1,
    coverage: [
      { key: "entra_sign_ins", label: "Microsoft Entra sign-ins", status: "present", records: 118, detail: "Authentication requirement, methods, and Conditional Access fields present" },
      { key: "entra_directory_audits", label: "Microsoft Entra directory audit", status: "present", records: 42, detail: "Evidence ready for analysis" },
      { key: "m365_activity", label: "Microsoft 365 activity", status: "present", records: 26, detail: "Evidence ready for analysis" },
    ],
    files: [
      { id: "offile_demo_1", investigationId: "offinv_demo_1", name: "signIns.json", mediaType: "application/json", evidenceType: "entra_sign_ins", sizeBytes: 428104, sha256: "75d8f8a610ad86a06466c03a526ced6dd1f5a00186fa311544a3e59de142fcb8", status: "ready", recordCount: 118, uploadedAt: "2026-08-28T09:59:00Z" },
      { id: "offile_demo_2", investigationId: "offinv_demo_1", name: "directoryAudits.json", mediaType: "application/json", evidenceType: "entra_directory_audits", sizeBytes: 180211, sha256: "c12f33ab70de983874f3287f253ded60c9a3195cb2e38856da44f19dbe2c900e", status: "ready", recordCount: 42, uploadedAt: "2026-08-28T09:59:20Z" },
      { id: "offile_demo_3", investigationId: "offinv_demo_1", name: "m365-activity.csv", mediaType: "text/csv", evidenceType: "m365_activity", sizeBytes: 92143, sha256: "035daab3a9b3ca516d58ce30f361f88aff4de30dfbb50f55544f6bf16cc3ecac", status: "ready", recordCount: 26, uploadedAt: "2026-08-28T10:00:00Z" },
    ],
    detections: [
      { id: "odet_1", tenantId: "offline:offinv_demo_1", eventId: "oevt_2", eventIds: ["oevt_2"], ruleId: "single_factor_authentication", ruleVersion: 1, title: "Single-factor authentication sign-in observed", description: "A successful Entra sign-in explicitly reports a single-factor authentication requirement.", severity: "High", detectionType: "direct", confidence: "high", occurredAt: "2026-08-28T09:14:00Z", createdAt: offlineCaseNow },
      { id: "odet_2", tenantId: "offline:offinv_demo_1", eventId: "oevt_1", eventIds: ["oevt_1", "oevt_2"], ruleId: "possible_impossible_travel", ruleVersion: 1, title: "Possible impossible travel", description: "Successful sign-ins from distant locations occurred inside an implausible travel window.", severity: "High", detectionType: "correlation", confidence: "medium", occurredAt: "2026-08-28T09:14:00Z", createdAt: offlineCaseNow },
      { id: "odet_3", tenantId: "offline:offinv_demo_1", eventId: "oevt_4", eventIds: ["oevt_4"], ruleId: "authentication_method_change", ruleVersion: 1, title: "User authentication method changed", description: "A new authentication method was registered after the suspicious sign-in.", severity: "High", detectionType: "direct", confidence: "high", occurredAt: "2026-08-28T09:28:00Z", createdAt: offlineCaseNow },
      { id: "odet_4", tenantId: "offline:offinv_demo_1", eventId: "oevt_6", eventIds: ["oevt_6"], ruleId: "inbox_rule_change", ruleVersion: 1, title: "Inbox rule changed", description: "A rule was created to move and mark messages as read.", severity: "Medium", detectionType: "direct", confidence: "high", occurredAt: "2026-08-28T09:41:00Z", createdAt: offlineCaseNow },
    ],
    storylines: [
      { id: "ostory_1", packId: "account_takeover_bec", title: "Probable account takeover and mailbox persistence", summary: "A single-factor sign-in from a new location was followed by authentication-method and mailbox persistence changes.", severity: "High", riskScore: 88, confidence: "high", status: "New", firstSeen: "2026-08-28T09:11:00Z", lastSeen: "2026-08-28T09:41:00Z", updatedAt: offlineCaseNow, tenantIds: ["offline:offinv_demo_1"], tenantNames: ["Contoso Ltd"], entities: [{ type: "account", key: "offline|account|alex@contoso.com", label: "alex@contoso.com", primary: true }], stages: ["Initial Access", "Credential Access", "Persistence"], workloads: ["MicrosoftEntra", "Exchange"], detectionIds: ["odet_1", "odet_2", "odet_3", "odet_4"], eventIds: ["oevt_1", "oevt_2", "oevt_4", "oevt_6"], signalCount: 4, affectedUsers: 1, affectedResources: 2, reasons: ["Successful single-factor sign-in", "Implausible location change", "New authentication method", "Mailbox rule created"], recommendedActions: ["Reset the password and validate recent sign-ins", "Revoke active sessions", "Remove unapproved authentication methods", "Review mailbox rules"] },
    ],
    timeline: [
      { id: "oevt_7", evidenceType: "m365_activity", source: "m365_audit", workload: "Exchange", operation: "MailItemsAccessed", actor: "alex@contoso.com", clientIp: "198.51.100.77", objectId: "alex@contoso.com", resultStatus: "Succeeded", occurredAt: "2026-08-28T09:46:00Z", facts: [{ label: "Application", value: "Outlook" }, { label: "Access", value: "External" }, { label: "Affected", value: "24 items" }], signals: [] },
      { id: "oevt_6", evidenceType: "m365_activity", source: "m365_audit", workload: "Exchange", operation: "New-InboxRule", actor: "alex@contoso.com", clientIp: "198.51.100.77", objectId: "Hide security mail", resultStatus: "Succeeded", severity: "Medium", occurredAt: "2026-08-28T09:41:00Z", facts: [{ label: "Application", value: "Outlook on the web" }, { label: "Authentication", value: "OAuth" }], signals: [{ ruleId: "inbox_rule_change", title: "Inbox rule changed", severity: "Medium" }] },
      { id: "oevt_5", evidenceType: "entra_directory_audits", source: "entra_graph", workload: "MicrosoftEntra", operation: "Update user", actor: "alex@contoso.com", objectId: "alex@contoso.com", resultStatus: "success", occurredAt: "2026-08-28T09:32:00Z", facts: [{ label: "Application", value: "Microsoft Graph" }], signals: [] },
      { id: "oevt_4", evidenceType: "entra_directory_audits", source: "entra_graph", workload: "MicrosoftEntra", operation: "Add authentication method", actor: "alex@contoso.com", objectId: "alex@contoso.com", resultStatus: "success", severity: "High", occurredAt: "2026-08-28T09:28:00Z", facts: [{ label: "Application", value: "Microsoft Graph" }], signals: [{ ruleId: "authentication_method_change", title: "User authentication method changed", severity: "High" }] },
      { id: "oevt_3", evidenceType: "entra_sign_ins", source: "entra_graph", workload: "MicrosoftEntra", operation: "UserLoggedIn", actor: "alex@contoso.com", clientIp: "198.51.100.77", objectId: "Microsoft 365", resultStatus: "Succeeded", occurredAt: "2026-08-28T09:21:00Z", facts: [{ label: "Authentication", value: "singleFactorAuthentication" }, { label: "Location", value: "Seattle, WA, US" }], signals: [] },
      { id: "oevt_2", evidenceType: "entra_sign_ins", source: "entra_graph", workload: "MicrosoftEntra", operation: "UserLoggedIn", actor: "alex@contoso.com", clientIp: "198.51.100.77", objectId: "Microsoft 365", resultStatus: "Succeeded", severity: "High", occurredAt: "2026-08-28T09:14:00Z", facts: [{ label: "Authentication", value: "singleFactorAuthentication" }, { label: "Location", value: "Seattle, WA, US" }], signals: [{ ruleId: "single_factor_authentication", title: "Single-factor authentication sign-in observed", severity: "High" }, { ruleId: "possible_impossible_travel", title: "Possible impossible travel", severity: "High" }] },
      { id: "oevt_1", evidenceType: "entra_sign_ins", source: "entra_graph", workload: "MicrosoftEntra", operation: "UserLoggedIn", actor: "alex@contoso.com", clientIp: "203.0.113.18", objectId: "Microsoft 365", resultStatus: "Succeeded", severity: "High", occurredAt: "2026-08-28T09:11:00Z", facts: [{ label: "Authentication", value: "singleFactorAuthentication" }, { label: "Location", value: "Dublin, IE" }], signals: [{ ruleId: "possible_impossible_travel", title: "Possible impossible travel", severity: "High" }] },
    ],
  },
];

export function listOfflineInvestigations(): OfflineInvestigation[] {
  return structuredClone(offlineInvestigationDetails.map(({ files: _files, timeline: _timeline, detections: _detections, storylines: _storylines, ...investigation }) => investigation));
}

export function getOfflineInvestigation(id: string): OfflineInvestigationDetail | null {
  const investigation = offlineInvestigationDetails.find((item) => item.id === id);
  return investigation ? structuredClone(investigation) : null;
}

export function createOfflineInvestigation(body: { name: string; tenantLabel: string }): OfflineInvestigation {
  const now = new Date().toISOString();
  const investigation: OfflineInvestigationDetail = {
    id: `offinv_mock_${++offlineInvestigationSeq}`, name: body.name, tenantLabel: body.tenantLabel,
    status: "draft", progress: 0, createdBy: "Jordan Meyer", createdAt: now, updatedAt: now,
    eventCount: 0, detectionCount: 0, highPriorityCount: 0, storylineCount: 0, coverage: [],
    files: [], timeline: [], detections: [], storylines: [],
  };
  offlineInvestigationDetails = [investigation, ...offlineInvestigationDetails];
  const { files: _files, timeline: _timeline, detections: _detections, storylines: _storylines, ...summary } = investigation;
  return structuredClone(summary);
}

export function uploadOfflineInvestigationFile(id: string, input: File): OfflineInvestigationFile {
  const investigation = offlineInvestigationDetails.find((item) => item.id === id);
  if (!investigation) throw new Error("Offline investigation not found.");
  if (input.size > OFFLINE_EVIDENCE_MAX_FILE_BYTES) throw new Error(`${input.name} exceeds the 1 GiB per-file limit.`);
  const lower = input.name.toLowerCase();
  const evidenceType = lower.includes("signin") ? "entra_sign_ins" : lower.includes("director") ? "entra_directory_audits" : "m365_activity";
  const recordCount = Math.max(1, Math.round(input.size / 900));
  if (recordCount > OFFLINE_EVIDENCE_MAX_FILE_RECORDS) throw new Error(`${input.name} exceeds the 10 million record per-file limit.`);
  const caseBytes = investigation.files.reduce((total, file) => total + file.sizeBytes, 0) + input.size;
  const caseRecords = investigation.files.reduce((total, file) => total + file.recordCount, 0) + recordCount;
  if (caseBytes > OFFLINE_EVIDENCE_MAX_CASE_BYTES || caseRecords > OFFLINE_EVIDENCE_MAX_CASE_RECORDS) {
    throw new Error("This case exceeds the 10 GiB or 50 million record limit.");
  }
  const file: OfflineInvestigationFile = {
    id: `offile_mock_${++offlineFileSeq}`, investigationId: id, name: input.name,
    mediaType: input.type || (lower.endsWith(".csv") ? "text/csv" : "application/json"), evidenceType,
    sizeBytes: input.size, sha256: crypto.randomUUID().replaceAll("-", ""), status: "ready",
    recordCount, uploadedAt: new Date().toISOString(),
  };
  investigation.files.push(file);
  investigation.status = "ready";
  investigation.updatedAt = file.uploadedAt;
  return structuredClone(file);
}

export function analyzeOfflineInvestigation(id: string): Job {
  const investigation = offlineInvestigationDetails.find((item) => item.id === id);
  if (!investigation) throw new Error("Offline investigation not found.");
  investigation.status = "complete";
  investigation.progress = 100;
  investigation.detail = "Analysis complete";
  investigation.updatedAt = new Date().toISOString();
  investigation.analyzedAt = investigation.updatedAt;
  investigation.eventCount = investigation.files.reduce((total, file) => total + file.recordCount, 0);
  investigation.coverage = [
    { key: "entra_sign_ins", label: "Microsoft Entra sign-ins", status: investigation.files.some((file) => file.evidenceType === "entra_sign_ins") ? "partial" : "missing", records: investigation.files.filter((file) => file.evidenceType === "entra_sign_ins").reduce((total, file) => total + file.recordCount, 0), detail: "Authentication field coverage depends on the uploaded export columns" },
    { key: "entra_directory_audits", label: "Microsoft Entra directory audit", status: investigation.files.some((file) => file.evidenceType === "entra_directory_audits") ? "present" : "missing", records: investigation.files.filter((file) => file.evidenceType === "entra_directory_audits").reduce((total, file) => total + file.recordCount, 0), detail: investigation.files.some((file) => file.evidenceType === "entra_directory_audits") ? "Evidence ready for analysis" : "No evidence uploaded" },
    { key: "m365_activity", label: "Microsoft 365 activity", status: investigation.files.some((file) => file.evidenceType === "m365_activity") ? "present" : "missing", records: investigation.files.filter((file) => file.evidenceType === "m365_activity").reduce((total, file) => total + file.recordCount, 0), detail: investigation.files.some((file) => file.evidenceType === "m365_activity") ? "Evidence ready for analysis" : "No evidence uploaded" },
  ];
  return { id: `job_offline_${Date.now()}`, type: "offline_investigation_analysis", tenant: investigation.tenantLabel, status: "Completed", progress: 100, started: "Just now", duration: "0.6s", triggeredBy: "Jordan Meyer" };
}

export function deleteOfflineInvestigation(id: string): void {
  offlineInvestigationDetails = offlineInvestigationDetails.filter((item) => item.id !== id);
}

export function securityRuleConditionOptions(tenantId?: string): SecurityRuleConditionOptions {
  const events = securityEvents.filter((event) => !tenantId || event.tenantId === tenantId);
  const values = (items: Array<string | undefined>) => [...new Set(items.filter((item): item is string => !!item?.trim()))]
    .sort((left, right) => left.localeCompare(right, undefined, { sensitivity: "base" }));
  return {
    workloads: values(["AzureActiveDirectory", "Exchange", "General", "OneDrive", "SharePoint", ...events.map((event) => event.workload)]),
    operations: values([
      "Add application", "Add domain to company", "Add member to group", "Add member to role", "Add named location", "Add owner to application",
      "Add service principal credentials", "Add user", "Consent to application", "Delete named location", "Delete user",
      "FileDeleted", "FileDownloaded", "Invite external user",
      "New-InboxRule", "New-OutboundConnector", "Remove domain from company", "Remove member from group", "Remove member from role",
      "Reset user password", "Set domain authentication", "Set federation settings on domain", "Set-AntiPhishPolicy",
      "Set-InboxRule", "Set-Mailbox", "Set-MailboxAuditBypassAssociation", "Set-OrganizationConfig",
      "SharingInvitationCreated", "Suspicious activity reported", "Update authorization policy",
      "Update cross-tenant access setting", "Update domain", "Update named location", "Update role management policy",
      "Update security defaults", "Update service principal", "Update user", "UserLoggedIn", "UserLoginFailed",
      "Verify domain", ...events.map((event) => event.operation),
    ]),
    actors: values(events.map((event) => event.actor)),
    clientIps: values(events.map((event) => event.clientIp)),
    results: values(["Success", "Succeeded", "Failed", "Failure", "PartiallySucceeded", "Unknown", ...events.map((event) => event.resultStatus)]),
    objects: values(events.map((event) => event.objectId)),
    rawEvidenceTerms: values([
      "AccountEnabled", "AppRole.Value", "AuthenticationRequirement", "ClientInfoString", "ConsentContext", "Country",
      "DeliverToMailboxAndForward", "EndDateTime", "ForwardAsAttachmentTo", "ForwardTo",
      "ForwardingSmtpAddress", "ModifiedProperties", "OperationProperties", "Parameters",
      "Permission", "RedirectTo", "SessionId", "SharingType", "UserAgent", "UserType",
    ]),
    eventsScanned: events.length,
    evidenceWindowDays: 180,
    limited: false,
  };
}

export function listSecurityRules(): SecurityDetectionRule[] {
  return [...builtinSecurityRules, ...customSecurityRules].map((rule) => ({ ...rule, definition: { ...rule.definition, exclusions: rule.definition.exclusions?.map((item) => ({ ...item })) } }));
}

export function getSecurityRule(id: string): SecurityDetectionRule | null {
  return listSecurityRules().find((rule) => rule.id === id) ?? null;
}

export function previewSecurityRule(rule: SecurityDetectionRule): SecurityRulePreview {
  const matched = securityEvents.filter((event) =>
    (!rule.tenantId || rule.tenantId === event.tenantId) &&
    (!rule.definition.workloads?.length || rule.definition.workloads.some((value) => event.workload.toLowerCase().includes(value.toLowerCase()))) &&
    (!rule.definition.operations?.length || rule.definition.operations.some((value) => event.operation.toLowerCase().includes(value.toLowerCase()))),
  );
  return { matchedEvents: matched.length, eventsScanned: securityEvents.length, tenantsMatched: matched.length ? { "Contoso Ltd": matched.length } : {}, sampleEvents: matched.slice(0, 20), warnings: ["Preview scans the latest 30 days. Enabling affects future evaluation."], approvalToken: `mock-${Date.now()}` };
}

function recordSecurityRevision(rule: SecurityDetectionRule) {
  securityRuleRevisions[rule.id] ??= [];
  securityRuleRevisions[rule.id].unshift({ ruleId: rule.id, revision: rule.revision, snapshot: structuredClone(rule), actor: "Jordan Meyer", createdAt: rule.updatedAt });
}

export function createSecurityRule(input: SecurityDetectionRule): SecurityDetectionRule {
  const now = new Date().toISOString();
  const base = input.baseRuleId ? builtinSecurityRules.find((rule) => rule.ruleId === input.baseRuleId) : undefined;
  const id = `rule_mock_${Date.now()}`;
  const rule = { ...input, id, ruleId: base?.ruleId ?? `custom_${Date.now()}`, builtIn: !!base, override: !!base, locked: !!base, revision: 1, updatedBy: "Jordan Meyer", createdAt: now, updatedAt: now };
  customSecurityRules = [rule, ...customSecurityRules];
  recordSecurityRevision(rule);
  return structuredClone(rule);
}

export function updateSecurityRule(id: string, input: SecurityDetectionRule): SecurityDetectionRule {
  const index = customSecurityRules.findIndex((rule) => rule.id === id);
  if (index < 0) throw new Error("Detection rule not found.");
  const rule = { ...customSecurityRules[index], ...input, id, revision: customSecurityRules[index].revision + 1, updatedBy: "Jordan Meyer", updatedAt: new Date().toISOString() };
  customSecurityRules[index] = rule;
  recordSecurityRevision(rule);
  return structuredClone(rule);
}

export function listSecurityRuleRevisions(id: string): SecurityDetectionRuleRevision[] {
  return structuredClone(securityRuleRevisions[id] ?? []);
}

export function restoreSecurityRule(id: string, revision: number): SecurityDetectionRule {
  const target = securityRuleRevisions[id]?.find((item) => item.revision === revision);
  if (!target) throw new Error("Rule revision not found.");
  return updateSecurityRule(id, target.snapshot);
}
