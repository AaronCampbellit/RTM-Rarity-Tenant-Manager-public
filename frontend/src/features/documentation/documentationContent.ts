import {
  Activity,
  BookOpen,
  Building2,
  Cable,
  ClipboardCheck,
  CloudCog,
  FileSearch,
  History,
  KeyRound,
  LifeBuoy,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Users,
  type LucideIcon,
} from "lucide-react";

export type CalloutTone = "info" | "success" | "warning" | "danger";

export type DocumentationBlock =
  | { type: "paragraph"; text: string }
  | { type: "heading"; id: string; title: string }
  | { type: "bullets"; items: string[] }
  | { type: "steps"; items: Array<{ title: string; detail: string }> }
  | { type: "callout"; tone: CalloutTone; title: string; body: string }
  | {
      type: "screenshot";
      src: string;
      alt: string;
      title: string;
      caption: string;
    }
  | { type: "table"; columns: string[]; rows: string[][] };

export interface DocumentationGuide {
  slug: string;
  section: DocumentationSection;
  title: string;
  description: string;
  icon: LucideIcon;
  route?: string;
  routeLabel?: string;
  keywords: string[];
  blocks: DocumentationBlock[];
}

export function documentationGuideSearchText(guide: DocumentationGuide) {
  const blockText = guide.blocks.flatMap((block) => {
    switch (block.type) {
      case "paragraph":
        return [block.text];
      case "heading":
        return [block.title];
      case "bullets":
        return block.items;
      case "steps":
        return block.items.flatMap((item) => [item.title, item.detail]);
      case "callout":
        return [block.title, block.body];
      case "screenshot":
        return [block.title, block.caption, block.alt];
      case "table":
        return [...block.columns, ...block.rows.flat()];
    }
  });
  return [guide.title, guide.description, ...guide.keywords, ...blockText]
    .join(" ")
    .toLowerCase();
}

export const DOCUMENTATION_SECTION_ORDER = [
  "Setup",
  "Safe operations",
  "Tenant tools",
  "Global & security",
  "Administration & help",
] as const;

export type DocumentationSection = (typeof DOCUMENTATION_SECTION_ORDER)[number];

export interface MicrosoftPermissionReference {
  category: "Security Operations" | "Directory & Identity" | "Exchange" | "SharePoint" | "Licensing";
  resource: string;
  permission: string;
  authorization: "Application" | "Delegated (temporary)" | "Exchange RBAC";
  usedFor: string;
  requirement: string;
}

/** Least-privilege Microsoft authorization reference for every live RTM
 * feature. Keep this aligned with backend preflight and What-If requirements. */
export const MICROSOFT_PERMISSION_REFERENCE: MicrosoftPermissionReference[] = [
  { category: "Security Operations", resource: "Microsoft Graph", permission: "AuditLog.Read.All", authorization: "Application", usedFor: "One-minute successful/failed sign-ins, directory audits, identity-change detections, and the MFA registration report.", requirement: "Required for the fast identity lane and MFA readiness." },
  { category: "Security Operations", resource: "Office 365 Management APIs", permission: "ActivityFeed.Read", authorization: "Application", usedFor: "Unified Microsoft 365 audit ingestion, historical backfill, Raw Event Explorer, and RTM-native detections.", requirement: "Required for authoritative audit coverage." },
  { category: "Security Operations", resource: "Microsoft Graph", permission: "SecurityIncident.Read.All", authorization: "Application", usedFor: "Reads Defender XDR incidents and alerts into the global incident queue.", requirement: "Optional; only useful when Defender XDR is licensed and provisioned." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "User.Read.All", authorization: "Application", usedFor: "User and guest inventory, raw user detail, source-of-authority signals, mailbox identities, and SharePoint principal resolution.", requirement: "Required for directory inventory." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "Group.Read.All", authorization: "Application", usedFor: "Group inventory and group metadata.", requirement: "Required for group inventory." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "GroupMember.Read.All", authorization: "Application", usedFor: "Group membership, SharePoint group expansion, and group-based access investigation.", requirement: "Required for membership and SharePoint investigations." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "RoleManagement.Read.Directory", authorization: "Application", usedFor: "Privileged directory role membership and readiness reporting.", requirement: "Required for the privileged-roles report." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "Policy.Read.All", authorization: "Application", usedFor: "Conditional Access policy and exclusion reporting.", requirement: "Required only for Conditional Access reports." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "Application.Read.All", authorization: "Application", usedFor: "Application registration and expiring secret/certificate reporting.", requirement: "Required only for app-credential reports and related detections." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "User.ReadWrite.All", authorization: "Application", usedFor: "Block/unblock sign-in and assign/remove licenses through What-If jobs.", requirement: "Required for those directory write actions." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "User-PasswordProfile.ReadWrite.All", authorization: "Application", usedFor: "Resets Microsoft 365 user passwords and forces a password change at next sign-in. Used by Reset password and Revoke user access.", requirement: "Required for password reset. Microsoft can also require the RTM service principal to hold an appropriate Entra role for sensitive or administrator targets." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "UserAuthenticationMethod.ReadWrite.All", authorization: "Application", usedFor: "Removes registered MFA and strong-authentication methods during compromised-account containment so stolen factors cannot be reused.", requirement: "Required for the MFA step in Revoke user access." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "User.RevokeSessions.All", authorization: "Application", usedFor: "Invalidates refresh tokens and browser sign-in sessions during compromised-account containment.", requirement: "Required for the session step in Revoke user access. Microsoft notes revocation can take several minutes." },
  { category: "Directory & Identity", resource: "Microsoft Graph", permission: "GroupMember.ReadWrite.All", authorization: "Application", usedFor: "Add and remove cloud-group members through What-If jobs.", requirement: "Required for group membership writes." },
  { category: "Licensing", resource: "Microsoft Graph", permission: "Organization.Read.All", authorization: "Application", usedFor: "Subscribed SKU inventory, available capacity, and license-readiness reporting.", requirement: "Required for Licensing reads." },
  { category: "Exchange", resource: "Microsoft Graph", permission: "Reports.Read.All", authorization: "Application", usedFor: "Mailbox size, item count, archive, quota, and activity enrichment from Microsoft 365 reports.", requirement: "Optional; mailbox identity still loads without it." },
  { category: "Exchange", resource: "Microsoft Graph", permission: "MailboxSettings.ReadWrite", authorization: "Application", usedFor: "Reads and changes automatic replies, forwarding settings, and RTM-managed inbox forwarding rules.", requirement: "Required for Exchange mail-flow settings and writes." },
  { category: "Exchange", resource: "Office 365 Exchange Online", permission: "Exchange.ManageAsAppV2", authorization: "Application", usedFor: "Issues the app-only Exchange token used by the supported Admin API for Get-Mailbox and Send on Behalf.", requirement: "Required for Exchange delegate inventory and Send on Behalf changes." },
  { category: "Exchange", resource: "Exchange Online", permission: "Recipient Management", authorization: "Exchange RBAC", usedFor: "Limits the runtime Exchange application to the mailbox cmdlets RTM needs, including Get-Mailbox and Set-Mailbox.", requirement: "Required with Exchange.ManageAsAppV2." },
  { category: "Exchange", resource: "Microsoft Graph", permission: "RoleManagement.ReadWrite.Exchange", authorization: "Delegated (temporary)", usedFor: "Allows the GUI Authorize Exchange flow to create the one Recipient Management assignment.", requirement: "Bootstrap only; the token and submitted bootstrap credentials are discarded." },
  { category: "SharePoint", resource: "Microsoft Graph", permission: "Sites.Read.All", authorization: "Application", usedFor: "Discovers sites, libraries, drives, items, sharing evidence, and site permissions.", requirement: "Required for SharePoint inventory and investigations." },
  { category: "SharePoint", resource: "Microsoft Graph", permission: "Sites.ReadWrite.All", authorization: "Application", usedFor: "Manages supported drive-item permission operations from the SharePoint workspace.", requirement: "Required for supported SharePoint permission writes." },
  { category: "SharePoint", resource: "Microsoft Graph", permission: "Sites.FullControl.All", authorization: "Application", usedFor: "Grants or revokes direct site and item permissions where Microsoft requires full-control scope.", requirement: "Required for direct permission-management actions." },
  { category: "SharePoint", resource: "SharePoint Online", permission: "Sites.FullControl.All", authorization: "Application", usedFor: "Reads and changes SharePoint REST role assignments and inheritance with the RTM certificate application.", requirement: "Required for advanced SharePoint access management." },
];

function permissionRows(category: MicrosoftPermissionReference["category"]) {
  return MICROSOFT_PERMISSION_REFERENCE
    .filter((permission) => permission.category === category)
    .map((permission) => [permission.resource, permission.permission, permission.authorization, permission.usedFor, permission.requirement]);
}

export const START_STEPS = [
  {
    number: "1",
    title: "Choose a tenant",
    detail: "Confirm the active tenant before opening a tenant-scoped tool.",
    guide: "getting-started",
  },
  {
    number: "2",
    title: "Review permissions",
    detail: "Configure the required Microsoft resources, then run preflight.",
    guide: "microsoft-365-setup",
  },
  {
    number: "3",
    title: "Run What-If",
    detail: "Inspect targets, impact, permissions, warnings, and blocked rows.",
    guide: "safety-model",
  },
  {
    number: "4",
    title: "Verify and audit",
    detail: "Follow the job, inspect the change record, and confirm the audit event.",
    guide: "working-sets-changes",
  },
] as const;

export const DOCUMENTATION_GUIDES: DocumentationGuide[] = [
  {
    slug: "getting-started",
    section: "Setup",
    title: "Getting started",
    description: "Learn RTM's scope model, navigation, and the safest path through a first task.",
    icon: BookOpen,
    route: "/dashboard",
    routeLabel: "Open dashboard",
    keywords: ["dashboard", "navigation", "scope", "tenant switcher", "first login"],
    blocks: [
      {
        type: "paragraph",
        text: "RTM is an authenticated MSP operations console for Microsoft 365 and ThreatLocker. It keeps tenant context visible, separates global and tenant-scoped work, and records every sensitive action in a durable audit trail.",
      },
      { type: "heading", id: "scope", title: "Understand operating scope" },
      {
        type: "table",
        columns: ["Navigation area", "Scope", "What changes when you switch tenants"],
        rows: [
          ["Global", "All managed tenants or the MSP parent workspace", "Dashboard, Security Operations, and ThreatLocker stay global and never inherit the active tenant as a data filter."],
          ["Tenant Tools", "The active tenant", "Users, Groups, Licensing, Exchange, and SharePoint refresh for the selected tenant."],
          ["Operations", "Tenant-aware records", "Working Sets, Jobs, and Change History show the operational record for authorized work."],
          ["Governance and System", "Platform-wide", "Reports, audit, tenant administration, rules, administration, and this handbook are platform surfaces."],
        ],
      },
      { type: "heading", id: "first-task", title: "Complete a first task" },
      {
        type: "steps",
        items: [
          { title: "Select the tenant", detail: "Use the switcher in the upper-left and verify the tenant name in the header." },
          { title: "Confirm service health", detail: "Open the tenant detail page, review connection status, and run permission preflight." },
          { title: "Find the object", detail: "Use a tenant tool, filter its table, and open a detail view before selecting a write action." },
          { title: "Preview and verify", detail: "Run What-If, confirm the impact, execute, then follow the job and change record." },
        ],
      },
      {
        type: "callout",
        tone: "info",
        title: "Global does not mean writable",
        body: "Global Reports is intentionally read-only. Cross-tenant exports are available only with permission and every export is audited.",
      },
      {
        type: "callout",
        tone: "success",
        title: "Tenant tools wait for tenant context",
        body: "When RTM is restoring or switching the active tenant, tenant-scoped pages hold their requests until the tenant ID is available. A loading state is expected; a tenant tool must never fall back to an empty or previous tenant ID.",
      },
      {
        type: "screenshot",
        src: "/docs/dashboard.png",
        alt: "RTM dashboard showing global security metrics, pending work, jobs, and recent changes",
        title: "The operator landing page",
        caption: "Use the dashboard to spot security risk, active or failed jobs, pending work, and recent changes before beginning a tenant task.",
      },
    ],
  },
  {
    slug: "microsoft-365-setup",
    section: "Setup",
    title: "Microsoft 365 setup & permissions",
    description: "Register RTM, grant least-privilege Microsoft permissions, connect a tenant, and verify every enabled feature.",
    icon: Cable,
    route: "/tenants",
    routeLabel: "Open tenant setup",
    keywords: ["setup", "install", "permissions", "admin consent", "app registration", "graph", "exchange", "sharepoint", "activityfeed", "preflight"],
    blocks: [
      {
        type: "paragraph",
        text: "Use this guide before connecting a live tenant. RTM uses application permissions for unattended inventory and monitoring, one short-lived delegated permission for the optional Exchange bootstrap, and a separate SharePoint Online resource grant for advanced SharePoint administration. Grant only the rows needed for the RTM features you enable.",
      },
      { type: "heading", id: "prepare", title: "Prepare the tenant application" },
      {
        type: "steps",
        items: [
          { title: "Register the app", detail: "In the customer tenant, create or select the Entra application RTM will use and record its tenant ID and application client ID." },
          { title: "Create credentials", detail: "Create a client secret for the tenant Graph app. SharePoint's central app uses a deployment-managed certificate instead of a browser-uploaded private key." },
          { title: "Add API permissions", detail: "Add Application permissions under the exact resource shown below. A similarly named permission under another API does not authorize that resource." },
          { title: "Grant consent", detail: "Grant tenant-wide admin consent, connect the tenant in RTM, then run Permission Preflight from Tenant Detail." },
        ],
      },
      {
        type: "callout",
        tone: "warning",
        title: "Resource and permission type must match",
        body: "ActivityFeed.Read belongs to Office 365 Management APIs, Exchange.ManageAsAppV2 belongs to Office 365 Exchange Online, and SharePoint Online Sites.FullControl.All is separate from Microsoft Graph. Except for the temporary Exchange bootstrap row, select Application—not Delegated—permissions.",
      },
      { type: "heading", id: "security-operations", title: "Security Operations permissions" },
      {
        type: "table",
        columns: ["Microsoft resource", "Permission", "Type", "Used by RTM", "When needed"],
        rows: permissionRows("Security Operations"),
      },
      {
        type: "callout",
        tone: "info",
        title: "Defender is optional",
        body: "SecurityIncident.Read.All can be granted without provisioning Defender, but Microsoft will still report the Defender endpoint unavailable. AuditLog.Read.All and ActivityFeed.Read continue to provide RTM-native monitoring without a Defender license.",
      },
      { type: "heading", id: "directory-identity", title: "Directory & Identity permissions" },
      {
        type: "table",
        columns: ["Microsoft resource", "Permission", "Type", "Used by RTM", "When needed"],
        rows: permissionRows("Directory & Identity"),
      },
      { type: "heading", id: "licensing", title: "Licensing permissions" },
      {
        type: "table",
        columns: ["Microsoft resource", "Permission", "Type", "Used by RTM", "When needed"],
        rows: permissionRows("Licensing"),
      },
      { type: "heading", id: "exchange", title: "Exchange permissions and authorization" },
      {
        type: "table",
        columns: ["Microsoft resource", "Permission or role", "Type", "Used by RTM", "When needed"],
        rows: permissionRows("Exchange"),
      },
      {
        type: "paragraph",
        text: "For Exchange delegate coverage, first add Exchange.ManageAsAppV2 to the runtime tenant application and grant admin consent. Then use Authorize Exchange on Tenant Detail. The GUI uses RoleManagement.ReadWrite.Exchange only for that authorization attempt, creates the Recipient Management assignment, and discards the delegated token and bootstrap credentials. RTM currently supports Send on Behalf through Microsoft's Admin API; Full Access and Send As remain explicitly not collected because that API does not expose them.",
      },
      { type: "heading", id: "sharepoint", title: "SharePoint permissions and certificate" },
      {
        type: "table",
        columns: ["Microsoft resource", "Permission", "Type", "Used by RTM", "When needed"],
        rows: permissionRows("SharePoint"),
      },
      {
        type: "bullets",
        items: [
          "The RTM deployment owns the SharePoint application's X.509 certificate and private key; tenant administrators grant consent but never upload a private key through the RTM GUI.",
          "Add the tenant's SharePoint admin URL in the form https://<tenant>-admin.sharepoint.com so RTM can request the correct SharePoint Online resource token.",
          "The central certificate app also needs Microsoft Graph User.Read.All and GroupMember.Read.All for users, guests, and group expansion; those permissions are described in Directory & Identity above.",
        ],
      },
      { type: "heading", id: "connect-verify", title: "Connect and verify" },
      {
        type: "steps",
        items: [
          { title: "Connect tenant", detail: "Open Tenants, enter the directory ID, domain, client ID, and client secret, and choose any bounded Security Operations history import." },
          { title: "Test connection", detail: "RTM verifies that the tenant authority can issue a Microsoft Graph token before saving the live connection." },
          { title: "Run preflight", detail: "Open Tenant Detail and run Permission Preflight once. Results are stored and grouped by RTM section for later review." },
          { title: "Resolve exact rows", detail: "Fix missing consent under the resource named by RTM, grant consent, then explicitly re-run preflight to refresh the saved snapshot." },
        ],
      },
      {
        type: "callout",
        tone: "success",
        title: "Broader grants are recognized, not recommended",
        body: "Preflight recognizes conservative parent grants such as Directory.Read.All or Directory.ReadWrite.All when Microsoft includes them in the token. The setup list shows RTM's narrower feature permissions; broad directory grants do not replace AuditLog, Policy, Reports, Sites, Exchange, or Office 365 Management API consent.",
      },
    ],
  },
  {
    slug: "safety-model",
    section: "Safe operations",
    title: "Safety model",
    description: "Preview, confirm, execute, verify, and revert supported changes without losing accountability.",
    icon: ShieldCheck,
    route: "/changes",
    routeLabel: "Open change history",
    keywords: ["what-if", "preview", "execute", "revert", "approval", "audit", "job"],
    blocks: [
      {
        type: "paragraph",
        text: "RTM's write engine is built around a mandatory What-If gate. The preview is computed from current tenant state and shows the exact action, targets, required permission, risk, expected changes, warnings, skipped objects, and source-of-authority blocks before anything is queued.",
      },
      { type: "heading", id: "workflow", title: "The mandatory write workflow" },
      {
        type: "steps",
        items: [
          { title: "Preview", detail: "RTM reads current state and creates a short-lived approval token for this exact request." },
          { title: "Confirm", detail: "An authorized operator reviews risk and explicitly approves execution. This is not a separate approver queue in v1." },
          { title: "Execute", detail: "A tracked job applies the change per object with partial-failure tolerance." },
          { title: "Verify", detail: "The job, change record, execution log, correlation ID, and audit entry preserve the outcome." },
        ],
      },
      {
        type: "callout",
        tone: "danger",
        title: "The preview cannot be bypassed",
        body: "If a preview is stale, incomplete, blocked, or no longer matches the intended targets, close it and generate a new one. RTM does not expose a direct-write path.",
      },
      { type: "heading", id: "results", title: "Read preview and execution results" },
      {
        type: "table",
        columns: ["Result", "Meaning", "Operator response"],
        rows: [
          ["Successful", "The provider confirmed the requested change.", "Verify the final state and review the change record."],
          ["Skipped", "The object already matched the requested state or had no applicable work.", "Confirm the reason; no retry is normally needed."],
          ["Blocked", "RTM refused an unsafe or on-prem-mastered write before queueing it.", "Follow the resolution shown in the preview."],
          ["Failed", "The provider rejected or could not complete this object's write.", "Use the execution log and correlation ID; retry only after fixing the cause."],
        ],
      },
      { type: "heading", id: "revert", title: "Revert only when RTM has a safe snapshot" },
      {
        type: "paragraph",
        text: "Revert replays the stored before-state through the same job and audit machinery. One-way operations—such as session revocation, clear-forwarding, disable-auto-reply, SharePoint sharing-level changes, ThreatLocker restart, and approval actions—are labeled non-revertible before execution.",
      },
      {
        type: "screenshot",
        src: "/docs/users.png",
        alt: "RTM Users inventory showing hybrid identity notice, source badges, filters, and user selection controls",
        title: "Select targets from a tenant inventory",
        caption: "The Users inventory keeps the active tenant, hybrid notice, object source, and selection state visible before the What-If dialog opens.",
      },
    ],
  },
  {
    slug: "tenant-management",
    section: "Setup",
    title: "Tenant management",
    description: "Connect, test, inspect, update, and safely remove managed Microsoft 365 tenants.",
    icon: Building2,
    route: "/tenants",
    routeLabel: "Open tenants",
    keywords: ["connect tenant", "graph", "exchange", "sharepoint", "credentials", "preflight"],
    blocks: [
      {
        type: "paragraph",
        text: "Admins manage the tenant lifecycle. Each RTM tenant maps to its own Entra directory authority and may use dedicated app registrations for Graph, Exchange Online, and SharePoint—or reuse the configured global app where allowed.",
      },
      { type: "heading", id: "connect", title: "Connect a tenant" },
      {
        type: "bullets",
        items: [
          "Enter the display name, primary domain, and Microsoft directory ID.",
          "Optionally provide a tenant-specific Graph client ID and secret. Secrets are write-only and never returned to the browser.",
          "Add Exchange credentials and a SharePoint admin URL when those service connections require dedicated configuration.",
          "RTM tests the connection before completing creation and audits the lifecycle event.",
        ],
      },
      { type: "heading", id: "preflight", title: "Review permission preflight" },
      {
        type: "paragraph",
        text: "Permission preflight opens as a categorized view of the last saved result, so expanding it does not contact Microsoft. Use Run or Re-run Preflight when you intentionally want fresh harmless feature-area reads. RTM maps Microsoft 403 responses to missing consent and groups requirements under Security Operations, Directory & Identity, Exchange, SharePoint, and Licensing.",
      },
      {
        type: "callout",
        tone: "warning",
        title: "Blank secret fields preserve stored values",
        body: "In Edit Tenant Settings, leave a secret blank to keep it. Use the explicit disconnect or return-to-global-app control when you intend to remove a service-specific credential.",
      },
      { type: "heading", id: "remove", title: "Remove a tenant deliberately" },
      {
        type: "paragraph",
        text: "Tenant removal requires typing the tenant name. RTM deletes its stored credentials and associated tenant records and writes an audit event. Confirm the target carefully; this is a lifecycle operation, not a temporary disconnect.",
      },
      {
        type: "screenshot",
        src: "/docs/tenant-detail.png",
        alt: "RTM tenant detail page showing connection state, service connections, identity mode, and permission preflight",
        title: "Tenant health in one place",
        caption: "The tenant detail page combines directory identity, service connections, hybrid mode, permissions, recent work, and administrative settings.",
      },
    ],
  },
  {
    slug: "directory-licensing",
    section: "Tenant tools",
    title: "Users, groups & licensing",
    description: "Inventory identities, inspect raw attributes, and run source-aware directory actions.",
    icon: Users,
    route: "/users",
    routeLabel: "Open users",
    keywords: ["users", "groups", "license", "mfa", "raw user", "membership", "source"],
    blocks: [
      {
        type: "paragraph",
        text: "The directory tools share one tenant context and expose searchable, exportable inventories. User names open the audited raw directory object, while group rows open membership details. Source badges distinguish cloud objects from identities mastered in on-prem Active Directory.",
      },
      { type: "heading", id: "users", title: "Investigate and act on users" },
      {
        type: "bullets",
        items: [
          "Search by display name or UPN and filter by department.",
          "Open a user's name to inspect the full directory object, extension attributes, and identities. Every raw view is audited.",
          "Select one or more users to save a Working Set or run a What-If action.",
          "Supported actions include group membership, sign-in block/unblock, license assignment/removal, password reset, and compromised-user containment (password + MFA methods + sessions).",
        ],
      },
      { type: "heading", id: "groups", title: "Use the unified group inventory" },
      {
        type: "paragraph",
        text: "Groups combines Microsoft Graph results with Exchange Online inventory where Graph is incomplete. Every row identifies Graph or Exchange as its source, so distribution lists, dynamic distribution lists, and mail-enabled security metadata can live in one workspace without disguising the provider.",
      },
      { type: "heading", id: "actions", title: "Know the action boundaries" },
      {
        type: "table",
        columns: ["Action", "Cloud object", "Synced object", "Revert"],
        rows: [
          ["Add/remove cloud-group membership", "Supported", "Supported when the group is cloud-mastered", "Supported"],
          ["Membership on a synced group", "—", "Blocked; change in on-prem AD", "Not queued"],
          ["Block/unblock sign-in", "Supported", "Blocked; change in on-prem AD", "Supported for cloud users"],
          ["Assign/remove license", "Supported", "Supported; licensing is cloud-side", "Supported"],
          ["Reset password", "Supported", "Supported", "Not revertible; password shown once"],
          ["Revoke user access", "Supported", "Supported", "Not revertible; resets password, MFA methods, and sessions"],
        ],
      },
      {
        type: "screenshot",
        src: "/docs/users.png",
        alt: "Users table with MFA, source-of-authority, account status, and last sign-in columns",
        title: "Directory inventory with source-of-authority context",
        caption: "Treat the source badge as a safety signal: cloud-service actions can remain available even when core identity attributes are mastered on-prem.",
      },
    ],
  },
  {
    slug: "exchange-sharepoint",
    section: "Tenant tools",
    title: "Exchange & SharePoint",
    description: "Inspect mailbox behavior, investigate shared access, and gate service writes through What-If.",
    icon: CloudCog,
    route: "/exchange",
    routeLabel: "Open Exchange",
    keywords: ["mailbox", "forwarding", "auto reply", "delegates", "sites", "onedrive", "share detective"],
    blocks: [
      {
        type: "paragraph",
        text: "Exchange and SharePoint are tenant-scoped workspaces. They surface provider coverage honestly: unknown or uncollected state is never presented as a confirmed zero, and operations that require an unavailable admin API return NOT_IMPLEMENTED instead of guessing.",
      },
      { type: "heading", id: "exchange", title: "Review mailbox state" },
      {
        type: "bullets",
        items: [
          "Overview combines directory identity with sourced usage and quota data.",
          "Mail flow shows forwarding rules, redirects, forward-as-attachment actions, automatic replies, locale, and working hours.",
          "Access shows Full Access, Send As, and Send on Behalf only when the Exchange reader supplies them.",
          "Forwarding and automatic-reply writes use What-If. Live mailbox-permission writes remain explicit NOT_IMPLEMENTED until the Exchange admin API is available.",
        ],
      },
      {
        type: "screenshot",
        src: "/docs/exchange.png",
        alt: "Exchange mailbox inventory in RTM with mail flow, storage, delegate, and status columns",
        title: "Exchange inventory",
        caption: "Select a mailbox for its detailed overview, mail-flow configuration, and collected delegate state.",
      },
      { type: "heading", id: "sharepoint", title: "Navigate SharePoint inventory" },
      {
        type: "bullets",
        items: [
          "Sites and OneDrive use the same securable-object inventory model, with size, file totals, unique-permission markers, freshness, and scan coverage.",
          "Access Investigations embeds Share Detective for offboarding and shared-access review.",
          "Scan History records nightly and manual snapshots, progress, warnings, and partial coverage.",
          "Inherited access guides the operator to its source. Breaking inheritance is an explicit advanced operation.",
        ],
      },
      {
        type: "callout",
        tone: "warning",
        title: "Revoke only confirmed direct grants",
        body: "Share Detective classifies direct, link-based, group-based, site-membership, and inherited findings. Only confirmed direct grants are revocable from the investigation workflow.",
      },
      {
        type: "screenshot",
        src: "/docs/sharepoint-investigations.png",
        alt: "SharePoint Access Investigations tab showing offboarding investigation coverage and findings",
        title: "Share Detective access investigation",
        caption: "Coverage stays explicit per site so a partial or skipped scan cannot be mistaken for a complete access conclusion.",
      },
    ],
  },
  {
    slug: "working-sets-changes",
    section: "Safe operations",
    title: "Working sets & changes",
    description: "Reuse target collections, follow background jobs, inspect outcomes, and revert supported work.",
    icon: History,
    route: "/jobs",
    routeLabel: "Open jobs",
    keywords: ["working set", "job", "change history", "partial", "failed", "revert"],
    blocks: [
      {
        type: "paragraph",
        text: "Operations preserves both the technician's intent and the provider outcome. Working Sets are reusable target collections; Jobs track execution; Change History is the durable human-readable record of completed work and its revert support.",
      },
      { type: "heading", id: "working-sets", title: "Save repeatable scope with Working Sets" },
      {
        type: "paragraph",
        text: "Select users from an inventory and save them with a descriptive name. RTM confirms the save and retains the exact selected user IDs, tenant, description, count, and creator in its durable store, so the scope remains after reloads and service restarts. Re-open the source inventory before executing if membership may have changed.",
      },
      { type: "heading", id: "jobs", title: "Follow every job to a terminal state" },
      {
        type: "table",
        columns: ["Status", "Meaning", "Next action"],
        rows: [
          ["Queued", "Accepted and waiting for a worker.", "Monitor; do not submit a duplicate."],
          ["Running", "Provider writes are in progress.", "Wait for completion and keep the job ID."],
          ["Completed", "All applicable targets succeeded.", "Verify the change record."],
          ["Partial", "Some targets succeeded and some failed or were blocked.", "Inspect the per-object execution log before retrying."],
          ["Failed", "The job could not produce a successful target outcome.", "Use its error and correlation ID to resolve the cause."],
        ],
      },
      { type: "heading", id: "history", title: "Use Change History as the ledger" },
      {
        type: "bullets",
        items: [
          "Open a change to review before/after data, execution log, duration, technician, and correlation ID.",
          "Revert is offered only when a safe prior-state snapshot exists.",
          "A revert creates its own tracked work and marks the original record Reverted after success.",
          "Audit Logs answers who attempted the action, while Change History explains what changed and how execution ended.",
        ],
      },
      {
        type: "screenshot",
        src: "/docs/dashboard.png",
        alt: "Dashboard panels showing active and failed jobs alongside recent change records",
        title: "Operational attention at a glance",
        caption: "The dashboard is intentionally selective: it keeps queued, running, failed, and partial work visible while the Jobs page retains the full history.",
      },
    ],
  },
  {
    slug: "reports-audit",
    section: "Global & security",
    title: "Reports & audit",
    description: "Run partial-failure-tolerant cross-tenant reports and trace every sensitive action.",
    icon: ClipboardCheck,
    route: "/global-reports",
    routeLabel: "Open reports",
    keywords: ["global reports", "audit log", "csv", "correlation id", "read only", "entra readiness"],
    blocks: [
      {
        type: "paragraph",
        text: "Global Reports fans out across managed tenants with bounded concurrency and keeps tenant results separated. One unavailable tenant produces an honest partial result instead of discarding every successful tenant response.",
      },
      { type: "heading", id: "reports", title: "Choose the right report family" },
      {
        type: "bullets",
        items: [
          "Operations: MFA Status, License Usage, Inactive Users, and Guest Accounts.",
          "Connector posture: ThreatLocker Posture with an honest Not connected state.",
          "Entra readiness: License Readiness, MFA Gaps, Stale Guests, Privileged Roles, CA Exclusions, and App Credential Expiry.",
          "Exports preserve tenant labels and are audited. No write action is available from a global report.",
        ],
      },
      {
        type: "screenshot",
        src: "/docs/global-reports.png",
        alt: "Global Reports screen with read-only banner, report tabs, tenant-separated rows, and audited export",
        title: "Read-only cross-tenant reporting",
        caption: "The blue boundary and READ-ONLY label distinguish reporting from a tenant write workflow.",
      },
      { type: "heading", id: "audit", title: "Trace an action with Audit Logs" },
      {
        type: "paragraph",
        text: "Use the audit trail to correlate actor, action, target, tenant, result, timestamp, and correlation ID. Denied attempts—including hybrid source-of-authority blocks—are retained. Application logs never contain Microsoft tokens or stored secrets.",
      },
      {
        type: "callout",
        tone: "info",
        title: "Keep the correlation ID",
        body: "When reporting an API or job issue, include the visible correlation ID, tenant, timestamp, and action. Never copy client secrets, access tokens, or raw credentials into a ticket.",
      },
    ],
  },
  {
    slug: "threatlocker",
    section: "Global & security",
    title: "ThreatLocker",
    description: "Operate the parent MSP workspace, review approvals, and clean duplicate applications safely.",
    icon: ShieldAlert,
    route: "/threatlocker",
    routeLabel: "Open ThreatLocker",
    keywords: ["devices", "approvals", "policies", "applications", "cleanup", "maintenance", "restart"],
    blocks: [
      {
        type: "paragraph",
        text: "ThreatLocker is RTM's first non-Microsoft connector. It is scoped to the configured MSP parent organization and remains stable when the active Microsoft tenant changes. Tenant records do not store ThreatLocker credentials or organization IDs.",
      },
      { type: "heading", id: "workspace", title: "Use the parent-scoped workspace" },
      {
        type: "table",
        columns: ["Tab", "Use it for"],
        rows: [
          ["Devices", "Mode, group, service version, last check-in, detail, maintenance, secure, and restart actions."],
          ["Approval Requests", "Inspect pending requests and run permit or deny flows through What-If."],
          ["Apps", "Review parent and child applications, inspect files and policies, and rename applications."],
          ["Policies", "Inspect owning-organization policy details and supported edits."],
          ["Clean up", "Plan, execute, and verify native duplicate-application promotion and merge work."],
        ],
      },
      { type: "heading", id: "actions", title: "Respect public API boundaries" },
      {
        type: "bullets",
        items: [
          "Supported live device actions: enter maintenance mode, secure device, and restart agent.",
          "Supported approval actions: approve through the permit flow and deny a request.",
          "Restart and approval actions are not revertible. Maintenance mode is reverted by securing the device.",
          "Lockdown, isolation, and tamper-protection toggles are not exposed by ThreatLocker's public API and return NOT_IMPLEMENTED.",
        ],
      },
      {
        type: "callout",
        tone: "warning",
        title: "ThreatLocker has no production sample mode",
        body: "If the global parent connection is absent, the live application returns NOT_CONNECTED. Configure and test the write-only parent connection in Admin Settings before relying on the workspace. RTM loads ThreatLocker data only after you open that workspace and only for the active tab; a failed connector read is held for 15 minutes unless you explicitly refresh, which prevents the same unavailable service from flooding every page with retries.",
      },
      { type: "heading", id: "cleanup", title: "Review every cleanup plan" },
      {
        type: "paragraph",
        text: "Application cleanup may promote a reviewed child policy before a parent target exists, merge the family in the parent context, move preserved policies to the exact Global group one at a time, and verify the retained application, file rules, source removal, and bindings. Parent-pushed child policy copies are excluded with a preview warning because ThreatLocker makes them undeletable by design.",
      },
      {
        type: "screenshot",
        src: "/docs/threatlocker.png",
        alt: "ThreatLocker parent workspace displaying tabs, device inventory, modes, groups, service versions, and actions",
        title: "ThreatLocker parent workspace",
        caption: "The selected Microsoft tenant does not rescope this page; all rows belong to the configured MSP parent workspace and its managed organizations.",
      },
    ],
  },
  {
    slug: "security-operations",
    section: "Global & security",
    title: "Security Operations",
    description: "Work explainable attack storylines, triage cross-tenant detections, inspect durable evidence, and manage RTM rules.",
    icon: Activity,
    route: "/security",
    routeLabel: "Open Security Operations",
    keywords: ["incidents", "attack storylines", "correlation", "blast radius", "defender", "audit", "sign in", "detection rules", "raw events", "coverage", "deduplication"],
    blocks: [
      {
        type: "paragraph",
        text: "Security Operations is a global, cross-tenant workspace that combines Defender XDR incidents with RTM-native detections over normalized Microsoft evidence. Attack Storylines sit above the queue and connect independent signals into a reproducible attack sequence. RTM-local owner and status controls do not write back to Microsoft.",
      },
      { type: "heading", id: "coverage", title: "Read coverage before conclusions" },
      {
        type: "bullets",
        items: [
          "Microsoft Graph polls sign-ins and directory audits every minute for fast identity visibility.",
          "Microsoft 365 Management Activity backfills supported workloads every five minutes as durable evidence.",
          "Defender, fast identity, and Microsoft 365 Audit report health independently; planned sources remain labeled Planned.",
          "Feeds keep independent checkpoints and overlap safely. RTM first deduplicates by tenant and Microsoft provider record ID, then consolidates cross-source copies with the same normalized tenant, operation, actor, target, result, and 10-second occurrence window while retaining every provider alias.",
        ],
      },
      { type: "heading", id: "storylines", title: "Work the attack storyline first" },
      {
        type: "paragraph",
        text: "A storyline requires at least two independent detections; repeated copies of one rule cannot create one. The compact queue defaults to Active and lets analysts search retained storylines, filter by tenant, severity, or status, and sort by risk, activity, or title so resolved and dismissed investigations remain easy to revisit. Correlation is deterministic and evidence-backed: the detail drawer explains the score, attack-stage sequence, affected tenants and entities, workloads, supporting detections and events, weak evidence, and recommended containment steps. Late evidence updates the same stable storyline without discarding analyst ownership or status.",
      },
      {
        type: "table",
        columns: ["Correlation pack", "Signals RTM connects"],
        rows: [
          ["Account takeover / BEC", "Suspicious sign-in activity followed by persistence or abuse such as inbox rules, forwarding, delegation, or mail-flow changes."],
          ["Privilege escalation and persistence", "Application, credential, consent, directory-role, privileged-group, guest, and identity changes around the same principal or resource."],
          ["Data theft", "Suspicious identity context followed by bulk access, download, sharing, deletion, or permission activity in SharePoint or OneDrive."],
          ["Defense evasion", "Audit configuration changes, evidence searches, repeated administrative failures, connectors, and transport changes that reduce visibility or control."],
          ["MSP administrator compromise", "Independent suspicious administrative activity by the same normalized administrator across managed tenants; a shared client IP alone is never enough."],
        ],
      },
      {
        type: "steps",
        items: [
          { title: "Read the explanation", detail: "Confirm why RTM linked the signals, the stage progression, confidence, weak evidence, and affected blast radius." },
          { title: "Inspect the evidence chain", detail: "Review every underlying detection and normalized event before treating correlation as proof of compromise." },
          { title: "Accept and assign", detail: "Accept the storyline to assign it to yourself and move it from New to In Progress, or set an explicit workflow state." },
          { title: "Contain safely", detail: "Use the recommended actions as guidance; every tenant change must still use RTM's What-If, approval, execution, and audit controls." },
        ],
      },
      {
        type: "callout",
        tone: "warning",
        title: "Correlation is an explanation, not a verdict",
        body: "Risk is a bounded 0–100 deterministic score built from retained facts such as severity, confidence, independent rule families, stage and workload breadth, tenant impact, proximity, and novelty. Analysts must validate the complete evidence chain and any conflicting or weak evidence.",
      },
      { type: "heading", id: "triage", title: "Triage from the incident queue" },
      {
        type: "steps",
        items: [
          { title: "Filter", detail: "Narrow by tenant, severity, RTM status, entity, provider source, rule ID, or classification." },
          { title: "Inspect", detail: "Open the evidence drawer for entities, alerts, timeline, provider state, and native rule metadata." },
          { title: "Assign", detail: "Set RTM-local ownership and workflow status without changing the provider incident." },
          { title: "Correlate", detail: "Use the parent storyline when one exists, then open Raw Event Explorer for retained, redacted source evidence and related detections." },
        ],
      },
      { type: "heading", id: "raw-events", title: "Inspect raw evidence without losing the workspace" },
      {
        type: "paragraph",
        text: "Raw Event Explorer searches normalized evidence across managed tenants and exposes the redacted provider payload for investigation. Older or partial records are normalized before rendering, so missing sources, related detections, or raw fields show as empty evidence instead of crashing the page. If an unexpected rendering failure still occurs, RTM contains it to the current route and offers Retry or Dashboard recovery rather than blanking the entire console.",
      },
      { type: "heading", id: "rules", title: "Manage detection rules deliberately" },
      {
        type: "paragraph",
        text: "Admins manage 53 locked built-ins through scoped overrides and can create direct or threshold custom rules with exclusions. Native severity combines likely impact with evidence strength, while confidence remains separate. Enablement changes are preview-gated against bounded history, and immutable revisions support restore.",
      },
      {
        type: "screenshot",
        src: "/docs/security-operations.png",
        alt: "Security Operations screen showing incident metrics, connector coverage, filters, and a cross-tenant incident queue",
        title: "Cross-tenant security triage",
        caption: "Start with connector health, then severity and incident context. A healthy queue still needs per-tenant coverage review.",
      },
    ],
  },
  {
    slug: "hybrid-identity",
    section: "Tenant tools",
    title: "Hybrid identity",
    description: "Recognize source of authority and keep cloud work moving without fighting on-prem sync.",
    icon: KeyRound,
    route: "/users",
    routeLabel: "Review user sources",
    keywords: ["hybrid", "mixed", "on-prem", "source of authority", "entra connect", "synced"],
    blocks: [
      {
        type: "paragraph",
        text: "RTM uses the tenant organization's on-premises sync signal as the authoritative cloud-versus-hybrid indicator and object-level source metadata to refine hybrid tenants into mixed environments. The notice is informational: cloud work stays available while on-prem-mastered writes fail closed.",
      },
      { type: "heading", id: "modes", title: "Interpret identity mode" },
      {
        type: "table",
        columns: ["Mode", "Meaning"],
        rows: [
          ["Cloud", "The organization reports no on-prem sync; directory objects are managed in Entra and Microsoft 365."],
          ["Hybrid", "The organization reports sync and inventory is entirely or predominantly on-prem-mastered."],
          ["Mixed", "The tenant uses sync and also contains cloud-only users or groups; evaluate each object."],
          ["Unknown", "RTM could not obtain enough organization or object evidence. Treat write assumptions cautiously."],
        ],
      },
      { type: "heading", id: "allowed", title: "Keep cloud-side work available" },
      {
        type: "bullets",
        items: [
          "Licensing and session revocation remain usable for synced users.",
          "Exchange mailbox settings and SharePoint access remain cloud service operations.",
          "Membership changes remain usable when the target group is cloud-mastered.",
          "Sign-in block/unblock on synced users and membership changes on synced groups are blocked before a job is queued.",
        ],
      },
      {
        type: "callout",
        tone: "warning",
        title: "Follow the source of authority",
        body: "When RTM blocks a synced object, make the change in on-prem Active Directory and allow Entra synchronization to update Microsoft 365. Do not retry the same cloud write.",
      },
      {
        type: "screenshot",
        src: "/docs/users.png",
        alt: "Mixed identity tenant Users page with a prominent hybrid notice and Cloud and On-prem AD source badges",
        title: "Hybrid context stays visible",
        caption: "The tenant notice explains the boundary, while each row's source badge provides the object-level decision signal.",
      },
    ],
  },
  {
    slug: "administration",
    section: "Administration & help",
    title: "Administration",
    description: "Manage technicians, role policy, service settings, credentials, and session security.",
    icon: Settings,
    route: "/admin",
    routeLabel: "Open Admin Settings",
    keywords: ["admin", "technician", "roles", "permissions", "password", "settings", "session"],
    blocks: [
      {
        type: "paragraph",
        text: "RTM v1 has two roles. Every authenticated operator can read every managed tenant; Admins additionally control tenant lifecycle, technician accounts, role policy, platform settings, write execution, and security-rule management.",
      },
      { type: "heading", id: "technicians", title: "Manage technician accounts" },
      {
        type: "bullets",
        items: [
          "Inviting a technician produces a one-time temporary password that is shown once and must be rotated at first sign-in.",
          "Admins can edit role and status, delete an account, or issue a confirmed password reset.",
          "Password reset revokes all older access and refresh tokens immediately.",
          "Operators change their own password from the account menu by confirming the current password; the current browser receives fresh credentials.",
        ],
      },
      { type: "heading", id: "roles", title: "Review role capabilities" },
      {
        type: "paragraph",
        text: "Role cards show descriptions and named elevated capabilities. Technician capabilities are editable; Admin capabilities are visibly locked while the Admin description remains editable. Every save is explicit and audited.",
      },
      { type: "heading", id: "connections", title: "Configure global connections" },
      {
        type: "paragraph",
        text: "Admin Settings stores application settings and the write-only ThreatLocker MSP parent connection. Tenant-specific Microsoft credentials belong to the tenant lifecycle flow, not global ThreatLocker configuration. Never expect a saved secret to be displayed back to the browser.",
      },
      {
        type: "callout",
        tone: "success",
        title: "Credential fields are intentionally write-only",
        body: "A blank value is not evidence that RTM lost a secret. Use connection status and an explicit test to verify configuration without exposing credential material.",
      },
    ],
  },
  {
    slug: "troubleshooting",
    section: "Administration & help",
    title: "Troubleshooting",
    description: "Use status, provider errors, permission evidence, jobs, and correlation IDs to resolve issues safely.",
    icon: LifeBuoy,
    route: "/jobs",
    routeLabel: "Review jobs",
    keywords: ["error", "not connected", "not implemented", "403", "failed", "partial", "correlation", "password"],
    blocks: [
      {
        type: "paragraph",
        text: "Begin with the smallest reliable evidence: active tenant, service connection, permission preflight, job status, execution log, audit result, and correlation ID. Avoid repeating a write until you know whether any targets already succeeded.",
      },
      { type: "heading", id: "errors", title: "Interpret common errors" },
      {
        type: "table",
        columns: ["Signal", "What it usually means", "Next step"],
        rows: [
          ["NOT_CONNECTED (409)", "The required global or tenant service connection is absent.", "Open Tenant Detail or Admin Settings, configure it, and run a connection test."],
          ["NOT_IMPLEMENTED", "The live provider API does not safely expose this operation yet.", "Use the provider's supported administrative surface; do not keep retrying."],
          ["403 / missing consent", "The app lacks a required read permission or admin consent.", "Run permission preflight and grant the named permission in the correct tenant and resource API."],
          ["Partial job", "Some objects changed and others did not.", "Inspect every per-object result before previewing a targeted retry."],
          ["PASSWORD_CHANGE_REQUIRED", "The account is using bootstrap or temporary credentials.", "Complete the forced password rotation; other APIs remain locked until then."],
        ],
      },
      { type: "heading", id: "checklist", title: "Collect a safe support bundle" },
      {
        type: "bullets",
        items: [
          "Timestamp and timezone, RTM route, active tenant, and operator role.",
          "The exact action and target count, plus preview risk and any warnings or blocks.",
          "Job ID, change ID, audit action, and correlation ID.",
          "A screenshot with secrets and personal data minimized.",
          "Never include access tokens, refresh tokens, client secrets, temporary passwords, or raw credential values.",
        ],
      },
      {
        type: "callout",
        tone: "danger",
        title: "Do not retry blind",
        body: "A network error can occur after the provider accepted some writes. Check the job and change record first so a retry does not duplicate or reverse successful work.",
      },
    ],
  },
  {
    slug: "feature-map",
    section: "Administration & help",
    title: "Platform feature map",
    description: "See every major RTM workspace, its scope, provider, and write posture in one reference.",
    icon: FileSearch,
    keywords: ["all features", "map", "module", "provider", "scope", "reference"],
    blocks: [
      {
        type: "paragraph",
        text: "Use this reference when you know the operational question but are unsure which RTM workspace owns it. Global surfaces never silently inherit tenant scope, and tenant tools always use the active tenant shown in the shell.",
      },
      { type: "heading", id: "map", title: "Workspace reference" },
      {
        type: "table",
        columns: ["Workspace", "Scope", "Primary provider or store", "Write posture"],
        rows: [
          ["Dashboard", "Global summary", "RTM stores and security snapshot", "Navigation only"],
          ["Security Operations", "All tenants", "Defender, Graph audit, M365 Management Activity, RTM correlation store", "Storyline and incident triage are RTM-local; containment remains What-If gated"],
          ["ThreatLocker", "MSP parent", "ThreatLocker public portal API", "What-If gated supported actions"],
          ["Users / Groups / Licensing", "Active tenant", "Microsoft Graph plus Exchange group inventory", "What-If gated and source-aware"],
          ["Exchange", "Active tenant", "Graph mailbox settings; future EXO admin APIs", "What-If; unsupported live admin writes are explicit"],
          ["SharePoint", "Active tenant", "Graph and SharePoint admin surfaces", "What-If; investigation revokes are admin-only"],
          ["Working Sets / Jobs / Changes", "Authorized operations", "RTM store and River worker", "Tracks and reverts supported work"],
          ["Global Reports", "All tenants", "Bounded provider fan-out", "Read-only; exports audited"],
          ["Audit Logs", "Platform", "Separate audit store", "Read-only evidence"],
          ["Detection Rules", "Platform", "RTM Security Operations", "Admin changes are preview-gated and versioned"],
          ["Admin Settings", "Platform", "RTM settings and credential store", "Admin-only, explicit, audited"],
        ],
      },
      {
        type: "screenshot",
        src: "/docs/dashboard.png",
        alt: "Full RTM shell with navigation grouped into Global, Tenant Tools, Operations, Governance, and System",
        title: "Navigation follows operating scope",
        caption: "The left rail is organized by scope first, then by workflow, so the active tenant only affects the tools that are safe to rescope.",
      },
    ],
  },
];
