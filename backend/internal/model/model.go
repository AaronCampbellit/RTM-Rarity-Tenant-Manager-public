// Package model holds the API entity types shared by the store, the Graph
// provider, and the HTTP handlers. JSON shapes match the frontend types
// (the /api/v1 contract).
package model

import (
	"encoding/json"
	"time"
)

// ---- RTM-owned entities (persisted in Postgres) ----

type Tenant struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Domain            string            `json:"domain"`
	MicrosoftTenantID string            `json:"microsoftTenantId"`
	Status            string            `json:"status"`
	Users             int               `json:"users"`
	LastGraphTest     string            `json:"lastGraphTest"`
	Modules           []string          `json:"modules"`
	Connections       TenantConnections `json:"connections"`

	// Hybrid identity summary — computed on demand for the tenant detail view
	// (omitted from the list endpoint, which stays a cheap store read). See
	// SourceOfAuthority constants. IdentityMode is one of "cloud", "hybrid"
	// (all synced), "mixed" (both), or "unknown" (couldn't determine).
	IdentityMode string `json:"identityMode,omitempty"`
	SyncedUsers  int    `json:"syncedUsers,omitempty"`
	CloudUsers   int    `json:"cloudUsers,omitempty"`
	SyncedGroups int    `json:"syncedGroups,omitempty"`
	CloudGroups  int    `json:"cloudGroups,omitempty"`
}

// Source-of-authority values for a directory object. Objects mastered by an
// on-prem Active Directory (synced up to Entra via Entra Connect) must be
// changed on-prem; RTM only edits their cloud-authoritative facets.
const (
	SourceCloud   = "cloud"   // created/managed in Entra ID — RTM can write directory changes
	SourceOnPrem  = "on_prem" // synced from on-prem AD — directory identity is mastered there
	SourceUnknown = "unknown" // sync state could not be determined
)

// Identity modes for a tenant, derived from its objects' source of authority.
const (
	IdentityCloud   = "cloud"
	IdentityHybrid  = "hybrid"
	IdentityMixed   = "mixed"
	IdentityUnknown = "unknown"
)

// TenantConnections reports which service integrations have a dedicated
// per-tenant app registration stored (true) versus inheriting the tenant's
// Graph app / the global app (false). Booleans only — never the credentials
// themselves, which are write-only.
type TenantConnections struct {
	Graph      bool `json:"graph"`      // dedicated Graph app (else global/sample)
	Exchange   bool `json:"exchange"`   // dedicated Exchange Online app (else inherits Graph)
	SharePoint bool `json:"sharePoint"` // SharePoint admin URL configured for the central certificate app
}

type WorkingSet struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Items       int      `json:"items"`
	TenantID    string   `json:"tenantId"`
	Tenant      string   `json:"tenant"`
	UserIDs     []string `json:"userIds"`
	CreatedBy   string   `json:"createdBy"`
	LastUsed    string   `json:"lastUsed"`
}

type Job struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Tenant       string `json:"tenant"`
	Status       string `json:"status"`
	Progress     int    `json:"progress"`
	Started      string `json:"started"`
	Duration     string `json:"duration"`
	TriggeredBy  string `json:"triggeredBy"`
	Acknowledged bool   `json:"acknowledged"`
}

type Change struct {
	ID         string `json:"id"`
	Timestamp  string `json:"timestamp"`
	Technician string `json:"technician"`
	Tenant     string `json:"tenant"`
	Action     string `json:"action"`
	Target     string `json:"target"`
	Status     string `json:"status"`
	Revert     string `json:"revert"`
}

type ChangeDetail struct {
	Change
	GraphRequestID string   `json:"graphRequestId"`
	RevertEligible bool     `json:"revertEligible"`
	Before         []string `json:"before"`
	After          []string `json:"after"`
	ExecutionLog   []string `json:"executionLog"`
	// RevertPayload is the job payload that undoes this change (set by the
	// worker when the action is revertible).
	RevertPayload string `json:"revertPayload,omitempty"`
}

type AuditEntry struct {
	ID            string `json:"id"`
	Timestamp     string `json:"timestamp"`
	Actor         string `json:"actor"`
	Action        string `json:"action"`
	Resource      string `json:"resource"`
	Result        string `json:"result"`
	CorrelationID string `json:"correlationId"`
}

type Technician struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Email              string `json:"email"`
	Role               string `json:"role"`
	Tenants            string `json:"tenants"`
	Status             string `json:"status"`
	LastActive         string `json:"lastActive"`
	MustChangePassword bool   `json:"mustChangePassword"`
}

type Role struct {
	Name                 string   `json:"name"`
	Description          string   `json:"description"`
	Permissions          string   `json:"permissions"`
	PermissionKeys       []string `json:"permissionKeys"`
	LockedPermissionKeys []string `json:"lockedPermissionKeys,omitempty"`
	Level                string   `json:"level"`
	LevelTone            string   `json:"levelTone"`
	Assigned             int      `json:"assigned"`
}

type AppSetting struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Locked      bool   `json:"locked,omitempty"`
	Value       string `json:"value,omitempty"`
}

type DashboardStat struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Delta string `json:"delta"`
	Tone  string `json:"tone"`
}

type Approval struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Tenant string `json:"tenant"`
	By     string `json:"by"`
	Risk   string `json:"risk"`
}

type TenantAccessRow struct {
	Technician string `json:"technician"`
	Role       string `json:"role"`
	Access     []bool `json:"access"`
}

type TenantAccessMatrix struct {
	Tenants []string          `json:"tenants"`
	Rows    []TenantAccessRow `json:"rows"`
}

// ---- Microsoft-sourced entities (from the Graph provider) ----

type User struct {
	ID                         string   `json:"id"`
	Name                       string   `json:"name"`
	GivenName                  string   `json:"givenName"`
	Surname                    string   `json:"surname"`
	UPN                        string   `json:"upn"`
	Mail                       string   `json:"mail"`
	UserType                   string   `json:"userType"`
	Department                 string   `json:"department"`
	JobTitle                   string   `json:"jobTitle"`
	CompanyName                string   `json:"companyName"`
	OfficeLocation             string   `json:"officeLocation"`
	EmployeeID                 string   `json:"employeeId"`
	EmployeeType               string   `json:"employeeType"`
	BusinessPhones             []string `json:"businessPhones"`
	MobilePhone                string   `json:"mobilePhone"`
	StreetAddress              string   `json:"streetAddress"`
	City                       string   `json:"city"`
	State                      string   `json:"state"`
	PostalCode                 string   `json:"postalCode"`
	Country                    string   `json:"country"`
	UsageLocation              string   `json:"usageLocation"`
	PreferredLanguage          string   `json:"preferredLanguage"`
	CreatedDateTime            string   `json:"createdDateTime"`
	OnPremisesSAMAccountName   string   `json:"onPremisesSamAccountName"`
	OnPremisesLastSyncDateTime string   `json:"onPremisesLastSyncDateTime"`
	License                    string   `json:"license"`
	Licenses                   []string `json:"licenses"`
	MFA                        string   `json:"mfa"`
	Status                     string   `json:"status"`
	LastSignIn                 string   `json:"lastSignIn"`
	LastSignInAvailable        bool     `json:"lastSignInAvailable"`
	// SourceOfAuthority is "cloud", "on_prem", or "unknown" (see constants).
	// Synced (on_prem) users cannot have their directory identity edited from
	// RTM — the write gate blocks those actions.
	SourceOfAuthority string `json:"sourceOfAuthority,omitempty"`
}

type Group struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Membership string `json:"membership"`
	Members    int    `json:"members"`
	Mail       string `json:"mail"`
	Service    string `json:"service"`
	Source     string `json:"source"`
}

type GroupMember struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	UPN   string `json:"upn"`
	Role  string `json:"role"`
	Added string `json:"added"`
}

type License struct {
	// SkuID is the Microsoft GUID used by assignLicense; SKU is the
	// human-readable part number (SPE_E5, …).
	SkuID       string `json:"skuId"`
	SKU         string `json:"sku"`
	Product     string `json:"product"`
	Assigned    int    `json:"assigned"`
	Available   int    `json:"available"`
	Total       int    `json:"total"`
	Utilization int    `json:"utilization"`
	Pool        string `json:"pool"`
}

type Mailbox struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	UserPrincipalName string   `json:"userPrincipalName"`
	Aliases           []string `json:"aliases"`
	Type              string   `json:"type"`
	AccountStatus     string   `json:"accountStatus"`
	SourceOfAuthority string   `json:"sourceOfAuthority"`
	CreatedAt         string   `json:"createdAt"`
	LicenseCount      int      `json:"licenseCount"`
	Size              string   `json:"size"`
	Items             int      `json:"items"`
	Archive           string   `json:"archive"`
	LitigationHold    string   `json:"litigationHold"`
	UsageAvailable    bool     `json:"usageAvailable"`
	UsageAsOf         string   `json:"usageAsOf"`
	LastActivityAt    string   `json:"lastActivityAt"`
	DeletedItems      int      `json:"deletedItems"`
	DeletedSize       string   `json:"deletedSize"`
	WarningQuota      string   `json:"warningQuota"`
	SendQuota         string   `json:"sendQuota"`
	SendReceiveQuota  string   `json:"sendReceiveQuota"`
	UsageDetail       string   `json:"usageDetail"`
}

// MailboxSettings is the Exchange detail view for one mailbox: auto-reply
// state and message plus mail forwarding (RTM-managed inbox rule in live
// mode). Read via MailboxSettings.Read; written by the auto-reply and
// forwarding write actions.
type MailboxSettings struct {
	MailboxID                      string                  `json:"mailboxId"`
	AutoReply                      bool                    `json:"autoReply"`
	AutoReplyStatus                string                  `json:"autoReplyStatus"`
	AutoReplyMessage               string                  `json:"autoReplyMessage"`
	ExternalAutoReplyMessage       string                  `json:"externalAutoReplyMessage"`
	ExternalAudience               string                  `json:"externalAudience"`
	AutoReplyStart                 string                  `json:"autoReplyStart"`
	AutoReplyEnd                   string                  `json:"autoReplyEnd"`
	ForwardingTo                   string                  `json:"forwardingTo"` // legacy RTM-managed forwarding target
	ForwardingRules                []MailboxForwardingRule `json:"forwardingRules"`
	RulesAvailable                 bool                    `json:"rulesAvailable"`
	RulesDetail                    string                  `json:"rulesDetail"`
	TimeZone                       string                  `json:"timeZone"`
	Language                       string                  `json:"language"`
	DateFormat                     string                  `json:"dateFormat"`
	TimeFormat                     string                  `json:"timeFormat"`
	WorkingDays                    []string                `json:"workingDays"`
	WorkingHoursStart              string                  `json:"workingHoursStart"`
	WorkingHoursEnd                string                  `json:"workingHoursEnd"`
	WorkingHoursTimeZone           string                  `json:"workingHoursTimeZone"`
	UserPurpose                    string                  `json:"userPurpose"`
	DelegateMeetingMessageDelivery string                  `json:"delegateMeetingMessageDelivery"`
}

// MailboxForwardingRule is a forwarding or redirect action observed in the
// mailbox's Inbox rules. ManagedByRTM distinguishes RTM's own reversible rule
// from rules created by a user or another administrator.
type MailboxForwardingRule struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	HasError     bool     `json:"hasError"`
	ReadOnly     bool     `json:"readOnly"`
	Mode         string   `json:"mode"`
	Recipients   []string `json:"recipients"`
	ManagedByRTM bool     `json:"managedByRtm"`
}

// MailboxPermission is one delegate entry on a mailbox (Full Access, Send As,
// or Send on Behalf — the Exchange coverage set from the Graph guide).
type MailboxPermission struct {
	ID          string `json:"id"`
	Delegate    string `json:"delegate"`
	DelegateUPN string `json:"delegateUpn"`
	Permission  string `json:"permission"` // "Full Access" | "Send As" | "Send on Behalf"
	Granted     string `json:"granted"`
}

// MailboxPermissionCoverage prevents an empty delegate list from being
// mistaken for complete coverage. Exchange's supported Admin REST API can
// currently read Send on Behalf, while Full Access and Send As still require
// Exchange Online PowerShell.
type MailboxPermissionCoverage struct {
	Permission string `json:"permission"`
	Status     string `json:"status"` // "collected" | "not_supported"
	Source     string `json:"source"`
	Detail     string `json:"detail,omitempty"`
}

type MailboxPermissionFeed struct {
	Permissions []MailboxPermission         `json:"permissions"`
	Coverage    []MailboxPermissionCoverage `json:"coverage"`
}

// SitePermission is one principal's access to a SharePoint site (owners,
// members, visitors, direct grants, external users, sharing links).
type SitePermission struct {
	ID           string `json:"id"`
	Principal    string `json:"principal"`
	PrincipalUPN string `json:"principalUpn"`
	Type         string `json:"type"`   // "User" | "Group" | "External" | "App" | "Link"
	Role         string `json:"role"`   // "Read" | "Edit" | "Full Control"
	Source       string `json:"source"` // "Owners" | "Members" | "Visitors" | "Direct" | "Sharing link"
}

type Site struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	Template        string `json:"template"`
	Storage         string `json:"storage"`
	Files           int    `json:"files"`
	ExternalSharing string `json:"externalSharing"`
}

// SharePointScan is one persisted inventory run. Scope is "sites" or
// "onedrive"; file-permission runs are explicit and carry a SiteID/NodeID.
// Counts and coverage describe only what Microsoft actually returned.
type SharePointScan struct {
	ID                    string   `json:"id"`
	TenantID              string   `json:"tenantId"`
	Scope                 string   `json:"scope"` // sites | onedrive | file_permissions
	SiteID                string   `json:"siteId,omitempty"`
	NodeID                string   `json:"nodeId,omitempty"`
	Status                string   `json:"status"`  // queued | running | completed | partial | failed
	Trigger               string   `json:"trigger"` // manual | nightly | on_demand
	StartedBy             string   `json:"startedBy"`
	StartedAt             string   `json:"startedAt"`
	CompletedAt           string   `json:"completedAt,omitempty"`
	Coverage              string   `json:"coverage"` // pending | complete | partial | failed
	SiteCount             int      `json:"siteCount"`
	LibraryCount          int      `json:"libraryCount"`
	FolderCount           int      `json:"folderCount"`
	FileCount             int      `json:"fileCount"`
	TotalBytes            int64    `json:"totalBytes"`
	UniquePermissionCount int      `json:"uniquePermissionCount"`
	Warnings              []string `json:"warnings"`
	Error                 string   `json:"error,omitempty"`
}

// SharePointInventoryNode is a normalized site/library/folder/file row from a
// completed snapshot. Baseline scans persist sites, libraries, and folders;
// file rows are added only by an explicit file-permission scan.
type SharePointInventoryNode struct {
	ID                   string `json:"id"`
	TenantID             string `json:"tenantId"`
	ScanID               string `json:"scanId"`
	ParentID             string `json:"parentId,omitempty"`
	SiteID               string `json:"siteId,omitempty"`
	DriveID              string `json:"driveId,omitempty"`
	ItemID               string `json:"itemId,omitempty"`
	Kind                 string `json:"kind"` // site | library | folder | file
	Name                 string `json:"name"`
	Path                 string `json:"path"`
	WebURL               string `json:"webUrl,omitempty"`
	SizeBytes            int64  `json:"sizeBytes"`
	FileCount            int    `json:"fileCount"`
	HasUniquePermissions bool   `json:"hasUniquePermissions"`
	ExternalSharing      string `json:"externalSharing,omitempty"`
	LastScannedAt        string `json:"lastScannedAt"`
}

// SharePointInventory is the latest completed snapshot for one tenant/scope.
type SharePointInventory struct {
	Scan  SharePointScan            `json:"scan"`
	Nodes []SharePointInventoryNode `json:"nodes"`
}

// SharePointPermissionTarget identifies one site/library/folder/file scope.
type SharePointPermissionTarget struct {
	SiteID  string `json:"siteId"`
	DriveID string `json:"driveId,omitempty"`
	ItemID  string `json:"itemId,omitempty"`
	Kind    string `json:"kind"`
	Path    string `json:"path"`
}

// SharePointScopePermission is one normalized role assignment at any scope.
type SharePointScopePermission struct {
	ID           string                      `json:"id"`
	PrincipalID  string                      `json:"principalId"`
	Principal    string                      `json:"principal"`
	PrincipalUPN string                      `json:"principalUpn,omitempty"`
	Type         string                      `json:"type"` // User | Guest | Security Group | Microsoft 365 Group | SharePoint Group | Link
	Role         string                      `json:"role"`
	Source       string                      `json:"source"` // Direct | Inherited from <path>
	Inherited    bool                        `json:"inherited"`
	Expandable   bool                        `json:"expandable"`
	MemberCount  int                         `json:"memberCount,omitempty"`
	SourceTarget *SharePointPermissionTarget `json:"sourceTarget,omitempty"`
}

// SharePointPermissionChange is one approved permission mutation. When a
// target inherits, SourceTarget identifies the parent assignment RTM guides
// the operator to; BreakInheritance must be explicitly true for a local break.
type SharePointPermissionChange struct {
	Target           SharePointPermissionTarget `json:"target"`
	PrincipalID      string                     `json:"principalId"`
	PrincipalUPN     string                     `json:"principalUpn,omitempty"`
	PrincipalType    string                     `json:"principalType,omitempty"`
	Role             string                     `json:"role"`
	Operation        string                     `json:"operation"` // grant | revoke | restore_inheritance
	BreakInheritance bool                       `json:"breakInheritance"`
	CopyAssignments  bool                       `json:"copyAssignments"`
}

type SharePointPermissionRequest struct {
	Target           SharePointPermissionTarget `json:"target"`
	PrincipalID      string                     `json:"principalId"`
	PrincipalUPN     string                     `json:"principalUpn,omitempty"`
	PrincipalType    string                     `json:"principalType,omitempty"`
	Role             string                     `json:"role"`
	Operation        string                     `json:"operation"`
	BreakInheritance bool                       `json:"breakInheritance"`
	CopyAssignments  bool                       `json:"copyAssignments"`
	ApprovalToken    string                     `json:"approvalToken,omitempty"`
}

type SharePointPermissionPreview struct {
	Target            SharePointPermissionTarget  `json:"target"`
	EffectiveTarget   *SharePointPermissionTarget `json:"effectiveTarget,omitempty"`
	Principal         string                      `json:"principal"`
	Operation         string                      `json:"operation"`
	Role              string                      `json:"role"`
	Before            []SharePointScopePermission `json:"before"`
	Warnings          []string                    `json:"warnings"`
	Blocked           []string                    `json:"blocked"`
	BreaksInheritance bool                        `json:"breaksInheritance"`
	Risk              string                      `json:"risk"`
	ApprovalToken     string                      `json:"approvalToken"`
}

type SharePointPermissionResult struct {
	Status   string `json:"status"`
	ChangeID string `json:"changeId"`
}

// ---- Microsoft security operations (Defender XDR + RTM triage) ----

// SecurityIncident is the normalized incident row used by the cross-tenant
// Security Operations queue. Microsoft remains the incident source of truth;
// Status and Owner are RTM-local triage fields, while ProviderStatus and
// ProviderOwner preserve the workflow values Microsoft Defender XDR reported.
type SecurityIncident struct {
	ID             string                   `json:"id"`
	TenantID       string                   `json:"tenantId"`
	TenantName     string                   `json:"tenantName"`
	Title          string                   `json:"title"`
	Description    string                   `json:"description,omitempty"`
	Severity       string                   `json:"severity"`
	Status         string                   `json:"status"`
	ProviderStatus string                   `json:"providerStatus"`
	Classification string                   `json:"classification,omitempty"`
	Determination  string                   `json:"determination,omitempty"`
	ProviderOwner  string                   `json:"providerOwner,omitempty"`
	Owner          string                   `json:"owner,omitempty"`
	Source         string                   `json:"source"`
	DetectionType  string                   `json:"detectionType,omitempty"`
	Confidence     string                   `json:"confidence,omitempty"`
	RuleID         string                   `json:"ruleId,omitempty"`
	RuleVersion    int                      `json:"ruleVersion,omitempty"`
	AlertCount     int                      `json:"alertCount"`
	EntityCount    int                      `json:"entityCount"`
	Entities       []SecurityEntity         `json:"entities,omitempty"`
	Evidence       *SecurityEvidenceSummary `json:"evidence,omitempty"`
	RTMReceivedAt  string                   `json:"rtmReceivedAt"`
	CreatedAt      string                   `json:"createdAt"`
	UpdatedAt      string                   `json:"updatedAt"`
	IncidentWebURL string                   `json:"incidentWebUrl,omitempty"`
	Sample         bool                     `json:"sample,omitempty"`
}

// SecurityEvidenceSummary is the investigator-friendly projection of the
// normalized audit event behind an RTM-native incident. It deliberately omits
// raw provider JSON while retaining the actor, action, target, outcome, and a
// small set of meaningful before/after values.
type SecurityEvidenceSummary struct {
	EventID         string                   `json:"eventId"`
	Operation       string                   `json:"operation"`
	Actor           string                   `json:"actor,omitempty"`
	Target          string                   `json:"target,omitempty"`
	RelatedResource string                   `json:"relatedResource,omitempty"`
	Workload        string                   `json:"workload,omitempty"`
	ClientIP        string                   `json:"clientIp,omitempty"`
	ResultStatus    string                   `json:"resultStatus,omitempty"`
	OccurredAt      string                   `json:"occurredAt"`
	Changes         []SecurityEvidenceChange `json:"changes,omitempty"`
}

type SecurityEvidenceChange struct {
	Field  string `json:"field"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// SecurityEntity is a deliberately small, normalized identity for evidence
// attached to an incident. Raw provider payloads and tokens are never exposed.
type SecurityEntity struct {
	Type  string `json:"type"`
	Label string `json:"label"`
	// Key is the normalized, durable correlation identity. Labels remain
	// human-readable while keys are case-folded and type-prefixed so replayed
	// evidence joins the same account, mailbox, application, IP, or resource.
	Key string `json:"key,omitempty"`
}

// SecurityAlert is one Defender alert correlated into an incident.
type SecurityAlert struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	Severity        string `json:"severity"`
	Status          string `json:"status"`
	ServiceSource   string `json:"serviceSource"`
	DetectionSource string `json:"detectionSource,omitempty"`
	CreatedAt       string `json:"createdAt"`
	UpdatedAt       string `json:"updatedAt"`
}

// SecurityTimelineEvent is a provider-derived, read-only event in the
// incident evidence timeline.
type SecurityTimelineEvent struct {
	ID          string `json:"id"`
	Timestamp   string `json:"timestamp"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
}

type SecurityIncidentDetail struct {
	SecurityIncident
	Alerts      []SecurityAlert         `json:"alerts"`
	Timeline    []SecurityTimelineEvent `json:"timeline"`
	Remediation SecurityRemediationPlan `json:"remediation"`
}

// SecurityRemediationPlan is deterministic, read-only analyst guidance built
// from normalized incident metadata. It never executes a tenant write; any
// referenced RTM action still uses the normal What-If and approval gate.
type SecurityRemediationPlan struct {
	Category           string                    `json:"category"`
	Summary            string                    `json:"summary"`
	Steps              []SecurityRemediationStep `json:"steps"`
	CompletionCriteria []string                  `json:"completionCriteria"`
}

type SecurityRemediationStep struct {
	Phase       string `json:"phase"`   // Contain | Investigate | Eradicate | Recover | Validate
	Urgency     string `json:"urgency"` // Immediate | High | Standard
	Title       string `json:"title"`
	Description string `json:"description"`
	RTMAction   string `json:"rtmAction,omitempty"`
}

// SecurityIncidentFeed is one tenant's provider result. Mode is "live" or
// "sample" so connector coverage never presents sample data as live.
type SecurityIncidentFeed struct {
	Mode      string             `json:"mode"`
	Incidents []SecurityIncident `json:"incidents"`
	Truncated bool               `json:"truncated"`
}

// SecurityAuditCheckpoint records the durable ingestion position and health
// for one Microsoft 365 Management Activity content type. It contains no
// tokens or provider payloads and is safe to expose as connector coverage.
type SecurityAuditCheckpoint struct {
	TenantID       string    `json:"tenantId"`
	ContentType    string    `json:"contentType"`
	Status         string    `json:"status"` // healthy | degraded | missing_permission | auditing_disabled | sample
	Mode           string    `json:"mode"`   // live | sample
	Detail         string    `json:"detail,omitempty"`
	CursorEnd      time.Time `json:"cursorEnd"`
	LastPolledAt   time.Time `json:"lastPolledAt"`
	LastEventAt    time.Time `json:"lastEventAt,omitempty"`
	EventsReceived int       `json:"eventsReceived"`
	EventsInserted int       `json:"eventsInserted"`
}

// SecurityHistoryImport is the durable onboarding backfill policy and its
// progress. The incident cutoff remains after completion so future correlation
// cycles can use imported evidence as baseline without creating stale alerts.
type SecurityHistoryImport struct {
	TenantID               string    `json:"tenantId"`
	TenantName             string    `json:"tenantName,omitempty"`
	JobID                  string    `json:"jobId,omitempty"`
	RequestedWindow        string    `json:"requestedWindow"` // start_now | last_24h | last_7d | maximum_available
	WindowHours            int       `json:"windowHours"`
	HistoricalIncidentMode string    `json:"historicalIncidentMode"` // recent_24h | all | baseline_only
	Status                 string    `json:"status"`                 // queued | running | completed | partial | failed
	Progress               int       `json:"progress"`
	FeedsCompleted         int       `json:"feedsCompleted"`
	FeedsTotal             int       `json:"feedsTotal"`
	EventsReceived         int       `json:"eventsReceived"`
	EventsInserted         int       `json:"eventsInserted"`
	DetectionsCreated      int       `json:"detectionsCreated"`
	Detail                 string    `json:"detail,omitempty"`
	RequestedAt            time.Time `json:"requestedAt"`
	StartedAt              time.Time `json:"startedAt,omitempty"`
	CompletedAt            time.Time `json:"completedAt,omitempty"`
	IncidentCutoffAt       time.Time `json:"incidentCutoffAt,omitempty"`
}

// SecurityAuditEvent is an immutable normalized record from Microsoft Graph's
// fast identity feeds or the Microsoft 365 Management Activity API. Raw is
// retained server-side for investigation and detection replay. Only the
// explicitly redacted detail projection below may serialize provider evidence
// to an authenticated operator.
type SecurityAuditEvent struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenantId"`
	ProviderRecordID string    `json:"providerRecordId"`
	ContentType      string    `json:"contentType"`
	Workload         string    `json:"workload"`
	Operation        string    `json:"operation"`
	Actor            string    `json:"actor,omitempty"`
	ClientIP         string    `json:"clientIp,omitempty"`
	ObjectID         string    `json:"objectId,omitempty"`
	ResultStatus     string    `json:"resultStatus,omitempty"`
	OccurredAt       time.Time `json:"occurredAt"`
	// AvailableAt is the first time RTM observed the record from a Microsoft
	// API. Microsoft does not expose its internal publication timestamp, so
	// this is an honest upper bound for provider availability.
	AvailableAt time.Time       `json:"availableAt"`
	IngestedAt  time.Time       `json:"ingestedAt"`
	Sources     []string        `json:"sources"`
	Raw         json.RawMessage `json:"-"`
	Sample      bool            `json:"sample,omitempty"`
}

type SecurityAuditEventView struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenantId"`
	TenantName       string    `json:"tenantName"`
	ProviderRecordID string    `json:"providerRecordId"`
	ContentType      string    `json:"contentType"`
	Workload         string    `json:"workload"`
	Operation        string    `json:"operation"`
	Actor            string    `json:"actor,omitempty"`
	ClientIP         string    `json:"clientIp,omitempty"`
	ObjectID         string    `json:"objectId,omitempty"`
	ResultStatus     string    `json:"resultStatus,omitempty"`
	OccurredAt       time.Time `json:"occurredAt"`
	AvailableAt      time.Time `json:"availableAt"`
	IngestedAt       time.Time `json:"ingestedAt"`
	Sources          []string  `json:"sources"`
	Sample           bool      `json:"sample,omitempty"`
	HistoricalImport bool      `json:"historicalImport,omitempty"`
}

// SecurityAuditEventEvidence retains one immutable provider-native payload for
// each source record that contributed to a canonical security event. Raw is
// redacted by the server before this type is serialized to an operator.
type SecurityAuditEventEvidence struct {
	Source           string          `json:"source"`
	ProviderRecordID string          `json:"providerRecordId"`
	ContentType      string          `json:"contentType"`
	AvailableAt      time.Time       `json:"availableAt"`
	IngestedAt       time.Time       `json:"ingestedAt"`
	Raw              json.RawMessage `json:"raw"`
	RawTruncated     bool            `json:"rawTruncated"`
}

type SecurityAuditEventSearch struct {
	Query     string    `json:"query,omitempty"`
	TenantID  string    `json:"tenantId,omitempty"`
	Workload  string    `json:"workload,omitempty"`
	Operation string    `json:"operation,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	ClientIP  string    `json:"clientIp,omitempty"`
	Result    string    `json:"result,omitempty"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Limit     int       `json:"limit"`
	Offset    int       `json:"offset"`
}

type SecurityAuditEventPage struct {
	Events     []SecurityAuditEventView `json:"events"`
	Offset     int                      `json:"offset"`
	NextOffset *int                     `json:"nextOffset,omitempty"`
	Limit      int                      `json:"limit"`
	Limited    bool                     `json:"limited"`
	WindowDays int                      `json:"windowDays"`
}

type SecurityAuditEventDetail struct {
	SecurityAuditEventView
	Raw               json.RawMessage              `json:"raw"`
	RawTruncated      bool                         `json:"rawTruncated"`
	SourceEvidence    []SecurityAuditEventEvidence `json:"sourceEvidence"`
	RelatedDetections []SecurityNativeDetection    `json:"relatedDetections"`
}

// OfflineInvestigation is a case-scoped, read-only analysis workspace. Its
// imported evidence never enters the live tenant event or incident tables.
type OfflineInvestigation struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	TenantLabel       string                    `json:"tenantLabel"`
	Status            string                    `json:"status"` // draft | ready | queued | analyzing | complete | failed
	Progress          int                       `json:"progress"`
	Detail            string                    `json:"detail,omitempty"`
	CreatedBy         string                    `json:"createdBy"`
	CreatedAt         time.Time                 `json:"createdAt"`
	UpdatedAt         time.Time                 `json:"updatedAt"`
	AnalyzedAt        time.Time                 `json:"analyzedAt,omitempty"`
	PeriodStart       time.Time                 `json:"periodStart,omitempty"`
	PeriodEnd         time.Time                 `json:"periodEnd,omitempty"`
	EventCount        int                       `json:"eventCount"`
	DetectionCount    int                       `json:"detectionCount"`
	HighPriorityCount int                       `json:"highPriorityCount"`
	StorylineCount    int                       `json:"storylineCount"`
	Coverage          []OfflineEvidenceCoverage `json:"coverage"`
}

type OfflineEvidenceCoverage struct {
	Key           string   `json:"key"`
	Label         string   `json:"label"`
	Status        string   `json:"status"` // present | partial | missing
	Records       int      `json:"records"`
	Detail        string   `json:"detail"`
	Fields        []string `json:"fields,omitempty"`
	MissingFields []string `json:"missingFields,omitempty"`
}

type OfflineInvestigationFile struct {
	ID              string    `json:"id"`
	InvestigationID string    `json:"investigationId"`
	Name            string    `json:"name"`
	MediaType       string    `json:"mediaType"`
	EvidenceType    string    `json:"evidenceType"`
	SizeBytes       int64     `json:"sizeBytes"`
	SHA256          string    `json:"sha256"`
	Status          string    `json:"status"`
	RecordCount     int       `json:"recordCount"`
	UploadedAt      time.Time `json:"uploadedAt"`
	Content         []byte    `json:"-"`
}

type OfflineTimelineEvent struct {
	ID           string                  `json:"id"`
	EvidenceType string                  `json:"evidenceType"`
	Source       string                  `json:"source"`
	Workload     string                  `json:"workload"`
	Operation    string                  `json:"operation"`
	Actor        string                  `json:"actor,omitempty"`
	ClientIP     string                  `json:"clientIp,omitempty"`
	ObjectID     string                  `json:"objectId,omitempty"`
	ResultStatus string                  `json:"resultStatus,omitempty"`
	Severity     string                  `json:"severity,omitempty"`
	OccurredAt   time.Time               `json:"occurredAt"`
	Facts        []OfflineTimelineFact   `json:"facts"`
	Signals      []OfflineTimelineSignal `json:"signals"`
}

type OfflineTimelineFact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type OfflineTimelineSignal struct {
	RuleID   string `json:"ruleId"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

type OfflineInvestigationAnalysis struct {
	Events     []SecurityAuditEvent      `json:"-"`
	Detections []SecurityNativeDetection `json:"detections"`
	Storylines []SecurityStoryline       `json:"storylines"`
}

type OfflineInvestigationDetail struct {
	OfflineInvestigation
	Files      []OfflineInvestigationFile `json:"files"`
	Timeline   []OfflineTimelineEvent     `json:"timeline"`
	Detections []SecurityNativeDetection  `json:"detections"`
	Storylines []SecurityStoryline        `json:"storylines"`
}

type SecurityRuleExclusion struct {
	Field string `json:"field"` // actor | clientIp | objectId | tenantId
	Match string `json:"match"` // exact | contains
	Value string `json:"value"`
}

type SecurityRuleDefinition struct {
	TriggerMode    string                  `json:"triggerMode,omitempty"` // builtIn | custom (built-in overrides only)
	Workloads      []string                `json:"workloads,omitempty"`
	Operations     []string                `json:"operations,omitempty"`
	OperationMatch string                  `json:"operationMatch,omitempty"` // exact | contains
	Actors         []string                `json:"actors,omitempty"`
	ClientIPs      []string                `json:"clientIps,omitempty"`
	Results        []string                `json:"results,omitempty"`
	ObjectContains []string                `json:"objectContains,omitempty"`
	RawContains    []string                `json:"rawContains,omitempty"`
	Threshold      int                     `json:"threshold,omitempty"`
	WindowMinutes  int                     `json:"windowMinutes,omitempty"`
	GroupBy        string                  `json:"groupBy,omitempty"` // actor | clientIp | objectId | tenant
	Exclusions     []SecurityRuleExclusion `json:"exclusions,omitempty"`
}

// SecurityDetectionRule is either a custom rule or a persisted override of a
// locked built-in rule. BaseRuleID is set only for overrides.
type SecurityDetectionRule struct {
	ID            string                 `json:"id"`
	RuleID        string                 `json:"ruleId"`
	BaseRuleID    string                 `json:"baseRuleId,omitempty"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	BuiltIn       bool                   `json:"builtIn"`
	Override      bool                   `json:"override"`
	Locked        bool                   `json:"locked"`
	DetectionType string                 `json:"detectionType"` // direct | threshold | correlation | heuristic
	Severity      string                 `json:"severity"`
	Confidence    string                 `json:"confidence"`
	Enabled       bool                   `json:"enabled"`
	Scope         string                 `json:"scope"` // global | tenant
	TenantID      string                 `json:"tenantId,omitempty"`
	TenantName    string                 `json:"tenantName,omitempty"`
	Definition    SecurityRuleDefinition `json:"definition"`
	Revision      int                    `json:"revision"`
	UpdatedBy     string                 `json:"updatedBy"`
	CreatedAt     time.Time              `json:"createdAt"`
	UpdatedAt     time.Time              `json:"updatedAt"`
}

type SecurityDetectionRuleRevision struct {
	RuleID    string                `json:"ruleId"`
	Revision  int                   `json:"revision"`
	Snapshot  SecurityDetectionRule `json:"snapshot"`
	Actor     string                `json:"actor"`
	CreatedAt time.Time             `json:"createdAt"`
}

type SecurityRulePreview struct {
	MatchedEvents  int                      `json:"matchedEvents"`
	EventsScanned  int                      `json:"eventsScanned"`
	TenantsMatched map[string]int           `json:"tenantsMatched"`
	SampleEvents   []SecurityAuditEventView `json:"sampleEvents"`
	Warnings       []string                 `json:"warnings"`
	ApprovalToken  string                   `json:"approvalToken"`
}

// SecurityRuleConditionOptions is the safe suggestion catalog used by the
// detection-rule editor. Dynamic values come only from normalized audit
// columns; raw provider values are never projected into this response.
type SecurityRuleConditionOptions struct {
	Workloads          []string `json:"workloads"`
	Operations         []string `json:"operations"`
	Actors             []string `json:"actors"`
	ClientIPs          []string `json:"clientIps"`
	Results            []string `json:"results"`
	Objects            []string `json:"objects"`
	RawEvidenceTerms   []string `json:"rawEvidenceTerms"`
	EventsScanned      int      `json:"eventsScanned"`
	EvidenceWindowDays int      `json:"evidenceWindowDays"`
	Limited            bool     `json:"limited"`
}

// SecurityNativeDetection is an RTM rule match over immutable audit events.
// IDs are deterministic so replaying an overlapping ingestion window cannot
// duplicate incidents.
type SecurityNativeDetection struct {
	ID            string           `json:"id"`
	TenantID      string           `json:"tenantId"`
	EventID       string           `json:"eventId"`
	EventIDs      []string         `json:"eventIds,omitempty"`
	RuleID        string           `json:"ruleId"`
	RuleVersion   int              `json:"ruleVersion"`
	Title         string           `json:"title"`
	Description   string           `json:"description"`
	Severity      string           `json:"severity"`
	DetectionType string           `json:"detectionType"` // direct | threshold | correlation | heuristic
	Confidence    string           `json:"confidence"`    // high | medium | low
	Entities      []SecurityEntity `json:"entities,omitempty"`
	OccurredAt    time.Time        `json:"occurredAt"`
	CreatedAt     time.Time        `json:"createdAt"`
	Sample        bool             `json:"sample,omitempty"`
}

// SecurityStoryline is a persisted, deterministic correlation of independent
// RTM detections. CorrelationKey is server-only: it keeps overlapping replay
// windows and late-arriving evidence attached to the same active storyline.
type SecurityStoryline struct {
	ID                 string                    `json:"id"`
	CorrelationKey     string                    `json:"-"`
	PackID             string                    `json:"packId"`
	Title              string                    `json:"title"`
	Summary            string                    `json:"summary"`
	Severity           string                    `json:"severity"`
	RiskScore          int                       `json:"riskScore"`
	Confidence         string                    `json:"confidence"`
	Status             string                    `json:"status"`
	Owner              string                    `json:"owner,omitempty"`
	FirstSeen          time.Time                 `json:"firstSeen"`
	LastSeen           time.Time                 `json:"lastSeen"`
	UpdatedAt          time.Time                 `json:"updatedAt"`
	TenantIDs          []string                  `json:"tenantIds"`
	TenantNames        []string                  `json:"tenantNames"`
	Entities           []SecurityStorylineEntity `json:"entities"`
	Stages             []string                  `json:"stages"`
	Workloads          []string                  `json:"workloads"`
	DetectionIDs       []string                  `json:"detectionIds"`
	EventIDs           []string                  `json:"eventIds"`
	SignalCount        int                       `json:"signalCount"`
	AffectedUsers      int                       `json:"affectedUsers"`
	AffectedResources  int                       `json:"affectedResources"`
	Reasons            []string                  `json:"reasons"`
	WeakEvidence       []string                  `json:"weakEvidence,omitempty"`
	RecommendedActions []string                  `json:"recommendedActions"`
	Sample             bool                      `json:"sample,omitempty"`
}

type SecurityStorylineEntity struct {
	Type     string `json:"type"`
	Key      string `json:"key"`
	Label    string `json:"label"`
	TenantID string `json:"tenantId,omitempty"`
	Primary  bool   `json:"primary,omitempty"`
}

type SecurityStorylineEvidence struct {
	DetectionID string                    `json:"detectionId"`
	RuleID      string                    `json:"ruleId"`
	Title       string                    `json:"title"`
	Severity    string                    `json:"severity"`
	Confidence  string                    `json:"confidence"`
	Stage       string                    `json:"stage"`
	OccurredAt  time.Time                 `json:"occurredAt"`
	TenantID    string                    `json:"tenantId"`
	TenantName  string                    `json:"tenantName"`
	Events      []SecurityEvidenceSummary `json:"events"`
}

type SecurityStorylineDetail struct {
	SecurityStoryline
	Evidence []SecurityStorylineEvidence `json:"evidence"`
}

const (
	SecurityTriageNew        = "New"
	SecurityTriageInProgress = "In Progress"
	SecurityTriageResolved   = "Resolved"
	SecurityTriageDismissed  = "Dismissed"
)

// SecurityIncidentState persists RTM's first observation time and local
// ownership/status overlay keyed by tenant + Microsoft incident id. Provider
// incident content remains in Microsoft and is fetched on demand.
type SecurityIncidentState struct {
	TenantID   string    `json:"tenantId"`
	IncidentID string    `json:"incidentId"`
	Status     string    `json:"status"`
	Owner      string    `json:"owner,omitempty"`
	ReceivedAt time.Time `json:"receivedAt"`
	UpdatedBy  string    `json:"updatedBy"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type SecuritySummary struct {
	Open            int `json:"open"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	TenantsCovered  int `json:"tenantsCovered"`
	TenantsTotal    int `json:"tenantsTotal"`
	LiveTenants     int `json:"liveTenants"`
	SampleTenants   int `json:"sampleTenants"`
	IngestionHealth int `json:"ingestionHealth"`
}

type SecuritySeverityCount struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// SecurityConnectorSummary is an aggregate connector row. Planned connectors
// are returned explicitly so the UI distinguishes roadmap coverage from a
// broken or unconfigured live connection.
type SecurityConnectorSummary struct {
	Key                string `json:"key"`
	Name               string `json:"name"`
	Status             string `json:"status"` // healthy | degraded | sample | planned
	HealthyTenants     int    `json:"healthyTenants"`
	AttentionTenants   int    `json:"attentionTenants"`
	SampleTenants      int    `json:"sampleTenants"`
	RequiredPermission string `json:"requiredPermission,omitempty"`
}

type SecurityCoverage struct {
	TenantID           string `json:"tenantId"`
	TenantName         string `json:"tenantName"`
	ConnectorKey       string `json:"connectorKey"`
	ConnectorName      string `json:"connectorName"`
	Status             string `json:"status"` // healthy | missing_permission | not_provisioned | degraded | sample
	Detail             string `json:"detail,omitempty"`
	RequiredPermission string `json:"requiredPermission"`
	CheckedAt          string `json:"checkedAt"`
}

type SecurityOperationsSnapshot struct {
	GeneratedAt    string                     `json:"generatedAt"`
	Summary        SecuritySummary            `json:"summary"`
	Severity       []SecuritySeverityCount    `json:"severity"`
	Connectors     []SecurityConnectorSummary `json:"connectors"`
	Coverage       []SecurityCoverage         `json:"coverage"`
	HistoryImports []SecurityHistoryImport    `json:"historyImports"`
	Storylines     []SecurityStoryline        `json:"storylines"`
	Incidents      []SecurityIncident         `json:"incidents"`
	Warnings       []string                   `json:"warnings"`
}

// ---- ThreatLocker-sourced entities (from the threatlocker provider) ----

// Device is one ThreatLocker-protected endpoint. Mode is the protection state
// (see threatlocker.Mode* constants): "secured" is full protection; the
// maintenance modes, lockdown, and isolation are temporary states RTM's write
// actions move devices into and out of.
type Device struct {
	ID               string `json:"id"`
	OrganizationID   string `json:"organizationId"`
	Hostname         string `json:"hostname"`
	Group            string `json:"group"`
	OS               string `json:"os"` // "windows" | "mac" | "linux"
	AgentVersion     string `json:"agentVersion"`
	Mode             string `json:"mode"`
	ModeExpires      string `json:"modeExpires"` // RFC3339; empty = no scheduled end
	TamperProtection bool   `json:"tamperProtection"`
	LastCheckIn      string `json:"lastCheckIn"`
	Online           bool   `json:"online"`
}

type DeviceGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DeviceCount int    `json:"deviceCount"`
}

// ApprovalRequest is a pending ThreatLocker application-control request (a
// user asked to run/elevate/access something a policy blocked). Approving one
// creates a ThreatLocker policy — RTM presents it as the policy write it is.
type ApprovalRequest struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	DeviceID       string `json:"deviceId"`
	DeviceName     string `json:"deviceName"`
	Requester      string `json:"requester"`
	Application    string `json:"application"`
	Path           string `json:"path"`
	Hash           string `json:"hash"`
	RequestType    string `json:"requestType"` // "execution" | "elevation" | "storage"
	Status         string `json:"status"`      // "pending" | "approved" | "denied"
	RequestedAt    string `json:"requestedAt"`
}

// TLPolicy is a ThreatLocker policy row (read-only in v1; served by the
// portal's Policy/PolicyGetByParameters).
type TLPolicy struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Action           string `json:"action"` // "permit" | "deny" | "ringfence" | "elevate" | …
	PolicyActionID   int    `json:"policyActionId"`
	AppliesTo        string `json:"appliesTo"`
	Status           string `json:"status"` // "Enabled" | "Disabled"
	ApplicationCount int    `json:"applicationCount"`
	UserCount        int    `json:"userCount"`
	AllUsers         bool   `json:"allUsers"`
	LastMatchedAt    string `json:"lastMatchedAt"`
	MonitorMode      int    `json:"monitorMode"`
	OrganizationID   string `json:"organizationId"`
}

type TLPolicyApplication struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// TLPolicyDetail is the editable ThreatLocker policy shape RTM exposes. Raw
// carries the full portal object so update/create can preserve fields RTM does
// not yet render.
type TLPolicyDetail struct {
	ID                   string                `json:"id"`
	Name                 string                `json:"name"`
	Description          string                `json:"description"`
	Comments             string                `json:"comments"`
	Action               string                `json:"action"`
	PolicyActionID       int                   `json:"policyActionId"`
	AppliesTo            string                `json:"appliesTo"`
	Status               string                `json:"status"`
	IsEnabled            bool                  `json:"isEnabled"`
	MonitorMode          int                   `json:"monitorMode"`
	OrderBy              int                   `json:"orderBy"`
	NeverExpires         bool                  `json:"neverExpires"`
	EndDate              string                `json:"endDate"`
	LogAction            bool                  `json:"logAction"`
	NotifyOnMatch        bool                  `json:"notifyOnMatch"`
	NotifyOnRequest      bool                  `json:"notifyOnRequest"`
	KillRunningProcesses bool                  `json:"killRunningProcesses"`
	ApplicationSelection int                   `json:"applicationSelection"`
	ApplicationIDs       []string              `json:"applicationIds"`
	Applications         []TLPolicyApplication `json:"applications"`
	OrganizationID       string                `json:"organizationId"`
	Raw                  map[string]any        `json:"raw,omitempty"`
}

// TLPolicyPatch is a conservative edit payload. Pointer fields distinguish
// omitted fields from explicit false/zero values.
type TLPolicyPatch struct {
	ApprovalToken        string   `json:"approvalToken,omitempty"`
	ID                   string   `json:"id,omitempty"`
	Name                 *string  `json:"name,omitempty"`
	Description          *string  `json:"description,omitempty"`
	Comments             *string  `json:"comments,omitempty"`
	IsEnabled            *bool    `json:"isEnabled,omitempty"`
	AllDevices           *bool    `json:"allDevices,omitempty"`
	AllUserGroups        *bool    `json:"allUserGroups,omitempty"`
	ComputerGroupID      *string  `json:"computerGroupId,omitempty"`
	PolicyActionID       *int     `json:"policyActionId,omitempty"`
	MonitorMode          *int     `json:"monitorMode,omitempty"`
	OrderBy              *int     `json:"orderBy,omitempty"`
	NeverExpires         *bool    `json:"neverExpires,omitempty"`
	EndDate              *string  `json:"endDate,omitempty"`
	LogAction            *bool    `json:"logAction,omitempty"`
	NotifyOnMatch        *bool    `json:"notifyOnMatch,omitempty"`
	NotifyOnRequest      *bool    `json:"notifyOnRequest,omitempty"`
	KillRunningProcesses *bool    `json:"killRunningProcesses,omitempty"`
	ApplicationSelection *int     `json:"applicationSelection,omitempty"`
	ApplicationIDs       []string `json:"applicationIds,omitempty"`
}

type TLPolicyConsolidateResult struct {
	PolicyID          string   `json:"policyId"`
	Name              string   `json:"name"`
	Status            string   `json:"status"`
	MergedPolicyIDs   []string `json:"mergedPolicyIds"`
	DisabledPolicyIDs []string `json:"disabledPolicyIds"`
	Failed            []string `json:"failed"`
}

type TLPolicyTemplate struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Source      string         `json:"source"`
	Policy      TLPolicyDetail `json:"policy"`
	UpdatedAt   string         `json:"updatedAt"`
}

type TLPolicyDeployResult struct {
	TemplateID string   `json:"templateId"`
	Status     string   `json:"status"`
	Succeeded  []string `json:"succeeded"`
	Failed     []string `json:"failed"`
}

// TLApplication is one ThreatLocker Application Control application row. RTM
// surfaces both child-tenant apps and parent-owned global apps in the Apps tab.
type TLApplication struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	OrganizationID string `json:"organizationId"`
	Organization   string `json:"organization"`
	Source         string `json:"source"` // "parent" | "tenant"
	OSType         int    `json:"osType"`
	OS             string `json:"os"`
	Status         string `json:"status"`
	BuiltIn        bool   `json:"builtIn"`
	Hidden         bool   `json:"hidden"`
	PolicyCount    int    `json:"policyCount"`
	FileCount      int    `json:"fileCount"`
	UpdatedAt      string `json:"updatedAt"`
}

// TLApplicationFile is one file-rule condition inside a ThreatLocker custom
// application.
type TLApplicationFile struct {
	ID                string `json:"id"`
	ApplicationFileID int64  `json:"applicationFileId"`
	ApplicationID     string `json:"applicationId"`
	Name              string `json:"name"`
	FullPath          string `json:"fullPath"`
	ProcessPath       string `json:"processPath"`
	Cert              string `json:"cert"`
	Hash              string `json:"hash"`
	Notes             string `json:"notes"`
	InstalledBy       string `json:"installedBy"`
	OSType            int    `json:"osType"`
	KeyFile           bool   `json:"keyFile"`
	IsHashOnly        bool   `json:"isHashOnly"`
}

// TLApplicationDetail carries the editable app fields plus file rules and raw
// portal data so update/create can preserve fields RTM does not render.
type TLApplicationDetail struct {
	TLApplication
	Files []TLApplicationFile `json:"files"`
	Raw   map[string]any      `json:"raw,omitempty"`
}

type TLApplicationPatch struct {
	ApprovalToken string  `json:"approvalToken,omitempty"`
	ID            string  `json:"id,omitempty"`
	Name          *string `json:"name,omitempty"`
	Description   *string `json:"description,omitempty"`
}

type TLAppCleanupRequest struct {
	ApprovalToken    string   `json:"approvalToken,omitempty"`
	AppIDs           []string `json:"appIds"`
	RetainedAppID    string   `json:"retainedAppId,omitempty"`
	RetainedPolicyID string   `json:"retainedPolicyId,omitempty"`
	Name             string   `json:"name,omitempty"`
	ConfirmDelete    bool     `json:"confirmDelete,omitempty"`
}

// TLAppParentPromotion is the exact pre-merge policy move that causes
// ThreatLocker to materialize a child application in the MSP parent
// organization. ApprovalToken is issued by the cleanup preview and is bound to
// every other field.
type TLAppParentPromotion struct {
	ApprovalToken             string `json:"approvalToken,omitempty"`
	ApplicationID             string `json:"applicationId"`
	ApplicationName           string `json:"applicationName"`
	ApplicationOrganizationID string `json:"applicationOrganizationId"`
	SourceOrganizationID      string `json:"sourceOrganizationId"`
	PolicyID                  string `json:"policyId"`
	PolicyName                string `json:"policyName"`
	DestinationGroupID        string `json:"destinationGroupId"`
	DestinationGroupName      string `json:"destinationGroupName"`
	ParentOrganizationID      string `json:"parentOrganizationId"`
	OSType                    int    `json:"osType"`
}

type TLComputerGroup struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	OrganizationID string `json:"organizationId"`
}

type TLAppCleanupPreview struct {
	ApprovalToken   string          `json:"approvalToken,omitempty"`
	Fingerprint     string          `json:"fingerprint"`
	TenantID        string          `json:"tenantId"`
	RetainedApp     TLApplication   `json:"retainedApp"`
	RetainedPolicy  TLPolicy        `json:"retainedPolicy"`
	SourceApps      []TLApplication `json:"sourceApps"`
	FileRuleCount   int             `json:"fileRuleCount"`
	PolicyCount     int             `json:"policyCount"`
	DeleteAppIDs    []string        `json:"deleteAppIds"`
	DeletePolicyIDs []string        `json:"deletePolicyIds"`
	// DeletePolicies carries the full rows behind DeletePolicyIDs. Each row's
	// OrganizationID names the org the policy lives in (possibly a child org),
	// which execute needs to address the policy with the right
	// managedOrganizationId header.
	DeletePolicies []TLPolicy `json:"deletePolicies"`
	// PreservedPolicies are snapshotted before the native application merge and
	// queued to the exact Global group one at a time after the merge.
	PreservedPolicies []TLPolicy            `json:"preservedPolicies"`
	ParentPromotion   *TLAppParentPromotion `json:"parentPromotion,omitempty"`
	GlobalDestination TLComputerGroup       `json:"globalDestination"`
	Warnings          []string              `json:"warnings"`
	Blocked           []string              `json:"blocked"`
}

type TLAppCleanupResult struct {
	Status             string                   `json:"status"`
	Stage              string                   `json:"stage,omitempty"`
	OperationID        string                   `json:"operationId,omitempty"`
	VerificationStatus string                   `json:"verificationStatus,omitempty"`
	Verification       TLAppCleanupVerification `json:"verification"`
	RetainedAppID      string                   `json:"retainedAppId"`
	RetainedPolicyID   string                   `json:"retainedPolicyId"`
	CopiedFileRules    int                      `json:"copiedFileRules"`
	ExpectedFileRules  int                      `json:"expectedFileRules"`
	DeletedAppIDs      []string                 `json:"deletedAppIds"`
	DeletedPolicyIDs   []string                 `json:"deletedPolicyIds"`
	PreservedPolicies  []TLPolicy               `json:"preservedPolicies"`
	PromotedPolicyIDs  []string                 `json:"promotedPolicyIds"`
	ParentPromotion    *TLAppParentPromotion    `json:"parentPromotion,omitempty"`
	RetainedAppName    string                   `json:"retainedAppName,omitempty"`
	RetainedAppOSType  int                      `json:"retainedAppOsType,omitempty"`
	Failed             []string                 `json:"failed"`
}

type TLAppCleanupVerificationCheck struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

type TLAppCleanupVerification struct {
	Passed    bool                            `json:"passed"`
	CheckedAt string                          `json:"checkedAt"`
	Checks    []TLAppCleanupVerificationCheck `json:"checks"`
}

type TLAppCleanupCandidate struct {
	ID                       string          `json:"id"`
	Name                     string          `json:"name"`
	OSType                   int             `json:"osType"`
	OS                       string          `json:"os"`
	Score                    int             `json:"score"`
	Confidence               string          `json:"confidence"`
	ParentReady              bool            `json:"parentReady"`
	RecommendedRetainedAppID string          `json:"recommendedRetainedAppId"`
	OrganizationCount        int             `json:"organizationCount"`
	TotalFileRules           int             `json:"totalFileRules"`
	TotalPolicies            int             `json:"totalPolicies"`
	Applications             []TLApplication `json:"applications"`
	Reasons                  []string        `json:"reasons"`
}

const (
	TLCleanupSubmitted           = "submitted"
	TLCleanupVerificationPending = "verification_pending"
	TLCleanupNeedsReconciliation = "needs_reconciliation"
	TLCleanupVerified            = "verified"
	TLCleanupFailed              = "failed"
)

// TLAppCleanupOperation is the durable safety ledger around the multi-step
// ThreatLocker application cleanup. Active states block an equivalent
// fingerprint until an administrator reconciles the portal outcome.
type TLAppCleanupOperation struct {
	ID          string              `json:"id"`
	TenantID    string              `json:"tenantId"`
	Status      string              `json:"status"`
	RequestedBy string              `json:"requestedBy"`
	Fingerprint string              `json:"-"`
	Request     TLAppCleanupRequest `json:"-"`
	Result      TLAppCleanupResult  `json:"result"`
	Error       string              `json:"error,omitempty"`
	CreatedAt   time.Time           `json:"createdAt"`
	UpdatedAt   time.Time           `json:"updatedAt"`
}

// ---- Entra posture reads (read-only; Entra readiness reports + preflight) ----

// MFARegistration is one row of the authentication-methods registration report
// (live: /reports/authenticationMethods/userRegistrationDetails). It powers
// the "mfa-gaps" readiness report; IsAdmin flags privileged accounts so admin
// MFA gaps surface first.
type MFARegistration struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	UPN           string   `json:"upn"`
	IsAdmin       bool     `json:"isAdmin"`
	MFARegistered bool     `json:"mfaRegistered"`
	Passwordless  bool     `json:"passwordless"`
	SSPR          bool     `json:"sspr"`
	Methods       []string `json:"methods"`
}

// GuestAccount is a guest user with the lifecycle signals the stale-guest
// report needs. LastSignIn is RFC3339 or empty (never signed in / signal
// unavailable — Graph sign-in activity needs an Entra ID P1 license).
type GuestAccount struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	UPN            string `json:"upn"`
	Mail           string `json:"mail"`
	AccountEnabled bool   `json:"accountEnabled"`
	State          string `json:"state"` // "Accepted" | "PendingAcceptance" | ""
	Created        string `json:"created"`
	LastSignIn     string `json:"lastSignIn"`
}

// RoleAssignment is one member of an activated Entra directory role
// (privileged-roles report).
type RoleAssignment struct {
	RoleID     string `json:"roleId"`
	RoleName   string `json:"roleName"`
	MemberID   string `json:"memberId"`
	MemberName string `json:"memberName"`
	MemberUPN  string `json:"memberUpn"`
	MemberType string `json:"memberType"` // "User" | "Group" | "Service Principal"
}

// CAExclusion is one excluded user/group/app on a Conditional Access policy.
// Target carries the excluded object (live mode reports the raw GUID — Graph
// app-only reads don't resolve names without extra lookups; sample mode uses
// display names).
type CAExclusion struct {
	PolicyID   string `json:"policyId"`
	PolicyName string `json:"policyName"`
	State      string `json:"state"` // "enabled" | "disabled" | "reportOnly"
	Type       string `json:"type"`  // "Excluded user" | "Excluded group" | "Excluded app"
	Target     string `json:"target"`
}

// AppCredential is one client secret or certificate on an app registration
// (app-credentials expiry report). ExpiresAt is RFC3339, empty = no expiry set.
type AppCredential struct {
	AppID     string `json:"appId"`
	AppName   string `json:"appName"`
	Type      string `json:"type"` // "Secret" | "Certificate"
	ExpiresAt string `json:"expiresAt"`
}

// LicenseReadinessIssue is one per-user license blocker: a condition that will
// make a future license assignment fail (missing usage location) or that
// wastes onboarding time (enabled member account with no license at all).
type LicenseReadinessIssue struct {
	UserID string `json:"userId"`
	Name   string `json:"name"`
	UPN    string `json:"upn"`
	Issue  string `json:"issue"` // "Missing usage location" | "Unlicensed"
	Status string `json:"status"`
}

// PreflightCheck is one capability row from POST /tenants/{id}/preflight: does
// the tenant's app registration hold the Graph permission a feature area
// needs? Read areas are probed with harmless GETs; exact and documented
// broader application grants are read from Microsoft-issued token roles.
type PreflightCheck struct {
	Category   string `json:"category"`
	Area       string `json:"area"`
	Resource   string `json:"resource"` // Microsoft Graph | SharePoint Online
	Permission string `json:"permission"`
	Status     string `json:"status"` // "ok" | "missing" | "error" | "not_provisioned" | "sample" | "unchecked"
	Detail     string `json:"detail,omitempty"`
	GrantedVia string `json:"grantedVia,omitempty"`
}

// Preflight is the cached GET and diagnostic POST /tenants/{id}/preflight response.
type Preflight struct {
	Mode   string           `json:"mode"` // "sample" | "live"
	RanAt  string           `json:"ranAt"`
	Checks []PreflightCheck `json:"checks"`
}

// UserRaw is the full directory object for one user — every attribute the
// Graph app can read, including the uncommon ones (on-prem extension
// attributes, identities, proxy addresses) that the normal Users table
// doesn't show. Read-only; served by GET /tenants/{id}/users/{userId}/raw.
type UserRaw struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes"`
}

// ---- Share Detective (shared-access investigation) ----

// Classification of how a SharePoint/OneDrive finding grants the subject
// access. Only confirmed direct grants (direct_user, specific_people_link)
// are safely revocable per subject; the rest carry a manual-review resolution
// because deleting them would affect more than the subject.
const (
	ShareDirectUser     = "direct_user"          // direct permission on the item/site
	ShareSpecificLink   = "specific_people_link" // sharing link scoped to specific people incl. the subject
	ShareBroadLink      = "broad_link"           // anyone/organization link — affects everyone with the link
	ShareGroupBased     = "group_based"          // access via a group the subject belongs to
	ShareSiteMembership = "site_membership"      // access via site owners/members/visitors
	ShareInherited      = "inherited"            // permission inherited from a parent folder/site
)

// ShareSubject is the user or guest a Share Detective investigation targets.
type ShareSubject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	UPN  string `json:"upn"`
	Type string `json:"type"` // "Member" | "Guest"
}

// ShareCoverage reports scan honesty per site: a skipped site means the
// investigation is partial there, never a silent miss.
type ShareCoverage struct {
	SiteID       string `json:"siteId"`
	SiteName     string `json:"siteName"`
	Status       string `json:"status"` // "scanned" | "partial" | "skipped"
	ItemsScanned int    `json:"itemsScanned"`
	Reason       string `json:"reason,omitempty"`
}

// ShareFinding is one place the subject has (or may have) access. Revocable
// is true only for confirmed direct grants RTM can delete per subject;
// Detail explains the resolution path for everything else.
type ShareFinding struct {
	ID             string `json:"id"`
	SiteID         string `json:"siteId"`
	SiteName       string `json:"siteName"`
	DriveID        string `json:"driveId,omitempty"`
	ItemID         string `json:"itemId,omitempty"`
	ItemPath       string `json:"itemPath"`
	ItemType       string `json:"itemType"` // "site" | "folder" | "file"
	WebURL         string `json:"webUrl,omitempty"`
	Classification string `json:"classification"`
	Role           string `json:"role"`
	PermissionID   string `json:"permissionId,omitempty"`
	Via            string `json:"via,omitempty"` // group name / link scope that grants the access
	Revocable      bool   `json:"revocable"`
	Revoked        bool   `json:"revoked"`
	Detail         string `json:"detail,omitempty"`
}

// ShareSummary is the coverage + findings rollup shown on the investigation.
type ShareSummary struct {
	SitesDiscovered int `json:"sitesDiscovered"`
	SitesScanned    int `json:"sitesScanned"`
	SitesSkipped    int `json:"sitesSkipped"`
	ItemsScanned    int `json:"itemsScanned"`
	Findings        int `json:"findings"`
	Revocable       int `json:"revocable"`
}

// ShareInvestigation is one tenant-wide scan for everything shared with a
// subject. Investigations are ephemeral operational state (kept in memory,
// like pending approvals) — findings that matter should be exported or acted
// on through the revoke workflow, which is fully audited.
type ShareInvestigation struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenantId"`
	TenantName  string          `json:"tenantName"`
	Subject     ShareSubject    `json:"subject"`
	Status      string          `json:"status"` // "running" | "completed" | "failed"
	StartedAt   string          `json:"startedAt"`
	CompletedAt string          `json:"completedAt,omitempty"`
	StartedBy   string          `json:"startedBy"`
	Error       string          `json:"error,omitempty"`
	Summary     ShareSummary    `json:"summary"`
	Coverage    []ShareCoverage `json:"coverage"`
	Findings    []ShareFinding  `json:"findings"`
}

// ShareRevokeAction is one row of a What-If revoke plan.
type ShareRevokeAction struct {
	FindingID string `json:"findingId"`
	SiteName  string `json:"siteName"`
	ItemPath  string `json:"itemPath"`
	Action    string `json:"action"` // "delete_permission" | "manual_review"
	Reason    string `json:"reason,omitempty"`
}

// ShareRevokePreview is the What-If plan for revoking selected findings.
type ShareRevokePreview struct {
	ApprovalToken  string              `json:"approvalToken,omitempty"`
	Subject        ShareSubject        `json:"subject"`
	Tenant         string              `json:"tenant"`
	Risk           string              `json:"risk"`
	RevocableCount int                 `json:"revocableCount"`
	Actions        []ShareRevokeAction `json:"actions"`
	Warnings       []string            `json:"warnings"`
}

// ShareRevokeResult reports per-finding revoke outcomes (partial-failure
// tolerant — one failed site/item never fails the batch).
type ShareRevokeResult struct {
	Status  string   `json:"status"` // "Completed" | "Partial" | "Failed"
	Revoked []string `json:"revoked"`
	Failed  []string `json:"failed"`
}

// SharedItem is one drive item that carries its own sharing state, with the
// permission entries needed to match a subject.
type SharedItem struct {
	ItemID      string           `json:"itemId"`
	DriveID     string           `json:"driveId"`
	Name        string           `json:"name"`
	Path        string           `json:"path"`
	WebURL      string           `json:"webUrl"`
	Type        string           `json:"type"` // "file" | "folder"
	Permissions []ItemPermission `json:"permissions"`
}

// ItemPermission is one grant on a drive item. Link permissions scoped to
// specific people emit one entry per grantee so subject matching stays
// uniform.
type ItemPermission struct {
	ID          string   `json:"id"`
	GranteeID   string   `json:"granteeId,omitempty"`
	GranteeName string   `json:"granteeName,omitempty"`
	GranteeUPN  string   `json:"granteeUpn,omitempty"`
	GranteeType string   `json:"granteeType"`         // "user" | "group" | "link" | "app"
	LinkScope   string   `json:"linkScope,omitempty"` // "anonymous" | "organization" | "users"
	Roles       []string `json:"roles"`
	Inherited   bool     `json:"inherited"`
}

// GlobalReport is a cross-tenant read-only report (tenant column always first).
type GlobalReport struct {
	Columns []string             `json:"columns"`
	Rows    [][]GlobalReportCell `json:"rows"`
}

// GlobalReportCell is either plain text or a toned badge (matches the frontend
// union type). Exactly one of Text / Badge is set.
type GlobalReportCell struct {
	Text  string `json:"text,omitempty"`
	Badge string `json:"badge,omitempty"`
	Tone  string `json:"tone,omitempty"`
}

// ---- Workflow payloads ----

type WhatIfChange struct {
	Object string `json:"object"`
	Detail string `json:"detail"`
	Change string `json:"change"`
}

type WhatIfSkip struct {
	Object string `json:"object"`
	Reason string `json:"reason"`
}

// WhatIfBlock is a target that will NOT be changed because it is mastered by
// on-prem Active Directory. Unlike a skip (a no-op), a block is a hard refusal:
// the write is never queued, so RTM cannot fire a cloud change that on-prem AD
// would reject or overwrite at the next sync. Resolution tells the technician
// where to make the change instead.
type WhatIfBlock struct {
	Object     string `json:"object"`
	Reason     string `json:"reason"`
	Resolution string `json:"resolution"`
}

type WhatIfPreview struct {
	ApprovalToken      string `json:"approvalToken,omitempty"`
	Action             string `json:"action"`
	Tenant             string `json:"tenant"`
	Risk               string `json:"risk"`
	RequiredPermission string `json:"requiredPermission"`
	TargetCount        int    `json:"targetCount"`
	// TargetNoun is the plural object type ("users", "mailboxes", "sites") so
	// the UI labels the target count for the right entity family.
	TargetNoun string         `json:"targetNoun"`
	Changes    []WhatIfChange `json:"changes"`
	MoreCount  int            `json:"moreCount"`
	Warnings   []string       `json:"warnings"`
	Skipped    []WhatIfSkip   `json:"skipped"`
	// Blocked lists targets refused because they are mastered on-prem.
	Blocked []WhatIfBlock `json:"blocked"`
}

// JobRef is the async-operation response (API Spec → Async Operations).
type JobRef struct {
	JobID            string            `json:"job_id"`
	Status           string            `json:"status"`
	OneTimePasswords []OneTimePassword `json:"oneTimePasswords,omitempty"`
}

// OneTimePassword is returned only by the synchronous password-reset and
// compromised-user workflows. It is never stored in RTM's jobs, changes,
// audits, or logs and the response is marked no-store.
type OneTimePassword struct {
	UserID   string `json:"userId"`
	User     string `json:"user"`
	UPN      string `json:"upn"`
	Password string `json:"password"`
}
