// Package graph is the Microsoft integration layer. Microsoft-sourced data
// (users, groups, licensing, mailboxes, sites, cross-tenant reports) is read
// through the Provider interface so the rest of the app never talks to Graph
// directly (Coding Standards: keep Microsoft clients server-side only).
//
// Two implementations:
//   - sampleProvider: seeded data, used when no Entra app is configured.
//   - graphClient:    real Microsoft Graph via app-only (client-credentials)
//     tokens, used when RTM_ENTRA_* env vars are set.
package graph

import (
	"context"
	"log/slog"

	"github.com/rarity/rtm/internal/model"
)

type Provider interface {
	Users(ctx context.Context, tenantID string) ([]model.User, error)
	Groups(ctx context.Context, tenantID string) ([]model.Group, error)
	GroupMembers(ctx context.Context, tenantID, groupID string) ([]model.GroupMember, error)
	Licenses(ctx context.Context, tenantID string) ([]model.License, error)
	Mailboxes(ctx context.Context, tenantID string) ([]model.Mailbox, error)
	// MailboxSettings reads one mailbox's auto-reply + forwarding state (live:
	// GET /users/{id}/mailboxSettings + the RTM-managed forwarding inbox rule;
	// needs MailboxSettings.Read).
	MailboxSettings(ctx context.Context, tenantID, mailboxID string) (model.MailboxSettings, error)
	// MailboxPermissions lists delegate grants together with explicit coverage
	// per permission family. The Exchange Admin REST API currently supplies
	// Send on Behalf; Full Access and Send As remain PowerShell-only.
	MailboxPermissions(ctx context.Context, tenantID, mailboxID string) (model.MailboxPermissionFeed, error)
	Sites(ctx context.Context, tenantID string) ([]model.Site, error)
	// SitePermissions lists who can access a site (owners/members/visitors,
	// direct grants, external users; live: GET /sites/{id}/permissions with
	// Sites.Read.All — Graph only exposes app grants there, deeper user-level
	// detail needs SharePoint REST per the Graph guide).
	SitePermissions(ctx context.Context, tenantID, siteID string) ([]model.SitePermission, error)
	GlobalReport(ctx context.Context, reportType string) (model.GlobalReport, error)
	TestConnection(ctx context.Context, tenantID string) error

	// Entra posture reads (read-only) feeding the readiness reports and the
	// tenant preflight check. Live permissions: MFARegistrations needs
	// AuditLog.Read.All (registration report); GuestAccounts uses User.Read.All
	// (+ AuditLog.Read.All and an Entra ID P1 license for sign-in activity,
	// degrading to empty LastSignIn without them); RoleAssignments needs
	// RoleManagement.Read.Directory or Directory.Read.All; CAExclusions needs
	// Policy.Read.All; AppCredentials needs Application.Read.All.
	MFARegistrations(ctx context.Context, tenantID string) ([]model.MFARegistration, error)
	GuestAccounts(ctx context.Context, tenantID string) ([]model.GuestAccount, error)
	RoleAssignments(ctx context.Context, tenantID string) ([]model.RoleAssignment, error)
	CAExclusions(ctx context.Context, tenantID string) ([]model.CAExclusion, error)
	AppCredentials(ctx context.Context, tenantID string) ([]model.AppCredential, error)
	LicenseReadiness(ctx context.Context, tenantID string) ([]model.LicenseReadinessIssue, error)
	// Preflight probes each read feature area with a harmless GET and reports
	// whether the tenant's app registration holds the permission (403 =
	// missing). Write permissions can't be probed without writing — those rows
	// come back "unchecked" with the required permission listed.
	Preflight(ctx context.Context, tenantID string) ([]model.PreflightCheck, error)
	// UserRaw reads the full directory object for one user (every attribute
	// the app can $select, incl. on-prem extension attributes and identities).
	UserRaw(ctx context.Context, tenantID, userID string) (model.UserRaw, error)

	// Security Operations reads Microsoft Defender XDR incidents through the
	// current Graph incidents API. SecurityIncident.Read.All is the least
	// privileged application permission for this Phase 1 surface. Provider
	// mode is returned with the feed so sample coverage is always explicit.
	SecurityIncidents(ctx context.Context, tenantID string) (model.SecurityIncidentFeed, error)
	SecurityIncident(ctx context.Context, tenantID, incidentID string) (model.SecurityIncidentDetail, error)

	// Share Detective reads/writes. UserGroupIDs lists the subject's transitive
	// group memberships (classifying group-based access); SharedItems walks a
	// site's document libraries for items with their own sharing state (bounded
	// traversal — coverage gaps are reported, never silent). The two deletes
	// remove one permission entry (live: Sites.FullControl.All); they back the
	// revoke workflow and are never called outside it.
	UserGroupIDs(ctx context.Context, tenantID, userID string) ([]string, error)
	SharedItems(ctx context.Context, tenantID, siteID string) ([]model.SharedItem, error)
	DeleteSitePermission(ctx context.Context, tenantID, siteID, permissionID string) error
	DeleteItemPermission(ctx context.Context, tenantID, siteID, driveID, itemID, permissionID string) error
	// DirectorySyncEnabled reports the tenant-level Entra Connect signal
	// (organization.onPremisesSyncEnabled): the authoritative "is this tenant
	// hybrid" flag, independent of whether any synced objects appear in the
	// first page of users/groups. nil = Microsoft reports it as never
	// configured (or the provider can't know, e.g. sample mode).
	DirectorySyncEnabled(ctx context.Context, tenantID string) (*bool, error)

	// Writes (executed by the job worker after the What-If gate). Live mode
	// needs GroupMember.ReadWrite.All (group membership) and
	// User.ReadWrite.All (sign-in and licensing) plus the action-specific
	// password/authentication/session permissions surfaced by preflight.
	AddGroupMembers(ctx context.Context, tenantID, groupID string, userIDs []string) error
	RemoveGroupMembers(ctx context.Context, tenantID, groupID string, userIDs []string) error
	// SetAccountEnabled blocks (false) or unblocks (true) sign-in for a user.
	SetAccountEnabled(ctx context.Context, tenantID, userID string, enabled bool) error
	// AssignLicense adds (remove=false) or removes (remove=true) a license SKU.
	AssignLicense(ctx context.Context, tenantID, userID, skuID string, remove bool) error
	// RevokeSessions invalidates all refresh/session tokens for a user.
	RevokeSessions(ctx context.Context, tenantID, userID string) error
	// ResetPassword assigns a random temporary password and forces a change at
	// the next sign-in. The caller owns the one-time password and must never
	// persist it in a job payload, change record, audit entry, or application log.
	ResetPassword(ctx context.Context, tenantID, userID, temporaryPassword string) error
	// ResetMFA removes the user's registered non-password authentication methods
	// so trusted factors cannot be reused after an account compromise.
	ResetMFA(ctx context.Context, tenantID, userID string) error
	// CreateGroup provisions a new group and returns it.
	CreateGroup(ctx context.Context, tenantID string, in NewGroup) (model.Group, error)

	// Exchange writes. Forwarding and auto-reply are Graph-backed in live mode
	// (MailboxSettings.ReadWrite): auto-reply via PATCH mailboxSettings,
	// forwarding via an RTM-managed inbox rule. Send on Behalf uses the
	// Exchange Online Admin API; Full Access and Send As still fail closed until
	// controlled Exchange Online PowerShell execution lands.
	SetMailboxForwarding(ctx context.Context, tenantID, mailboxID, forwardTo string) error // empty forwardTo clears
	SetAutoReply(ctx context.Context, tenantID, mailboxID string, enabled bool, message string) error
	SetMailboxPermission(ctx context.Context, tenantID, mailboxID, delegateID, permission string, remove bool) error

	// SharePoint writes. Graph's site-permission API only grants to apps and
	// site sharing capability is a SharePoint admin setting, so both return
	// ErrExchangeOnly-style errors (ErrSharePointOnly) in live mode; sample
	// mode models them fully.
	SetSiteAccess(ctx context.Context, tenantID, siteID, userID, role string, remove bool) error
	SetSiteSharing(ctx context.Context, tenantID, siteID, level string) error

	// Mode reports "sample", "graph", or "auto" for diagnostics/version output.
	Mode() string
}

// UserCounter is an optional lightweight capability used by tenant summaries.
// It avoids downloading and enriching the full user inventory just to render a
// count. Every built-in provider implements it; external test doubles may omit
// it and the server will retain the stored fallback count.
type UserCounter interface {
	UserCount(ctx context.Context, tenantID string) (int, error)
}

// Config carries Entra app credentials (client-credentials / app-only flow).
type Config struct {
	ClientID     string
	ClientSecret string
	TenantID     string // Entra tenant that owns the multi-tenant app

	SharePointClientID        string
	SharePointCertificatePath string
	SharePointPrivateKeyPath  string
}

func (c Config) configured() bool {
	return c.ClientID != "" && c.ClientSecret != "" && c.TenantID != ""
}

// Group types RTM can create through Graph. Distribution, dynamic distribution,
// and mail-enabled security group creation is Exchange-managed, so those aren't
// offered in the Graph create flow.
const (
	GroupTypeM365     = "M365"     // Microsoft 365 (Unified) group
	GroupTypeSecurity = "Security" // security group
)

// NewGroup is the input to CreateGroup.
type NewGroup struct {
	DisplayName  string
	Description  string
	MailNickname string
	Type         string // GroupTypeM365 | GroupTypeSecurity
}

// Vocabulary for the Exchange/SharePoint write actions. Handlers validate
// requests against these; the sample provider and change records reuse the
// same strings so mock and live shapes stay identical.
const (
	MailboxPermFullAccess   = "Full Access"
	MailboxPermSendAs       = "Send As"
	MailboxPermSendOnBehalf = "Send on Behalf"

	SiteRoleRead        = "Read"
	SiteRoleEdit        = "Edit"
	SiteRoleFullControl = "Full Control"

	SharingInternal = "Internal" // no external sharing
	SharingExternal = "External" // existing + new guests
	SharingAnyone   = "Anyone"   // anonymous links
)

// TenantAuth is the connection material for one managed tenant: the Entra
// authority to token against (Microsoft tenant id or verified domain) plus,
// optionally, the tenant's own app registration. Empty fields fall back to the
// global RTM_ENTRA_* app configured at startup.
//
// The Exchange* / SharePoint* fields carry dedicated app registrations for the
// Exchange Online and SharePoint admin APIs (set up per tenant just like the
// Graph app). Empty means "reuse the Graph app above". They are consumed by
// the live Exchange Online / SharePoint admin clients (mailbox permissions,
// user-level site grants, per-site sharing) when those integrations are
// enabled; the Graph client ignores them.
type TenantAuth struct {
	Authority    string
	ClientID     string
	ClientSecret string

	ExchangeClientID       string
	ExchangeClientSecret   string
	SharePointClientID     string
	SharePointClientSecret string
	SharePointAdminURL     string
}

// AuthorityResolver maps an RTM tenant id (the {tenantId} handlers receive) to
// that tenant's TenantAuth. Wired from the tenants store in cmd/api so each
// managed tenant gets its own app-only token — and, when set, its own app.
type AuthorityResolver func(ctx context.Context, tenantID string) (TenantAuth, error)

// NewProvider picks the Microsoft integration mode. All satisfy the same
// interface, so no caller changes when credentials appear:
//   - Global RTM_ENTRA_* app configured → live Graph for every tenant.
//   - No global app but a resolver → hybrid: tenants whose stored connection
//     carries its own app credentials (added via the GUI) go live immediately;
//     tenants without stay on sample data. No restart or env change needed.
//   - Neither → sample provider only.
func NewProvider(cfg Config, log *slog.Logger, resolve AuthorityResolver) Provider {
	if cfg.configured() {
		log.Info("graph: using live Microsoft Graph client")
		return newGraphClient(cfg, log, resolve)
	}
	if resolve != nil {
		log.Info("graph: no global Entra app — live per-tenant when a tenant has its own app credentials, sample otherwise")
		return &hybridProvider{
			live:    newGraphClient(cfg, log, resolve),
			sample:  newSampleProvider(),
			resolve: resolve,
		}
	}
	log.Info("graph: no Entra app configured — using sample provider")
	sp := newSampleProvider()
	return &sp
}
