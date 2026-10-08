package graph

import (
	"context"

	"github.com/rarity/rtm/internal/model"
)

// hybridProvider routes per tenant: a tenant whose stored connection includes
// its own Entra app credentials is read live from Microsoft Graph; everything
// else (the seeded example tenant, tenants added without credentials) serves
// sample data. This is what makes "connect a tenant from the GUI" fully live
// without a global RTM_ENTRA_* app or a restart.
type hybridProvider struct {
	live    *graphClient
	sample  sampleProvider
	resolve AuthorityResolver
}

func (h *hybridProvider) Mode() string { return "auto" }

// isLive reports whether the tenant carries its own app credentials. Resolver
// errors fall back to sample so an unknown tenant degrades rather than 500s.
func (h *hybridProvider) isLive(ctx context.Context, tenantID string) bool {
	if tenantID == "" {
		return false
	}
	auth, err := h.resolve(ctx, tenantID)
	return err == nil && auth.ClientID != "" && auth.ClientSecret != ""
}

func (h *hybridProvider) DirectorySyncEnabled(ctx context.Context, tenantID string) (*bool, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.DirectorySyncEnabled(ctx, tenantID)
	}
	return h.sample.DirectorySyncEnabled(ctx, tenantID)
}

func (h *hybridProvider) Users(ctx context.Context, tenantID string) ([]model.User, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.Users(ctx, tenantID)
	}
	return h.sample.Users(ctx, tenantID)
}

func (h *hybridProvider) UserCount(ctx context.Context, tenantID string) (int, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.UserCount(ctx, tenantID)
	}
	return h.sample.UserCount(ctx, tenantID)
}

func (h *hybridProvider) Groups(ctx context.Context, tenantID string) ([]model.Group, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.Groups(ctx, tenantID)
	}
	return h.sample.Groups(ctx, tenantID)
}

func (h *hybridProvider) GroupMembers(ctx context.Context, tenantID, groupID string) ([]model.GroupMember, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.GroupMembers(ctx, tenantID, groupID)
	}
	return h.sample.GroupMembers(ctx, tenantID, groupID)
}

func (h *hybridProvider) Licenses(ctx context.Context, tenantID string) ([]model.License, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.Licenses(ctx, tenantID)
	}
	return h.sample.Licenses(ctx, tenantID)
}

func (h *hybridProvider) Mailboxes(ctx context.Context, tenantID string) ([]model.Mailbox, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.Mailboxes(ctx, tenantID)
	}
	return h.sample.Mailboxes(ctx, tenantID)
}

func (h *hybridProvider) MailboxSettings(ctx context.Context, tenantID, mailboxID string) (model.MailboxSettings, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.MailboxSettings(ctx, tenantID, mailboxID)
	}
	return h.sample.MailboxSettings(ctx, tenantID, mailboxID)
}

func (h *hybridProvider) MailboxPermissions(ctx context.Context, tenantID, mailboxID string) (model.MailboxPermissionFeed, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.MailboxPermissions(ctx, tenantID, mailboxID)
	}
	return h.sample.MailboxPermissions(ctx, tenantID, mailboxID)
}

func (h *hybridProvider) SitePermissions(ctx context.Context, tenantID, siteID string) ([]model.SitePermission, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.SitePermissions(ctx, tenantID, siteID)
	}
	return h.sample.SitePermissions(ctx, tenantID, siteID)
}

func (h *hybridProvider) SetMailboxForwarding(ctx context.Context, tenantID, mailboxID, forwardTo string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.SetMailboxForwarding(ctx, tenantID, mailboxID, forwardTo)
	}
	return h.sample.SetMailboxForwarding(ctx, tenantID, mailboxID, forwardTo)
}

func (h *hybridProvider) SetAutoReply(ctx context.Context, tenantID, mailboxID string, enabled bool, message string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.SetAutoReply(ctx, tenantID, mailboxID, enabled, message)
	}
	return h.sample.SetAutoReply(ctx, tenantID, mailboxID, enabled, message)
}

func (h *hybridProvider) SetMailboxPermission(ctx context.Context, tenantID, mailboxID, delegateID, permission string, remove bool) error {
	if h.isLive(ctx, tenantID) {
		return h.live.SetMailboxPermission(ctx, tenantID, mailboxID, delegateID, permission, remove)
	}
	return h.sample.SetMailboxPermission(ctx, tenantID, mailboxID, delegateID, permission, remove)
}

func (h *hybridProvider) SetSiteAccess(ctx context.Context, tenantID, siteID, userID, role string, remove bool) error {
	if h.isLive(ctx, tenantID) {
		return h.live.SetSiteAccess(ctx, tenantID, siteID, userID, role, remove)
	}
	return h.sample.SetSiteAccess(ctx, tenantID, siteID, userID, role, remove)
}

func (h *hybridProvider) SetSiteSharing(ctx context.Context, tenantID, siteID, level string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.SetSiteSharing(ctx, tenantID, siteID, level)
	}
	return h.sample.SetSiteSharing(ctx, tenantID, siteID, level)
}

func (h *hybridProvider) Sites(ctx context.Context, tenantID string) ([]model.Site, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.Sites(ctx, tenantID)
	}
	return h.sample.Sites(ctx, tenantID)
}

func (h *hybridProvider) AddGroupMembers(ctx context.Context, tenantID, groupID string, userIDs []string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.AddGroupMembers(ctx, tenantID, groupID, userIDs)
	}
	return h.sample.AddGroupMembers(ctx, tenantID, groupID, userIDs)
}

func (h *hybridProvider) RemoveGroupMembers(ctx context.Context, tenantID, groupID string, userIDs []string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.RemoveGroupMembers(ctx, tenantID, groupID, userIDs)
	}
	return h.sample.RemoveGroupMembers(ctx, tenantID, groupID, userIDs)
}

func (h *hybridProvider) SetAccountEnabled(ctx context.Context, tenantID, userID string, enabled bool) error {
	if h.isLive(ctx, tenantID) {
		return h.live.SetAccountEnabled(ctx, tenantID, userID, enabled)
	}
	return h.sample.SetAccountEnabled(ctx, tenantID, userID, enabled)
}

func (h *hybridProvider) AssignLicense(ctx context.Context, tenantID, userID, skuID string, remove bool) error {
	if h.isLive(ctx, tenantID) {
		return h.live.AssignLicense(ctx, tenantID, userID, skuID, remove)
	}
	return h.sample.AssignLicense(ctx, tenantID, userID, skuID, remove)
}

func (h *hybridProvider) RevokeSessions(ctx context.Context, tenantID, userID string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.RevokeSessions(ctx, tenantID, userID)
	}
	return h.sample.RevokeSessions(ctx, tenantID, userID)
}

func (h *hybridProvider) ResetPassword(ctx context.Context, tenantID, userID, temporaryPassword string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.ResetPassword(ctx, tenantID, userID, temporaryPassword)
	}
	return h.sample.ResetPassword(ctx, tenantID, userID, temporaryPassword)
}

func (h *hybridProvider) ResetMFA(ctx context.Context, tenantID, userID string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.ResetMFA(ctx, tenantID, userID)
	}
	return h.sample.ResetMFA(ctx, tenantID, userID)
}

func (h *hybridProvider) CreateGroup(ctx context.Context, tenantID string, in NewGroup) (model.Group, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.CreateGroup(ctx, tenantID, in)
	}
	return h.sample.CreateGroup(ctx, tenantID, in)
}

func (h *hybridProvider) TestConnection(ctx context.Context, tenantID string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.TestConnection(ctx, tenantID)
	}
	return h.sample.TestConnection(ctx, tenantID)
}

func (h *hybridProvider) MFARegistrations(ctx context.Context, tenantID string) ([]model.MFARegistration, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.MFARegistrations(ctx, tenantID)
	}
	return h.sample.MFARegistrations(ctx, tenantID)
}

func (h *hybridProvider) GuestAccounts(ctx context.Context, tenantID string) ([]model.GuestAccount, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.GuestAccounts(ctx, tenantID)
	}
	return h.sample.GuestAccounts(ctx, tenantID)
}

func (h *hybridProvider) RoleAssignments(ctx context.Context, tenantID string) ([]model.RoleAssignment, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.RoleAssignments(ctx, tenantID)
	}
	return h.sample.RoleAssignments(ctx, tenantID)
}

func (h *hybridProvider) CAExclusions(ctx context.Context, tenantID string) ([]model.CAExclusion, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.CAExclusions(ctx, tenantID)
	}
	return h.sample.CAExclusions(ctx, tenantID)
}

func (h *hybridProvider) AppCredentials(ctx context.Context, tenantID string) ([]model.AppCredential, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.AppCredentials(ctx, tenantID)
	}
	return h.sample.AppCredentials(ctx, tenantID)
}

func (h *hybridProvider) LicenseReadiness(ctx context.Context, tenantID string) ([]model.LicenseReadinessIssue, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.LicenseReadiness(ctx, tenantID)
	}
	return h.sample.LicenseReadiness(ctx, tenantID)
}

func (h *hybridProvider) Preflight(ctx context.Context, tenantID string) ([]model.PreflightCheck, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.Preflight(ctx, tenantID)
	}
	return h.sample.Preflight(ctx, tenantID)
}

func (h *hybridProvider) UserRaw(ctx context.Context, tenantID, userID string) (model.UserRaw, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.UserRaw(ctx, tenantID, userID)
	}
	return h.sample.UserRaw(ctx, tenantID, userID)
}

func (h *hybridProvider) SecurityIncidents(ctx context.Context, tenantID string) (model.SecurityIncidentFeed, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.SecurityIncidents(ctx, tenantID)
	}
	return h.sample.SecurityIncidents(ctx, tenantID)
}

func (h *hybridProvider) SecurityIncident(ctx context.Context, tenantID, incidentID string) (model.SecurityIncidentDetail, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.SecurityIncident(ctx, tenantID, incidentID)
	}
	return h.sample.SecurityIncident(ctx, tenantID, incidentID)
}

func (h *hybridProvider) UserGroupIDs(ctx context.Context, tenantID, userID string) ([]string, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.UserGroupIDs(ctx, tenantID, userID)
	}
	return h.sample.UserGroupIDs(ctx, tenantID, userID)
}

func (h *hybridProvider) SharedItems(ctx context.Context, tenantID, siteID string) ([]model.SharedItem, error) {
	if h.isLive(ctx, tenantID) {
		return h.live.SharedItems(ctx, tenantID, siteID)
	}
	return h.sample.SharedItems(ctx, tenantID, siteID)
}

func (h *hybridProvider) SharePointInventory(ctx context.Context, tenantID string, request SharePointInventoryRequest) ([]model.SharePointInventoryNode, []string, error) {
	if h.live.sharePointConfigured() || h.isLive(ctx, tenantID) {
		return h.live.SharePointInventory(ctx, tenantID, request)
	}
	return h.sample.SharePointInventory(ctx, tenantID, request)
}

func (h *hybridProvider) SharePointPreflight(ctx context.Context, tenantID string) []model.PreflightCheck {
	return h.live.SharePointPreflight(ctx, tenantID)
}

func (h *hybridProvider) SharePointScopePermissions(ctx context.Context, tenantID string, target model.SharePointPermissionTarget) ([]model.SharePointScopePermission, error) {
	if h.live.sharePointConfigured() || h.isLive(ctx, tenantID) {
		return h.live.SharePointScopePermissions(ctx, tenantID, target)
	}
	return h.sample.SharePointScopePermissions(ctx, tenantID, target)
}

func (h *hybridProvider) SetSharePointScopePermission(ctx context.Context, tenantID string, change model.SharePointPermissionChange) error {
	if h.live.sharePointConfigured() || h.isLive(ctx, tenantID) {
		return h.live.SetSharePointScopePermission(ctx, tenantID, change)
	}
	return h.sample.SetSharePointScopePermission(ctx, tenantID, change)
}

func (h *hybridProvider) DeleteSitePermission(ctx context.Context, tenantID, siteID, permissionID string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.DeleteSitePermission(ctx, tenantID, siteID, permissionID)
	}
	return h.sample.DeleteSitePermission(ctx, tenantID, siteID, permissionID)
}

func (h *hybridProvider) DeleteItemPermission(ctx context.Context, tenantID, siteID, driveID, itemID, permissionID string) error {
	if h.isLive(ctx, tenantID) {
		return h.live.DeleteItemPermission(ctx, tenantID, siteID, driveID, itemID, permissionID)
	}
	return h.sample.DeleteItemPermission(ctx, tenantID, siteID, driveID, itemID, permissionID)
}

// GlobalReport serves the seeded dataset; in hybrid mode the cross-tenant
// fan-out (internal/reports) reads per tenant through the methods above
// instead, so live tenants contribute live rows and sample tenants sample
// rows.
func (h *hybridProvider) GlobalReport(ctx context.Context, reportType string) (model.GlobalReport, error) {
	return h.sample.GlobalReport(ctx, reportType)
}
