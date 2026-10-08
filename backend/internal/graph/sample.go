package graph

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rarity/rtm/internal/model"
)

// sampleWrites holds the mutations applied in sample mode so created objects
// persist and reappear on the next read (per tenant). Shared by value copies
// of sampleProvider via the pointer, so the hybrid provider and the top-level
// sample provider see the same state.
type sampleWrites struct {
	mu     sync.Mutex
	groups map[string][]model.Group // tenantID → created groups
	// Exchange/SharePoint overlays, keyed tenantID → object id. Reads merge
	// these over the seeded defaults so demo writes stick.
	mailboxSettings map[string]map[string]model.MailboxSettings
	mailboxPerms    map[string]map[string][]model.MailboxPermission
	sitePerms       map[string]map[string][]model.SitePermission
	siteSharing     map[string]map[string]string // siteID → sharing level
	// Deleted permission entries (Share Detective revoke), keyed
	// tenantID → "siteID|permID" (site level) or "driveID|itemID|permID"
	// (item level). Reads filter these out so demo revokes stick.
	permDeletes map[string]map[string]bool
}

// sampleProvider returns seeded Microsoft-shaped data (no live Graph calls).
type sampleProvider struct {
	writes *sampleWrites
}

func newSampleProvider() sampleProvider {
	return sampleProvider{writes: &sampleWrites{
		groups:          map[string][]model.Group{},
		mailboxSettings: map[string]map[string]model.MailboxSettings{},
		mailboxPerms:    map[string]map[string][]model.MailboxPermission{},
		sitePerms:       map[string]map[string][]model.SitePermission{},
		siteSharing:     map[string]map[string]string{},
		permDeletes:     map[string]map[string]bool{},
	}}
}

func (sampleProvider) Mode() string { return "sample" }

func (sampleProvider) TestConnection(context.Context, string) error { return nil }

// DirectorySyncEnabled: the sample org models a mixed tenant (some synced
// users), so it reports sync as enabled.
func (sampleProvider) DirectorySyncEnabled(context.Context, string) (*bool, error) {
	enabled := true
	return &enabled, nil
}

func (sampleProvider) Users(context.Context, string) ([]model.User, error) {
	return sampleUsers, nil
}

func (sampleProvider) UserCount(context.Context, string) (int, error) {
	return len(sampleUsers), nil
}
func (s sampleProvider) Groups(_ context.Context, tenantID string) ([]model.Group, error) {
	groups := append([]model.Group(nil), sampleGroups...)
	if s.writes != nil {
		s.writes.mu.Lock()
		groups = append(groups, s.writes.groups[tenantID]...)
		s.writes.mu.Unlock()
	}
	return groups, nil
}
func (sampleProvider) GroupMembers(context.Context, string, string) ([]model.GroupMember, error) {
	return sampleGroupMembers, nil
}
func (sampleProvider) Licenses(context.Context, string) ([]model.License, error) {
	return sampleLicenses, nil
}
func (sampleProvider) Mailboxes(context.Context, string) ([]model.Mailbox, error) {
	return sampleMailboxes, nil
}
func (s sampleProvider) Sites(_ context.Context, tenantID string) ([]model.Site, error) {
	sites := append([]model.Site(nil), sampleSites...)
	if s.writes != nil {
		s.writes.mu.Lock()
		for i, site := range sites {
			if lvl, ok := s.writes.siteSharing[tenantID][site.ID]; ok {
				sites[i].ExternalSharing = lvl
			}
		}
		s.writes.mu.Unlock()
	}
	return sites, nil
}

// MailboxSettings serves the seeded defaults overlaid with any writes made in
// this session (forwarding / auto-reply actions).
func (s sampleProvider) MailboxSettings(_ context.Context, tenantID, mailboxID string) (model.MailboxSettings, error) {
	if s.writes != nil {
		s.writes.mu.Lock()
		if ms, ok := s.writes.mailboxSettings[tenantID][mailboxID]; ok {
			s.writes.mu.Unlock()
			return ms, nil
		}
		s.writes.mu.Unlock()
	}
	if ms, ok := sampleMailboxSettings[mailboxID]; ok {
		return ms, nil
	}
	for _, m := range sampleMailboxes {
		if m.ID == mailboxID {
			return defaultSampleMailboxSettings(mailboxID), nil
		}
	}
	return model.MailboxSettings{}, fmt.Errorf("sample: unknown mailbox %s", mailboxID)
}

func (s sampleProvider) MailboxPermissions(_ context.Context, tenantID, mailboxID string) (model.MailboxPermissionFeed, error) {
	permissions := []model.MailboxPermission(nil)
	if s.writes != nil {
		s.writes.mu.Lock()
		if perms, ok := s.writes.mailboxPerms[tenantID][mailboxID]; ok {
			permissions = append([]model.MailboxPermission(nil), perms...)
			s.writes.mu.Unlock()
			return sampleMailboxPermissionFeed(permissions), nil
		}
		s.writes.mu.Unlock()
	}
	permissions = append(permissions, sampleMailboxPerms[mailboxID]...)
	return sampleMailboxPermissionFeed(permissions), nil
}

func sampleMailboxPermissionFeed(permissions []model.MailboxPermission) model.MailboxPermissionFeed {
	return model.MailboxPermissionFeed{
		Permissions: permissions,
		Coverage: []model.MailboxPermissionCoverage{
			{Permission: MailboxPermFullAccess, Status: "collected", Source: "Sample data"},
			{Permission: MailboxPermSendAs, Status: "collected", Source: "Sample data"},
			{Permission: MailboxPermSendOnBehalf, Status: "collected", Source: "Sample data"},
		},
	}
}

func (s sampleProvider) SitePermissions(_ context.Context, tenantID, siteID string) ([]model.SitePermission, error) {
	if s.writes != nil {
		s.writes.mu.Lock()
		if perms, ok := s.writes.sitePerms[tenantID][siteID]; ok {
			out := append([]model.SitePermission(nil), perms...)
			s.writes.mu.Unlock()
			return out, nil
		}
		s.writes.mu.Unlock()
	}
	return append([]model.SitePermission(nil), sampleSitePerms[siteID]...), nil
}

// currentSettings resolves the effective settings for a mailbox (overlay or
// seed) with the writes lock already held.
func (w *sampleWrites) currentSettings(tenantID, mailboxID string) model.MailboxSettings {
	if ms, ok := w.mailboxSettings[tenantID][mailboxID]; ok {
		return ms
	}
	if ms, ok := sampleMailboxSettings[mailboxID]; ok {
		return ms
	}
	return defaultSampleMailboxSettings(mailboxID)
}

func (w *sampleWrites) putSettings(tenantID string, ms model.MailboxSettings) {
	if w.mailboxSettings[tenantID] == nil {
		w.mailboxSettings[tenantID] = map[string]model.MailboxSettings{}
	}
	w.mailboxSettings[tenantID][ms.MailboxID] = ms
}

func (s sampleProvider) SetMailboxForwarding(_ context.Context, tenantID, mailboxID, forwardTo string) error {
	if s.writes == nil {
		return nil
	}
	s.writes.mu.Lock()
	defer s.writes.mu.Unlock()
	ms := s.writes.currentSettings(tenantID, mailboxID)
	ms.ForwardingTo = forwardTo
	ms.RulesAvailable = true
	ms.ForwardingRules = []model.MailboxForwardingRule{}
	if forwardTo != "" {
		ms.ForwardingRules = append(ms.ForwardingRules, model.MailboxForwardingRule{
			ID: "rtm_forward", Name: rtmForwardRule, Enabled: true, Mode: "Forward",
			Recipients: []string{forwardTo}, ManagedByRTM: true,
		})
	}
	s.writes.putSettings(tenantID, ms)
	return nil
}

func (s sampleProvider) SetAutoReply(_ context.Context, tenantID, mailboxID string, enabled bool, message string) error {
	if s.writes == nil {
		return nil
	}
	s.writes.mu.Lock()
	defer s.writes.mu.Unlock()
	ms := s.writes.currentSettings(tenantID, mailboxID)
	ms.AutoReply = enabled
	ms.AutoReplyStatus = "disabled"
	if enabled {
		ms.AutoReplyStatus = "alwaysEnabled"
	}
	ms.AutoReplyMessage = message
	if !enabled {
		ms.AutoReplyMessage = ""
	}
	s.writes.putSettings(tenantID, ms)
	return nil
}

func defaultSampleMailboxSettings(mailboxID string) model.MailboxSettings {
	return model.MailboxSettings{
		MailboxID: mailboxID, AutoReplyStatus: "disabled", ForwardingRules: []model.MailboxForwardingRule{},
		RulesAvailable: true, TimeZone: "Pacific Standard Time", Language: "English (United States)",
		DateFormat: "M/d/yyyy", TimeFormat: "h:mm tt", WorkingDays: []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
		WorkingHoursStart: "08:00:00.0000000", WorkingHoursEnd: "17:00:00.0000000", WorkingHoursTimeZone: "Pacific Standard Time",
		UserPurpose: "user", DelegateMeetingMessageDelivery: "sendToDelegateAndInformationToPrincipal",
	}
}

func (s sampleProvider) SetMailboxPermission(_ context.Context, tenantID, mailboxID, delegateID, permission string, remove bool) error {
	if s.writes == nil {
		return nil
	}
	name, upn := sampleUserName(delegateID)
	if name == "" {
		return fmt.Errorf("sample: unknown delegate %s", delegateID)
	}
	s.writes.mu.Lock()
	defer s.writes.mu.Unlock()
	perms, ok := s.writes.mailboxPerms[tenantID][mailboxID]
	if !ok {
		perms = append([]model.MailboxPermission(nil), sampleMailboxPerms[mailboxID]...)
	}
	next := perms[:0]
	for _, p := range perms {
		if p.DelegateUPN == upn && p.Permission == permission {
			continue // dedupe on grant, drop on revoke
		}
		next = append(next, p)
	}
	if !remove {
		next = append(next, model.MailboxPermission{
			ID: fmt.Sprintf("mp_%d", time.Now().UnixNano()&0xffffff), Delegate: name,
			DelegateUPN: upn, Permission: permission, Granted: time.Now().Format("2006-01-02"),
		})
	}
	if s.writes.mailboxPerms[tenantID] == nil {
		s.writes.mailboxPerms[tenantID] = map[string][]model.MailboxPermission{}
	}
	s.writes.mailboxPerms[tenantID][mailboxID] = next
	return nil
}

func (s sampleProvider) SetSiteAccess(_ context.Context, tenantID, siteID, userID, role string, remove bool) error {
	if s.writes == nil {
		return nil
	}
	name, upn := sampleUserName(userID)
	if name == "" {
		return fmt.Errorf("sample: unknown user %s", userID)
	}
	s.writes.mu.Lock()
	defer s.writes.mu.Unlock()
	perms, ok := s.writes.sitePerms[tenantID][siteID]
	if !ok {
		perms = append([]model.SitePermission(nil), sampleSitePerms[siteID]...)
	}
	next := perms[:0]
	for _, p := range perms {
		if p.PrincipalUPN == upn && p.Source == "Direct" {
			continue
		}
		next = append(next, p)
	}
	if !remove {
		typ := "User"
		for _, u := range sampleUsers {
			if u.ID == userID && u.Status == "Guest" {
				typ = "External"
			}
		}
		next = append(next, model.SitePermission{
			ID: fmt.Sprintf("sp_%d", time.Now().UnixNano()&0xffffff), Principal: name,
			PrincipalUPN: upn, Type: typ, Role: role, Source: "Direct",
		})
	}
	if s.writes.sitePerms[tenantID] == nil {
		s.writes.sitePerms[tenantID] = map[string][]model.SitePermission{}
	}
	s.writes.sitePerms[tenantID][siteID] = next
	return nil
}

func (s sampleProvider) SetSiteSharing(_ context.Context, tenantID, siteID, level string) error {
	if s.writes == nil {
		return nil
	}
	s.writes.mu.Lock()
	defer s.writes.mu.Unlock()
	if s.writes.siteSharing[tenantID] == nil {
		s.writes.siteSharing[tenantID] = map[string]string{}
	}
	s.writes.siteSharing[tenantID][siteID] = level
	return nil
}

// sampleUserName resolves a sample user id to (name, upn); empty when unknown.
func sampleUserName(userID string) (string, string) {
	for _, u := range sampleUsers {
		if u.ID == userID {
			return u.Name, u.UPN
		}
	}
	return "", ""
}

// Sample writes succeed without touching anything (no live Microsoft side).
func (sampleProvider) AddGroupMembers(context.Context, string, string, []string) error {
	return nil
}
func (sampleProvider) RemoveGroupMembers(context.Context, string, string, []string) error {
	return nil
}
func (sampleProvider) SetAccountEnabled(context.Context, string, string, bool) error {
	return nil
}
func (sampleProvider) AssignLicense(context.Context, string, string, string, bool) error {
	return nil
}
func (sampleProvider) RevokeSessions(context.Context, string, string) error {
	return nil
}
func (sampleProvider) ResetPassword(context.Context, string, string, string) error {
	return nil
}
func (sampleProvider) ResetMFA(context.Context, string, string) error {
	return nil
}

// CreateGroup persists a group in the sample store so it shows on the next
// Groups() read (the demo's Contoso tenant behaves like a real one).
func (s sampleProvider) CreateGroup(_ context.Context, tenantID string, in NewGroup) (model.Group, error) {
	typ, mail := "Security", "No"
	if in.Type == GroupTypeM365 {
		typ, mail = "M365", "Yes"
	}
	g := model.Group{
		ID:         fmt.Sprintf("grp_new_%d", time.Now().UnixNano()&0xffffff),
		Name:       in.DisplayName,
		Type:       typ,
		Membership: "Assigned",
		Members:    0,
		Mail:       mail,
		Service:    "Graph",
		Source:     "Cloud",
	}
	if s.writes != nil {
		s.writes.mu.Lock()
		s.writes.groups[tenantID] = append(s.writes.groups[tenantID], g)
		s.writes.mu.Unlock()
	}
	return g, nil
}
func (sampleProvider) GlobalReport(_ context.Context, reportType string) (model.GlobalReport, error) {
	if r, ok := sampleReports[reportType]; ok {
		return r, nil
	}
	return sampleReports["mfa"], nil
}

// Contoso is intentionally a "mixed" tenant: the IT staff (Caleb, Julia) are
// synced from on-prem AD, matching the two "On-prem sync" groups below, so
// sample/offline mode exercises the hybrid write gate. Everyone else is
// cloud-only. Note these synced users can still be added to *cloud* groups and
// keep full licensing/session/Exchange/SharePoint actions — only their
// on-prem-mastered identity (name, sign-in state, synced-group membership) is
// off-limits.
var sampleUsers = []model.User{
	{ID: "usr_1", Name: "Avery Quinn", UPN: "avery.quinn@contoso.com", Department: "Sales", License: "E5", MFA: "Enabled", Status: "Active", LastSignIn: "1h ago", SourceOfAuthority: model.SourceCloud},
	{ID: "usr_2", Name: "Bianca Lopez", UPN: "bianca.lopez@contoso.com", Department: "Finance", License: "E5", MFA: "Enforced", Status: "Active", LastSignIn: "22m ago", SourceOfAuthority: model.SourceCloud},
	{ID: "usr_3", Name: "Caleb Stone", UPN: "caleb.stone@contoso.com", Department: "IT", License: "E5", MFA: "Enabled", Status: "Active", LastSignIn: "5m ago", SourceOfAuthority: model.SourceOnPrem},
	{ID: "usr_4", Name: "Dana White", UPN: "dana.white@contoso.com", Department: "Marketing", License: "E3", MFA: "Disabled", Status: "Active", LastSignIn: "3d ago", SourceOfAuthority: model.SourceCloud},
	{ID: "usr_5", Name: "Ethan Park", UPN: "ethan.park@contoso.com", Department: "Sales", License: "E3", MFA: "Enabled", Status: "Active", LastSignIn: "2h ago", SourceOfAuthority: model.SourceCloud},
	{ID: "usr_6", Name: "Farah Noor", UPN: "farah.noor@contoso.com", Department: "HR", License: "E5", MFA: "Enforced", Status: "Active", LastSignIn: "40m ago", SourceOfAuthority: model.SourceCloud},
	{ID: "usr_7", Name: "Gavin Reed", UPN: "gavin.reed@contoso.com", Department: "Sales", License: "—", MFA: "Disabled", Status: "Disabled", LastSignIn: "60d ago", SourceOfAuthority: model.SourceCloud},
	{ID: "usr_8", Name: "Hana Kim", UPN: "hana.kim@contoso.com", Department: "Finance", License: "E5", MFA: "Enabled", Status: "Active", LastSignIn: "12m ago", SourceOfAuthority: model.SourceCloud},
	{ID: "usr_9", Name: "Ivan Petrov", UPN: "ivan.petrov@partner.com", Department: "External", License: "—", MFA: "Disabled", Status: "Guest", LastSignIn: "8d ago", SourceOfAuthority: model.SourceCloud},
	{ID: "usr_10", Name: "Julia Sanz", UPN: "julia.sanz@contoso.com", Department: "IT", License: "E5", MFA: "Enforced", Status: "Active", LastSignIn: "just now", SourceOfAuthority: model.SourceOnPrem},
	// Kemal is deliberately enabled-but-unlicensed so the license-readiness
	// report has a real row to show.
	{ID: "usr_11", Name: "Kemal Yilmaz", UPN: "kemal.yilmaz@contoso.com", Department: "Operations", License: "—", MFA: "Enabled", Status: "Active", LastSignIn: "1d ago", SourceOfAuthority: model.SourceCloud},
	{ID: "usr_12", Name: "Lena Vogt", UPN: "lena.vogt@contoso.com", Department: "Marketing", License: "E3", MFA: "Disabled", Status: "Active", LastSignIn: "4h ago", SourceOfAuthority: model.SourceCloud},
}

func init() {
	lastSignInMinutes := []int{60, 22, 5, 4320, 120, 40, 86400, 12, 11520, 0, 1440, 240}
	sampleNow := time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)
	for i := range sampleUsers {
		user := &sampleUsers[i]
		parts := strings.Fields(user.Name)
		if len(parts) > 0 {
			user.GivenName = parts[0]
			user.Surname = strings.Join(parts[1:], " ")
		}
		user.Mail = user.UPN
		user.UserType = "Member"
		if user.Status == "Guest" {
			user.UserType = "Guest"
		}
		user.JobTitle = user.Department + " Specialist"
		user.CompanyName = "Contoso"
		user.OfficeLocation = "Seattle HQ"
		user.EmployeeID = fmt.Sprintf("CT-%04d", i+1)
		user.EmployeeType = "Employee"
		user.BusinessPhones = []string{fmt.Sprintf("+1 206 555 %04d", 1000+i)}
		user.City, user.State, user.PostalCode, user.Country = "Seattle", "WA", "98101", "United States"
		user.UsageLocation, user.PreferredLanguage = "US", "en-US"
		user.CreatedDateTime = fmt.Sprintf("202%d-01-15T12:00:00Z", i%5)
		user.LastSignIn = sampleNow.Add(-time.Duration(lastSignInMinutes[i]) * time.Minute).Format(time.RFC3339)
		user.LastSignInAvailable = true
		if user.License == "—" {
			user.License = "Unlicensed"
			user.Licenses = []string{}
		} else {
			user.Licenses = []string{user.License}
		}
		if user.SourceOfAuthority == model.SourceOnPrem {
			user.OnPremisesSAMAccountName = strings.Split(user.UPN, "@")[0]
			user.OnPremisesLastSyncDateTime = "2026-08-26T10:45:00Z"
		}
	}
}

var sampleGroups = []model.Group{
	{ID: "grp_1", Name: "Sales — All Staff", Type: "M365", Membership: "Assigned", Members: 86, Mail: "Yes", Service: "Graph", Source: "Cloud"},
	{ID: "grp_2", Name: "Finance", Type: "Security", Membership: "Assigned", Members: 22, Mail: "No", Service: "Graph", Source: "Cloud"},
	{ID: "grp_3", Name: "All Company", Type: "Dynamic Distribution", Membership: "Dynamic", Members: 482, Mail: "Yes", Service: "Exchange", Source: "Cloud"},
	{ID: "grp_4", Name: "IT Admins", Type: "Security", Membership: "Assigned", Members: 9, Mail: "No", Service: "Graph", Source: "On-prem sync"},
	{ID: "grp_5", Name: "Project Falcon", Type: "M365", Membership: "Assigned", Members: 14, Mail: "Yes", Service: "Graph", Source: "Cloud"},
	{ID: "grp_6", Name: "Marketing", Type: "M365", Membership: "Assigned", Members: 31, Mail: "Yes", Service: "Graph", Source: "Cloud"},
	{ID: "grp_7", Name: "Helpdesk", Type: "Mail-enabled Sec.", Membership: "Assigned", Members: 6, Mail: "Yes", Service: "Graph", Source: "Cloud"},
	{ID: "grp_8", Name: "Executives", Type: "Security", Membership: "Assigned", Members: 5, Mail: "No", Service: "Graph", Source: "On-prem sync"},
	{ID: "grp_9", Name: "Facilities Notices", Type: "Distribution", Membership: "Assigned", Members: 118, Mail: "Yes", Service: "Exchange", Source: "Cloud"},
}

// Member ids match sampleUsers so the write flows (remove-from-group,
// already-member skips) behave consistently, mirroring live Graph where
// members and users share directory object ids.
var sampleGroupMembers = []model.GroupMember{
	{ID: "usr_1", Name: "Avery Quinn", UPN: "avery.quinn@contoso.com", Role: "Owner", Added: "2024-03-12"},
	{ID: "usr_2", Name: "Bianca Lopez", UPN: "bianca.lopez@contoso.com", Role: "Member", Added: "2024-05-01"},
	{ID: "usr_5", Name: "Ethan Park", UPN: "ethan.park@contoso.com", Role: "Member", Added: "2025-01-22"},
	{ID: "usr_8", Name: "Hana Kim", UPN: "hana.kim@contoso.com", Role: "Member", Added: "2025-06-14"},
	{ID: "usr_10", Name: "Julia Sanz", UPN: "julia.sanz@contoso.com", Role: "Member", Added: "2026-02-09"},
	{ID: "usr_11", Name: "Kemal Yilmaz", UPN: "kemal.yilmaz@contoso.com", Role: "Member", Added: "2026-04-30"},
}

func lic(sku, product string, total, assigned int) model.License {
	avail := total - assigned
	pool := "OK"
	if avail == 0 {
		pool = "Full"
	} else if avail < 5 {
		pool = "Low"
	}
	return model.License{SkuID: "sku-" + sku, SKU: sku, Product: product, Total: total, Assigned: assigned, Available: avail, Utilization: assigned * 100 / total, Pool: pool}
}

var sampleLicenses = []model.License{
	lic("SPE_E5", "Microsoft 365 E5", 200, 182),
	lic("SPE_E3", "Microsoft 365 E3", 300, 241),
	lic("ENTERPRISEPACK", "Office 365 E3", 150, 150),
	lic("EMSPREMIUM", "Enterprise Mobility + Security E5", 120, 77),
	lic("POWER_BI_PRO", "Power BI Pro", 80, 52),
	lic("PROJECTPROFESSIONAL", "Project Plan 3", 25, 19),
	lic("VISIOCLIENT", "Visio Plan 2", 40, 12),
	lic("MCOEV", "Teams Phone Standard", 60, 44),
}

var sampleMailboxes = []model.Mailbox{
	{ID: "mbx_1", Name: "Avery Quinn", Email: "avery.quinn@contoso.com", UserPrincipalName: "avery.quinn@contoso.com", Aliases: []string{"avery@contoso.com"}, Type: "User", AccountStatus: "Enabled", SourceOfAuthority: model.SourceCloud, CreatedAt: "2022-04-18T16:20:00Z", LicenseCount: 2, Size: "14.2 GB", Items: 28411, Archive: "On", LitigationHold: "No", UsageAvailable: true, UsageAsOf: "2026-08-24", LastActivityAt: "2026-08-24", DeletedItems: 318, DeletedSize: "124.0 MB", WarningQuota: "49.0 GB", SendQuota: "49.5 GB", SendReceiveQuota: "50.0 GB", UsageDetail: "Mailbox usage report matched this directory identity."},
	{ID: "mbx_2", Name: "Sales Shared", Email: "sales@contoso.com", UserPrincipalName: "sales@contoso.com", Aliases: []string{"sales-team@contoso.com"}, Type: "Shared", AccountStatus: "Enabled", SourceOfAuthority: model.SourceCloud, CreatedAt: "2021-09-02T10:00:00Z", LicenseCount: 0, Size: "42.8 GB", Items: 91200, Archive: "On", LitigationHold: "Yes", UsageAvailable: true, UsageAsOf: "2026-08-24", LastActivityAt: "2026-08-24", DeletedItems: 1102, DeletedSize: "1.8 GB", WarningQuota: "49.0 GB", SendQuota: "49.5 GB", SendReceiveQuota: "50.0 GB", UsageDetail: "Mailbox usage report matched this directory identity."},
	{ID: "mbx_3", Name: "Conf Room A", Email: "rooma@contoso.com", UserPrincipalName: "rooma@contoso.com", Aliases: []string{}, Type: "Room", AccountStatus: "Enabled", SourceOfAuthority: model.SourceCloud, CreatedAt: "2023-02-12T09:00:00Z", LicenseCount: 0, Size: "0.4 GB", Items: 210, Archive: "Off", LitigationHold: "No", UsageAvailable: true, UsageAsOf: "2026-08-24", LastActivityAt: "2026-08-22", DeletedItems: 5, DeletedSize: "0 B", WarningQuota: "49.0 GB", SendQuota: "49.5 GB", SendReceiveQuota: "50.0 GB", UsageDetail: "Mailbox usage report matched this directory identity."},
	{ID: "mbx_4", Name: "Bianca Lopez", Email: "bianca.lopez@contoso.com", UserPrincipalName: "bianca.lopez@contoso.com", Aliases: []string{}, Type: "User", AccountStatus: "Enabled", SourceOfAuthority: model.SourceCloud, CreatedAt: "2020-11-09T14:00:00Z", LicenseCount: 2, Size: "9.7 GB", Items: 18044, Archive: "On", LitigationHold: "Yes", UsageAvailable: true, UsageAsOf: "2026-08-24", LastActivityAt: "2026-08-24", DeletedItems: 211, DeletedSize: "92.4 MB", WarningQuota: "49.0 GB", SendQuota: "49.5 GB", SendReceiveQuota: "50.0 GB", UsageDetail: "Mailbox usage report matched this directory identity."},
	{ID: "mbx_5", Name: "Support", Email: "support@contoso.com", UserPrincipalName: "support@contoso.com", Aliases: []string{"help@contoso.com", "helpdesk@contoso.com"}, Type: "Shared", AccountStatus: "Enabled", SourceOfAuthority: model.SourceCloud, CreatedAt: "2019-05-03T11:30:00Z", LicenseCount: 1, Size: "61.1 GB", Items: 140233, Archive: "On", LitigationHold: "No", UsageAvailable: true, UsageAsOf: "2026-08-24", LastActivityAt: "2026-08-24", DeletedItems: 4201, DeletedSize: "6.2 GB", WarningQuota: "98.0 GB", SendQuota: "99.0 GB", SendReceiveQuota: "100.0 GB", UsageDetail: "Mailbox usage report matched this directory identity."},
	{ID: "mbx_6", Name: "Projector 01", Email: "equip01@contoso.com", UserPrincipalName: "equip01@contoso.com", Aliases: []string{}, Type: "Equipment", AccountStatus: "Enabled", SourceOfAuthority: model.SourceCloud, CreatedAt: "2024-01-16T17:00:00Z", LicenseCount: 0, Size: "0.1 GB", Items: 54, Archive: "Off", LitigationHold: "No", UsageAvailable: true, UsageAsOf: "2026-08-24", LastActivityAt: "2026-08-20", DeletedItems: 0, DeletedSize: "0 B", WarningQuota: "49.0 GB", SendQuota: "49.5 GB", SendReceiveQuota: "50.0 GB", UsageDetail: "Mailbox usage report matched this directory identity."},
	{ID: "mbx_7", Name: "Caleb Stone", Email: "caleb.stone@contoso.com", UserPrincipalName: "caleb.stone@contoso.com", Aliases: []string{}, Type: "User", AccountStatus: "Enabled", SourceOfAuthority: model.SourceOnPrem, CreatedAt: "2018-08-27T15:00:00Z", LicenseCount: 2, Size: "22.0 GB", Items: 39870, Archive: "On", LitigationHold: "No", UsageAvailable: true, UsageAsOf: "2026-08-24", LastActivityAt: "2026-08-24", DeletedItems: 802, DeletedSize: "640.0 MB", WarningQuota: "49.0 GB", SendQuota: "49.5 GB", SendReceiveQuota: "50.0 GB", UsageDetail: "Mailbox usage report matched this directory identity."},
}

// Mailbox settings and permissions keyed by mailbox id. Only mailboxes with
// non-default state are listed; the rest read as "no auto-reply, no
// forwarding, no delegates".
var sampleMailboxSettings = map[string]model.MailboxSettings{
	"mbx_4": {MailboxID: "mbx_4", AutoReply: true, AutoReplyStatus: "scheduled", AutoReplyMessage: "I am out of the office until Monday, July 6. For urgent matters contact sales@contoso.com.", ExternalAutoReplyMessage: "Bianca is away. Please contact sales@contoso.com.", ExternalAudience: "contactsOnly", AutoReplyStart: "2026-08-24T17:00:00", AutoReplyEnd: "2026-08-31T08:00:00", ForwardingRules: []model.MailboxForwardingRule{}, RulesAvailable: true, TimeZone: "Pacific Standard Time", Language: "English (United States)", DateFormat: "M/d/yyyy", TimeFormat: "h:mm tt", WorkingDays: []string{"monday", "tuesday", "wednesday", "thursday", "friday"}, WorkingHoursStart: "08:00:00", WorkingHoursEnd: "17:00:00", WorkingHoursTimeZone: "Pacific Standard Time", UserPurpose: "user", DelegateMeetingMessageDelivery: "sendToDelegateAndInformationToPrincipal"},
	"mbx_7": {MailboxID: "mbx_7", AutoReplyStatus: "disabled", ForwardingTo: "it-archive@contoso.com", ForwardingRules: []model.MailboxForwardingRule{{ID: "rtm_forward", Name: rtmForwardRule, Enabled: true, Mode: "Forward", Recipients: []string{"it-archive@contoso.com"}, ManagedByRTM: true}, {ID: "rule_external", Name: "Vendor invoices", Enabled: true, Mode: "Redirect", Recipients: []string{"processing@accounting-partner.example"}}}, RulesAvailable: true, TimeZone: "Pacific Standard Time", Language: "English (United States)", DateFormat: "M/d/yyyy", TimeFormat: "h:mm tt", WorkingDays: []string{"monday", "tuesday", "wednesday", "thursday", "friday"}, WorkingHoursStart: "08:00:00", WorkingHoursEnd: "17:00:00", WorkingHoursTimeZone: "Pacific Standard Time", UserPurpose: "user", DelegateMeetingMessageDelivery: "sendToDelegateAndInformationToPrincipal"},
}

var sampleMailboxPerms = map[string][]model.MailboxPermission{
	"mbx_2": {
		{ID: "mp_1", Delegate: "Avery Quinn", DelegateUPN: "avery.quinn@contoso.com", Permission: MailboxPermFullAccess, Granted: "2024-11-02"},
		{ID: "mp_2", Delegate: "Ethan Park", DelegateUPN: "ethan.park@contoso.com", Permission: MailboxPermSendAs, Granted: "2025-03-18"},
	},
	"mbx_4": {
		{ID: "mp_3", Delegate: "Hana Kim", DelegateUPN: "hana.kim@contoso.com", Permission: MailboxPermSendOnBehalf, Granted: "2025-09-01"},
	},
	"mbx_5": {
		{ID: "mp_4", Delegate: "Caleb Stone", DelegateUPN: "caleb.stone@contoso.com", Permission: MailboxPermFullAccess, Granted: "2024-06-27"},
		{ID: "mp_5", Delegate: "Julia Sanz", DelegateUPN: "julia.sanz@contoso.com", Permission: MailboxPermFullAccess, Granted: "2025-01-15"},
		{ID: "mp_6", Delegate: "Hana Kim", DelegateUPN: "hana.kim@contoso.com", Permission: MailboxPermSendOnBehalf, Granted: "2025-10-22"},
	},
}

var sampleSitePerms = map[string][]model.SitePermission{
	"site_1": {
		{ID: "sp_1", Principal: "Avery Quinn", PrincipalUPN: "avery.quinn@contoso.com", Type: "User", Role: SiteRoleFullControl, Source: "Owners"},
		{ID: "sp_2", Principal: "Ethan Park", PrincipalUPN: "ethan.park@contoso.com", Type: "User", Role: SiteRoleEdit, Source: "Members"},
		{ID: "sp_3", Principal: "Sales — All Staff", PrincipalUPN: "grp_1", Type: "Group", Role: SiteRoleEdit, Source: "Members"},
		{ID: "sp_4", Principal: "Bianca Lopez", PrincipalUPN: "bianca.lopez@contoso.com", Type: "User", Role: SiteRoleRead, Source: "Visitors"},
	},
	"site_2": {
		{ID: "sp_5", Principal: "Julia Sanz", PrincipalUPN: "julia.sanz@contoso.com", Type: "User", Role: SiteRoleFullControl, Source: "Owners"},
		{ID: "sp_6", Principal: "All Company", PrincipalUPN: "grp_3", Type: "Group", Role: SiteRoleRead, Source: "Visitors"},
	},
	"site_3": {
		{ID: "sp_7", Principal: "Julia Sanz", PrincipalUPN: "julia.sanz@contoso.com", Type: "User", Role: SiteRoleFullControl, Source: "Owners"},
		{ID: "sp_8", Principal: "Project Falcon", PrincipalUPN: "grp_5", Type: "Group", Role: SiteRoleEdit, Source: "Members"},
		{ID: "sp_9", Principal: "Ivan Petrov", PrincipalUPN: "ivan.petrov@partner.com", Type: "External", Role: SiteRoleEdit, Source: "Direct"},
	},
	"site_4": {
		{ID: "sp_10", Principal: "Farah Noor", PrincipalUPN: "farah.noor@contoso.com", Type: "User", Role: SiteRoleFullControl, Source: "Owners"},
	},
	"site_5": {
		{ID: "sp_11", Principal: "Dana White", PrincipalUPN: "dana.white@contoso.com", Type: "User", Role: SiteRoleEdit, Source: "Members"},
		{ID: "sp_12", Principal: "Anyone with the link", PrincipalUPN: "—", Type: "Link", Role: SiteRoleRead, Source: "Sharing link"},
	},
	"site_6": {
		{ID: "sp_13", Principal: "Bianca Lopez", PrincipalUPN: "bianca.lopez@contoso.com", Type: "User", Role: SiteRoleFullControl, Source: "Owners"},
		{ID: "sp_14", Principal: "Finance", PrincipalUPN: "grp_2", Type: "Group", Role: SiteRoleEdit, Source: "Members"},
	},
}

var sampleSites = []model.Site{
	{ID: "site_1", Name: "Sales Team", URL: "/sites/sales", Template: "Team site", Storage: "48 GB", Files: 12044, ExternalSharing: "Internal"},
	{ID: "site_2", Name: "Company Intranet", URL: "/sites/intranet", Template: "Communication site", Storage: "12 GB", Files: 3120, ExternalSharing: "Internal"},
	{ID: "site_3", Name: "Project Falcon", URL: "/sites/falcon", Template: "Team site", Storage: "7 GB", Files: 880, ExternalSharing: "External"},
	{ID: "site_4", Name: "HR Portal", URL: "/sites/hr", Template: "Communication site", Storage: "3 GB", Files: 640, ExternalSharing: "Internal"},
	{ID: "site_5", Name: "Customer Files", URL: "/sites/customers", Template: "Team site", Storage: "118 GB", Files: 54021, ExternalSharing: "Anyone"},
	{ID: "site_6", Name: "Finance", URL: "/sites/finance", Template: "Team site", Storage: "22 GB", Files: 4500, ExternalSharing: "Internal"},
}

func txt(s string) model.GlobalReportCell       { return model.GlobalReportCell{Text: s} }
func bdg(s, tone string) model.GlobalReportCell { return model.GlobalReportCell{Badge: s, Tone: tone} }

// sampleReports mirror the single seeded example tenant (Contoso). In live
// mode reports are assembled per managed tenant by internal/reports instead.
var sampleReports = map[string]model.GlobalReport{
	"mfa": {
		Columns: []string{"Tenant", "Display Name", "UPN", "MFA State", "Method", "Last Sign-in"},
		Rows: [][]model.GlobalReportCell{
			{txt("Contoso Ltd"), txt("Avery Quinn"), txt("avery.quinn@contoso.com"), bdg("Enabled", "info"), txt("Authenticator"), txt("1h ago")},
			{txt("Contoso Ltd"), txt("Dana White"), txt("dana.white@contoso.com"), bdg("Disabled", "danger"), txt("None"), txt("3d ago")},
			{txt("Contoso Ltd"), txt("Farah Noor"), txt("farah.noor@contoso.com"), bdg("Enforced", "success"), txt("Authenticator"), txt("40m ago")},
			{txt("Contoso Ltd"), txt("Gavin Reed"), txt("gavin.reed@contoso.com"), bdg("Disabled", "danger"), txt("None"), txt("60d ago")},
			{txt("Contoso Ltd"), txt("Julia Sanz"), txt("julia.sanz@contoso.com"), bdg("Enforced", "success"), txt("FIDO2"), txt("just now")},
			{txt("Contoso Ltd"), txt("Lena Vogt"), txt("lena.vogt@contoso.com"), bdg("Disabled", "danger"), txt("None"), txt("4h ago")},
		},
	},
	"license": {
		Columns: []string{"Tenant", "SKU", "Product", "Assigned", "Total", "Utilization"},
		Rows: [][]model.GlobalReportCell{
			{txt("Contoso Ltd"), txt("SPE_E5"), txt("Microsoft 365 E5"), txt("182"), txt("200"), txt("91%")},
			{txt("Contoso Ltd"), txt("SPE_E3"), txt("Microsoft 365 E3"), txt("241"), txt("300"), txt("80%")},
			{txt("Contoso Ltd"), txt("ENTERPRISEPACK"), txt("Office 365 E3"), txt("150"), txt("150"), txt("100%")},
			{txt("Contoso Ltd"), txt("EMSPREMIUM"), txt("EM+S E5"), txt("77"), txt("120"), txt("64%")},
			{txt("Contoso Ltd"), txt("POWER_BI_PRO"), txt("Power BI Pro"), txt("52"), txt("80"), txt("65%")},
		},
	},
	"inactive": {
		Columns: []string{"Tenant", "Display Name", "UPN", "Last Sign-in", "License", "Status"},
		Rows: [][]model.GlobalReportCell{
			{txt("Contoso Ltd"), txt("Gavin Reed"), txt("gavin.reed@contoso.com"), txt("60d ago"), txt("E5"), bdg("Disabled", "neutral")},
			{txt("Contoso Ltd"), txt("Ivan Petrov"), txt("ivan.petrov@partner.com"), txt("8d ago"), txt("—"), bdg("Guest", "neutral")},
		},
	},
	"guests": {
		Columns: []string{"Tenant", "Display Name", "UPN", "Invited By", "Status", "Last Sign-in"},
		Rows: [][]model.GlobalReportCell{
			{txt("Contoso Ltd"), txt("Ivan Petrov"), txt("ivan.petrov@partner.com"), txt("A. Rivera"), bdg("Accepted", "success"), txt("8d ago")},
		},
	},
}
