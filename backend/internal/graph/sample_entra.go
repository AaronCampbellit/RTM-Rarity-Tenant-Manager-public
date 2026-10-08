package graph

import (
	"context"
	"fmt"
	"time"

	"github.com/rarity/rtm/internal/model"
)

// Sample implementations of the Entra posture reads (readiness reports,
// preflight, raw user view). Fixtures are derived from the seeded Contoso
// directory where possible so the demo stays internally consistent.

// sampleAdmins marks which seeded users hold directory roles. Dana White is
// deliberately an admin with MFA disabled so the mfa-gaps report has an
// admin-gap row to show.
var sampleAdmins = map[string]bool{
	"usr_3":  true, // Caleb Stone — IT
	"usr_4":  true, // Dana White — User Administrator, MFA disabled
	"usr_10": true, // Julia Sanz — IT
}

func (sampleProvider) MFARegistrations(context.Context, string) ([]model.MFARegistration, error) {
	regs := make([]model.MFARegistration, 0, len(sampleUsers))
	for _, u := range sampleUsers {
		registered := u.MFA == "Enabled" || u.MFA == "Enforced"
		methods := []string{}
		if registered {
			methods = append(methods, "Microsoft Authenticator")
		}
		if u.MFA == "Enforced" {
			methods = append(methods, "FIDO2 security key")
		}
		regs = append(regs, model.MFARegistration{
			ID: u.ID, Name: u.Name, UPN: u.UPN,
			IsAdmin:       sampleAdmins[u.ID],
			MFARegistered: registered,
			Passwordless:  u.MFA == "Enforced",
			SSPR:          registered,
			Methods:       methods,
		})
	}
	return regs, nil
}

// GuestAccounts: Ivan is the active guest from the directory; Priya and Marco
// are lifecycle problem cases (stuck invite, long-stale account) for the
// stale-guest report. Timestamps are relative to now so staleness math stays
// stable in the demo.
func (sampleProvider) GuestAccounts(context.Context, string) ([]model.GuestAccount, error) {
	day := 24 * time.Hour
	ts := func(age time.Duration) string { return time.Now().Add(-age).UTC().Format(time.RFC3339) }
	return []model.GuestAccount{
		{ID: "usr_9", Name: "Ivan Petrov", UPN: "ivan.petrov@partner.com", Mail: "ivan.petrov@partner.com",
			AccountEnabled: true, State: "Accepted", Created: ts(400 * day), LastSignIn: ts(8 * day)},
		{ID: "gst_2", Name: "Priya Patel", UPN: "priya.patel_vendor.io#EXT#@contoso.com", Mail: "priya.patel@vendor.io",
			AccountEnabled: true, State: "PendingAcceptance", Created: ts(150 * day), LastSignIn: ""},
		{ID: "gst_3", Name: "Marco Ruiz", UPN: "marco.ruiz_freelance.example#EXT#@contoso.com", Mail: "marco.ruiz@freelance.example",
			AccountEnabled: true, State: "Accepted", Created: ts(500 * day), LastSignIn: ts(120 * day)},
	}, nil
}

func (sampleProvider) RoleAssignments(context.Context, string) ([]model.RoleAssignment, error) {
	return []model.RoleAssignment{
		{RoleID: "role_1", RoleName: "Global Administrator", MemberID: "usr_3", MemberName: "Caleb Stone", MemberUPN: "caleb.stone@contoso.com", MemberType: "User"},
		{RoleID: "role_1", RoleName: "Global Administrator", MemberID: "usr_10", MemberName: "Julia Sanz", MemberUPN: "julia.sanz@contoso.com", MemberType: "User"},
		{RoleID: "role_2", RoleName: "User Administrator", MemberID: "usr_4", MemberName: "Dana White", MemberUPN: "dana.white@contoso.com", MemberType: "User"},
		{RoleID: "role_3", RoleName: "Exchange Administrator", MemberID: "usr_8", MemberName: "Hana Kim", MemberUPN: "hana.kim@contoso.com", MemberType: "User"},
		{RoleID: "role_4", RoleName: "Helpdesk Administrator", MemberID: "grp_7", MemberName: "Helpdesk", MemberUPN: "—", MemberType: "Group"},
	}, nil
}

func (sampleProvider) CAExclusions(context.Context, string) ([]model.CAExclusion, error) {
	return []model.CAExclusion{
		{PolicyID: "ca_1", PolicyName: "Require MFA for all users", State: "enabled", Type: "Excluded user", Target: "Caleb Stone (break-glass)"},
		{PolicyID: "ca_1", PolicyName: "Require MFA for all users", State: "enabled", Type: "Excluded group", Target: "IT Admins"},
		{PolicyID: "ca_2", PolicyName: "Block legacy authentication", State: "reportOnly", Type: "Excluded app", Target: "Legacy Importer"},
	}, nil
}

func (sampleProvider) AppCredentials(context.Context, string) ([]model.AppCredential, error) {
	day := 24 * time.Hour
	at := func(offset time.Duration) string { return time.Now().Add(offset).UTC().Format(time.RFC3339) }
	return []model.AppCredential{
		{AppID: "app_1", AppName: "Payroll Sync", Type: "Secret", ExpiresAt: at(-10 * day)},
		{AppID: "app_2", AppName: "CRM Connector", Type: "Secret", ExpiresAt: at(25 * day)},
		{AppID: "app_3", AppName: "Legacy Importer", Type: "Secret", ExpiresAt: at(80 * day)},
		{AppID: "app_4", AppName: "Backup Agent", Type: "Certificate", ExpiresAt: at(300 * day)},
	}, nil
}

// LicenseReadiness derives "Unlicensed" from the seeded directory (enabled
// member accounts with no license) and seeds one missing-usage-location case —
// usage location isn't part of the summary user model.
func (sampleProvider) LicenseReadiness(context.Context, string) ([]model.LicenseReadinessIssue, error) {
	issues := []model.LicenseReadinessIssue{}
	for _, u := range sampleUsers {
		if u.Status == "Active" && u.License == "—" {
			issues = append(issues, model.LicenseReadinessIssue{
				UserID: u.ID, Name: u.Name, UPN: u.UPN, Issue: "Unlicensed", Status: u.Status,
			})
		}
	}
	issues = append(issues, model.LicenseReadinessIssue{
		UserID: "usr_12", Name: "Lena Vogt", UPN: "lena.vogt@contoso.com",
		Issue: "Missing usage location", Status: "Active",
	})
	return issues, nil
}

func (sampleProvider) Preflight(context.Context, string) ([]model.PreflightCheck, error) {
	checks := make([]model.PreflightCheck, 0, len(preflightReadAreas)+5)
	for _, a := range preflightReadAreas {
		checks = append(checks, model.PreflightCheck{
			Area: a.area, Resource: "Microsoft Graph", Permission: a.permission, Status: "sample",
			Detail: "Sample data — this tenant has no live Microsoft connection.",
		})
	}
	checks = append(checks, model.PreflightCheck{
		Area: "Exchange delegate inventory", Resource: resourceExchangeOnline,
		Permission: "Exchange.ManageAsAppV2", Status: "sample",
		Detail: "Sample mode cannot probe the Exchange Online Admin API.",
	})
	checks = append(checks, samplePreflightWriteChecks()...)
	return checks, nil
}

// UserRaw builds a full directory object for a seeded user, including the
// uncommon fields (extension attributes, identities) the Users table hides.
func (sampleProvider) UserRaw(_ context.Context, _ string, userID string) (model.UserRaw, error) {
	for _, u := range sampleUsers {
		if u.ID != userID {
			continue
		}
		mail := u.UPN
		enabled := u.Status != "Disabled"
		userType := "Member"
		if u.Status == "Guest" {
			userType = "Guest"
		}
		onPrem := u.SourceOfAuthority == model.SourceOnPrem
		attrs := map[string]any{
			"id": u.ID, "displayName": u.Name, "userPrincipalName": u.UPN,
			"mail": mail, "mailNickname": u.ID, "proxyAddresses": []string{"SMTP:" + mail},
			"department": u.Department, "jobTitle": u.Department + " Specialist",
			"companyName": "Contoso Ltd", "officeLocation": "HQ / Floor 3",
			"usageLocation": "US", "preferredLanguage": "en-US",
			"accountEnabled": enabled, "userType": userType,
			"createdDateTime":       "2023-05-14T09:30:00Z",
			"businessPhones":        []string{"+1 425 555 0100"},
			"onPremisesSyncEnabled": onPrem,
			"identities": []map[string]any{
				{"signInType": "userPrincipalName", "issuer": "contoso.com", "issuerAssignedId": u.UPN},
			},
		}
		if onPrem {
			attrs["onPremisesSamAccountName"] = u.ID
			attrs["onPremisesDomainName"] = "corp.contoso.com"
			attrs["onPremisesDistinguishedName"] = fmt.Sprintf("CN=%s,OU=Staff,DC=corp,DC=contoso,DC=com", u.Name)
			attrs["onPremisesLastSyncDateTime"] = time.Now().Add(-40 * time.Minute).UTC().Format(time.RFC3339)
			attrs["onPremisesExtensionAttributes"] = map[string]any{
				"extensionAttribute1": "IT-OPS", "extensionAttribute2": "COST-4410",
			}
		}
		if userType == "Guest" {
			attrs["externalUserState"] = "Accepted"
			attrs["creationType"] = "Invitation"
		}
		return model.UserRaw{ID: u.ID, Attributes: attrs}, nil
	}
	// Match the live client's shape for a missing object so the handler maps
	// it to 404 in both modes.
	return model.UserRaw{}, &APIError{Status: 404, Code: "Request_ResourceNotFound", Message: fmt.Sprintf("sample: unknown user %s", userID), Path: "/users/" + userID}
}

// preflightReadAreas are the probeable read feature areas, shared by the
// sample and live preflight so both report the same rows.
var preflightReadAreas = []struct {
	area, permission, path string
}{
	{"Directory — users", "User.Read.All", "/users?$select=id&$top=1"},
	{"Directory — groups", "Group.Read.All", "/groups?$select=id&$top=1"},
	{"SharePoint group expansion", "GroupMember.Read.All", "/groups?$select=id&$top=1"},
	{"Licensing", "Organization.Read.All", "/subscribedSkus"},
	{"MFA registration report", "AuditLog.Read.All", "/reports/authenticationMethods/userRegistrationDetails?$top=1"},
	{"SharePoint sites", "Sites.Read.All", "/sites?search=*"},
	{"Directory roles", "RoleManagement.Read.Directory", "/directoryRoles"},
	{"Conditional Access", "Policy.Read.All", "/identity/conditionalAccess/policies?$top=1"},
	{"App registrations", "Application.Read.All", "/applications?$select=id&$top=1"},
	{"Security Operations incidents", "SecurityIncident.Read.All", "/security/incidents?$top=1"},
	{"Exchange mailbox usage", "Reports.Read.All", "/reports/getMailboxUsageDetail(period='D7')"},
}

var preflightWriteAreas = []struct {
	area, resource, permission string
}{
	{"Directory writes (sign-in and licensing)", resourceMicrosoftGraph, "User.ReadWrite.All"},
	{"Password reset", resourceMicrosoftGraph, "User-PasswordProfile.ReadWrite.All"},
	{"Compromised-user MFA reset", resourceMicrosoftGraph, "UserAuthenticationMethod.ReadWrite.All"},
	{"Compromised-user session revocation", resourceMicrosoftGraph, "User.RevokeSessions.All"},
	{"Group membership writes", resourceMicrosoftGraph, "GroupMember.ReadWrite.All"},
	{"Mailbox settings writes (forwarding, auto-reply)", resourceMicrosoftGraph, "MailboxSettings.ReadWrite"},
	{"SharePoint drive-item permission management", resourceMicrosoftGraph, "Sites.ReadWrite.All"},
	{"SharePoint direct permission management", resourceMicrosoftGraph, "Sites.FullControl.All"},
}

func samplePreflightWriteChecks() []model.PreflightCheck {
	checks := make([]model.PreflightCheck, 0, len(preflightWriteAreas)+1)
	for _, area := range preflightWriteAreas {
		checks = append(checks, model.PreflightCheck{
			Area: area.area, Resource: area.resource, Permission: area.permission,
			Status: "sample", Detail: "Sample mode cannot inspect tenant application-role assignments.",
		})
	}
	checks = append(checks, model.PreflightCheck{
		Area: "SharePoint role assignments and inheritance", Resource: resourceSharePointOnline,
		Permission: "Sites.FullControl.All", Status: "sample",
		Detail: "Sample mode cannot inspect the central certificate app's SharePoint Online token roles.",
	})
	return checks
}

func livePreflightWriteChecks(assigned map[string]struct{}, assignmentErr error) []model.PreflightCheck {
	checks := make([]model.PreflightCheck, 0, len(preflightWriteAreas))
	for _, area := range preflightWriteAreas {
		check := model.PreflightCheck{Area: area.area, Resource: area.resource, Permission: area.permission}
		if assignmentErr != nil {
			check.Status = "error"
			check.Detail = "RTM could not inspect the active app's application-role assignments: " + assignmentErr.Error()
		} else {
			check.Status, check.GrantedVia = resolveEffectiveGrant(area.resource, area.permission, assigned)
			if check.Status == "missing" {
				check.Detail = "The active app registration does not have this permission or a supported broader permission."
			} else if area.permission == "User-PasswordProfile.ReadWrite.All" {
				check.Detail = "Application permission confirmed. Microsoft can additionally require the RTM service principal to hold an appropriate Entra directory role for the target user; execution reports that restriction per user."
			}
		}
		checks = append(checks, check)
	}
	return checks
}
