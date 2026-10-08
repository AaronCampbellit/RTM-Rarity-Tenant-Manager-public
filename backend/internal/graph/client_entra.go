package graph

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/rarity/rtm/internal/model"
)

// Live implementations of the Entra posture reads (readiness reports,
// preflight, raw user view). All are read-only Graph calls; the permission
// each needs is documented on the Provider interface.

// MFARegistrations reads the authentication-methods registration report and
// maps the fields the mfa-gaps report renders (AuditLog.Read.All).
func (c *graphClient) MFARegistrations(ctx context.Context, tenantID string) ([]model.MFARegistration, error) {
	var out struct {
		Value []struct {
			ID                    string   `json:"id"`
			UserPrincipalName     string   `json:"userPrincipalName"`
			UserDisplayName       string   `json:"userDisplayName"`
			IsAdmin               bool     `json:"isAdmin"`
			IsMfaRegistered       bool     `json:"isMfaRegistered"`
			IsPasswordlessCapable bool     `json:"isPasswordlessCapable"`
			IsSsprRegistered      bool     `json:"isSsprRegistered"`
			MethodsRegistered     []string `json:"methodsRegistered"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/reports/authenticationMethods/userRegistrationDetails?$top=200", &out); err != nil {
		return nil, err
	}
	regs := make([]model.MFARegistration, 0, len(out.Value))
	for _, r := range out.Value {
		methods := r.MethodsRegistered
		if methods == nil {
			methods = []string{}
		}
		regs = append(regs, model.MFARegistration{
			ID: r.ID, Name: r.UserDisplayName, UPN: r.UserPrincipalName,
			IsAdmin: r.IsAdmin, MFARegistered: r.IsMfaRegistered,
			Passwordless: r.IsPasswordlessCapable, SSPR: r.IsSsprRegistered,
			Methods: methods,
		})
	}
	return regs, nil
}

// GuestAccounts lists guests with lifecycle signals. Sign-in activity needs
// AuditLog.Read.All plus an Entra ID P1 license — when Microsoft rejects that
// $select the read degrades to the plain guest list (LastSignIn empty) rather
// than failing the report.
func (c *graphClient) GuestAccounts(ctx context.Context, tenantID string) ([]model.GuestAccount, error) {
	type guestRow struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		UserPrincipalName string `json:"userPrincipalName"`
		Mail              string `json:"mail"`
		AccountEnabled    bool   `json:"accountEnabled"`
		ExternalUserState string `json:"externalUserState"`
		CreatedDateTime   string `json:"createdDateTime"`
		SignInActivity    *struct {
			LastSignInDateTime string `json:"lastSignInDateTime"`
		} `json:"signInActivity"`
	}
	var out struct {
		Value []guestRow `json:"value"`
	}
	base := "/users?$filter=userType%20eq%20%27Guest%27&$top=200&$select=id,displayName,userPrincipalName,mail,accountEnabled,externalUserState,createdDateTime"
	err := c.get(ctx, tenantID, base+",signInActivity", &out)
	if err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			return nil, err
		}
		// Retry without the premium signal so tenants without P1 still report.
		c.log.Warn("graph: guest sign-in activity unavailable, listing guests without it", "error", err)
		if err := c.get(ctx, tenantID, base, &out); err != nil {
			return nil, err
		}
	}
	guests := make([]model.GuestAccount, 0, len(out.Value))
	for _, g := range out.Value {
		last := ""
		if g.SignInActivity != nil {
			last = g.SignInActivity.LastSignInDateTime
		}
		guests = append(guests, model.GuestAccount{
			ID: g.ID, Name: g.DisplayName, UPN: g.UserPrincipalName, Mail: g.Mail,
			AccountEnabled: g.AccountEnabled, State: g.ExternalUserState,
			Created: g.CreatedDateTime, LastSignIn: last,
		})
	}
	return guests, nil
}

// RoleAssignments flattens every activated directory role's membership
// (RoleManagement.Read.Directory or Directory.Read.All). Role counts are
// small, so the per-role member read stays bounded.
func (c *graphClient) RoleAssignments(ctx context.Context, tenantID string) ([]model.RoleAssignment, error) {
	var roles struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/directoryRoles", &roles); err != nil {
		return nil, err
	}
	assignments := []model.RoleAssignment{}
	for _, role := range roles.Value {
		var members struct {
			Value []struct {
				ODataType         string `json:"@odata.type"`
				ID                string `json:"id"`
				DisplayName       string `json:"displayName"`
				UserPrincipalName string `json:"userPrincipalName"`
			} `json:"value"`
		}
		if err := c.get(ctx, tenantID, "/directoryRoles/"+role.ID+"/members?$select=id,displayName,userPrincipalName", &members); err != nil {
			return nil, err
		}
		for _, m := range members.Value {
			typ := "User"
			switch {
			case strings.HasSuffix(m.ODataType, "group"):
				typ = "Group"
			case strings.HasSuffix(m.ODataType, "servicePrincipal"):
				typ = "Service Principal"
			}
			upn := m.UserPrincipalName
			if upn == "" {
				upn = "—"
			}
			assignments = append(assignments, model.RoleAssignment{
				RoleID: role.ID, RoleName: role.DisplayName,
				MemberID: m.ID, MemberName: m.DisplayName, MemberUPN: upn, MemberType: typ,
			})
		}
	}
	return assignments, nil
}

// CAExclusions flattens the exclusion lists of every Conditional Access
// policy (Policy.Read.All). Targets are raw object ids — resolving each to a
// display name would multiply the call count.
func (c *graphClient) CAExclusions(ctx context.Context, tenantID string) ([]model.CAExclusion, error) {
	var out struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			State       string `json:"state"`
			Conditions  struct {
				Users struct {
					ExcludeUsers  []string `json:"excludeUsers"`
					ExcludeGroups []string `json:"excludeGroups"`
				} `json:"users"`
				Applications struct {
					ExcludeApplications []string `json:"excludeApplications"`
				} `json:"applications"`
			} `json:"conditions"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/identity/conditionalAccess/policies", &out); err != nil {
		return nil, err
	}
	state := func(s string) string {
		if s == "enabledForReportingButNotEnforced" {
			return "reportOnly"
		}
		return s
	}
	exclusions := []model.CAExclusion{}
	for _, p := range out.Value {
		for _, u := range p.Conditions.Users.ExcludeUsers {
			exclusions = append(exclusions, model.CAExclusion{PolicyID: p.ID, PolicyName: p.DisplayName, State: state(p.State), Type: "Excluded user", Target: u})
		}
		for _, g := range p.Conditions.Users.ExcludeGroups {
			exclusions = append(exclusions, model.CAExclusion{PolicyID: p.ID, PolicyName: p.DisplayName, State: state(p.State), Type: "Excluded group", Target: g})
		}
		for _, a := range p.Conditions.Applications.ExcludeApplications {
			exclusions = append(exclusions, model.CAExclusion{PolicyID: p.ID, PolicyName: p.DisplayName, State: state(p.State), Type: "Excluded app", Target: a})
		}
	}
	return exclusions, nil
}

// AppCredentials lists every secret and certificate on the tenant's app
// registrations (Application.Read.All); the report layer applies the expiry
// window.
func (c *graphClient) AppCredentials(ctx context.Context, tenantID string) ([]model.AppCredential, error) {
	var out struct {
		Value []struct {
			AppID               string `json:"appId"`
			DisplayName         string `json:"displayName"`
			PasswordCredentials []struct {
				EndDateTime string `json:"endDateTime"`
			} `json:"passwordCredentials"`
			KeyCredentials []struct {
				EndDateTime string `json:"endDateTime"`
			} `json:"keyCredentials"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/applications?$select=appId,displayName,passwordCredentials,keyCredentials&$top=200", &out); err != nil {
		return nil, err
	}
	creds := []model.AppCredential{}
	for _, app := range out.Value {
		for _, s := range app.PasswordCredentials {
			creds = append(creds, model.AppCredential{AppID: app.AppID, AppName: app.DisplayName, Type: "Secret", ExpiresAt: s.EndDateTime})
		}
		for _, k := range app.KeyCredentials {
			creds = append(creds, model.AppCredential{AppID: app.AppID, AppName: app.DisplayName, Type: "Certificate", ExpiresAt: k.EndDateTime})
		}
	}
	return creds, nil
}

// LicenseReadiness flags enabled member accounts that a license assignment
// would fail on (no usage location) or that hold no license at all
// (User.Read.All).
func (c *graphClient) LicenseReadiness(ctx context.Context, tenantID string) ([]model.LicenseReadinessIssue, error) {
	var out struct {
		Value []struct {
			ID                string `json:"id"`
			DisplayName       string `json:"displayName"`
			UserPrincipalName string `json:"userPrincipalName"`
			AccountEnabled    bool   `json:"accountEnabled"`
			UserType          string `json:"userType"`
			UsageLocation     string `json:"usageLocation"`
			AssignedLicenses  []struct {
				SkuID string `json:"skuId"`
			} `json:"assignedLicenses"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,usageLocation,assignedLicenses&$top=200", &out); err != nil {
		return nil, err
	}
	issues := []model.LicenseReadinessIssue{}
	for _, u := range out.Value {
		if !u.AccountEnabled || u.UserType == "Guest" {
			continue
		}
		if u.UsageLocation == "" {
			issues = append(issues, model.LicenseReadinessIssue{
				UserID: u.ID, Name: u.DisplayName, UPN: u.UserPrincipalName, Issue: "Missing usage location", Status: "Active",
			})
		}
		if len(u.AssignedLicenses) == 0 {
			issues = append(issues, model.LicenseReadinessIssue{
				UserID: u.ID, Name: u.DisplayName, UPN: u.UserPrincipalName, Issue: "Unlicensed", Status: "Active",
			})
		}
	}
	return issues, nil
}

// Preflight probes each read feature area with a harmless GET and classifies
// the outcome. The mailbox-usage CSV is the privacy-preserving exception: its
// role is verified from a fresh Microsoft-issued token without downloading
// tenant data. Write grants are also verified from that token.
func (c *graphClient) Preflight(ctx context.Context, tenantID string) ([]model.PreflightCheck, error) {
	// Preflight is a diagnostic: like TestConnection, drop the cached token so
	// consent granted moments ago is visible on this run.
	auth, err := c.tenantAuth(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	delete(c.tokens, tokenCacheKey(auth.Authority, auth.ClientID, "https://graph.microsoft.com/.default"))
	c.mu.Unlock()

	accessToken, assignmentErr := c.token(ctx, auth)
	assigned := map[string]struct{}{}
	if assignmentErr == nil {
		assigned, assignmentErr = tokenRoleSet(accessToken)
	}
	checks := make([]model.PreflightCheck, 0, len(preflightReadAreas)+4)
	for _, area := range preflightReadAreas {
		check := model.PreflightCheck{Area: area.area, Resource: "Microsoft Graph", Permission: area.permission, Status: "ok"}
		grantConfirmed := false
		if assignmentErr == nil {
			grantStatus, grantedVia := resolveEffectiveGrant(resourceMicrosoftGraph, area.permission, assigned)
			grantConfirmed, check.GrantedVia = grantStatus == "ok", grantedVia
		}
		// Usage reports are CSV downloads that can contain every mailbox in the
		// tenant. Preflight verifies Reports.Read.All from the freshly minted
		// Microsoft token instead of downloading that sensitive report merely
		// to test consent.
		if strings.HasPrefix(area.path, "/reports/getMailboxUsageDetail") {
			switch {
			case assignmentErr != nil:
				check.Status = "error"
				check.Detail = "RTM could not inspect the Microsoft-issued token: " + assignmentErr.Error()
			case grantConfirmed:
				check.Detail = "Confirmed from the Microsoft-issued token; preflight did not download mailbox usage data."
			default:
				check.Status = "missing"
				check.Detail = "The active app registration does not have admin-consented Reports.Read.All."
			}
			checks = append(checks, check)
			continue
		}
		var probeErr error
		var out map[string]any
		probeErr = c.get(ctx, tenantID, area.path, &out)
		if err := probeErr; err != nil {
			var apiErr *APIError
			switch {
			case errors.As(err, &apiErr) && defenderNotProvisioned(area.path, apiErr):
				check.Status = "not_provisioned"
				if grantConfirmed {
					check.Detail = "SecurityIncident.Read.All is granted, but Microsoft Defender XDR is not provisioned for this tenant. RTM's Microsoft 365 audit detections remain available without Defender."
				} else {
					check.Detail = "Microsoft Defender XDR is not provisioned for this tenant. RTM's Microsoft 365 audit detections remain available without Defender."
				}
			case errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden && grantConfirmed:
				check.Status = "error"
				check.Detail = "The Microsoft-issued token contains the required permission, but Graph still denied the probe. " + microsoftProbeDetail(apiErr)
			case errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden:
				check.Status, check.Detail = "missing", "Microsoft Graph denied the probe — grant admin consent for "+area.permission+". "+apiErr.Message
			case errors.As(err, &apiErr):
				check.Status, check.Detail = "error", microsoftProbeDetail(apiErr)
			default:
				check.Status, check.Detail = "error", err.Error()
			}
		}
		checks = append(checks, check)
	}
	checks = append(checks, c.exchangeAdminPreflight(ctx, tenantID))
	return append(checks, livePreflightWriteChecks(assigned, assignmentErr)...), nil
}

func defenderNotProvisioned(path string, apiErr *APIError) bool {
	return strings.HasPrefix(path, "/security/incidents") &&
		apiErr.Status == http.StatusForbidden &&
		strings.Contains(strings.ToLower(apiErr.Message), "account is not provisioned")
}

func microsoftProbeDetail(e *APIError) string {
	if e.Message != "" {
		return e.Message
	}
	if e.Code != "" {
		return "Microsoft error " + e.Code
	}
	return "Microsoft returned HTTP " + http.StatusText(e.Status)
}

// userRawSelect is the wide attribute set the raw user view requests — the
// default Graph response hides most of these unless they are $select-ed
// explicitly.
const userRawSelect = "id,displayName,givenName,surname,userPrincipalName,mail,otherMails,proxyAddresses," +
	"mailNickname,jobTitle,department,companyName,officeLocation,employeeId,employeeType,employeeHireDate," +
	"businessPhones,mobilePhone,streetAddress,city,state,postalCode,country,usageLocation,preferredLanguage," +
	"accountEnabled,userType,createdDateTime,creationType,externalUserState,externalUserStateChangeDateTime," +
	"onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesUserPrincipalName,onPremisesDistinguishedName," +
	"onPremisesDomainName,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSecurityIdentifier," +
	"onPremisesExtensionAttributes,securityIdentifier,identities,imAddresses,assignedLicenses,ageGroup," +
	"showInAddressList,signInSessionsValidFromDateTime"

// UserRaw reads the full directory object for one user (User.Read.All). Null
// attributes are dropped so the view shows what is actually set.
func (c *graphClient) UserRaw(ctx context.Context, tenantID, userID string) (model.UserRaw, error) {
	var out map[string]any
	if err := c.get(ctx, tenantID, "/users/"+url.PathEscape(userID)+"?$select="+userRawSelect, &out); err != nil {
		return model.UserRaw{}, err
	}
	attrs := make(map[string]any, len(out))
	for k, v := range out {
		if v == nil || strings.HasPrefix(k, "@odata") {
			continue
		}
		attrs[k] = v
	}
	id, _ := attrs["id"].(string)
	return model.UserRaw{ID: id, Attributes: attrs}, nil
}
