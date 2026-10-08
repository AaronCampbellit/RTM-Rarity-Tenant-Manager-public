package graph

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rarity/rtm/internal/model"
)

// ---- Entra posture reads (live client against the fake Graph server) ----

func TestMFARegistrationsLive(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/reports/authenticationMethods/userRegistrationDetails"] = `{"value":[
		{"id":"u1","userPrincipalName":"ada@contoso.com","userDisplayName":"Ada","isAdmin":true,"isMfaRegistered":false,"isSsprRegistered":false,"methodsRegistered":[]},
		{"id":"u2","userPrincipalName":"bo@contoso.com","userDisplayName":"Bo","isAdmin":false,"isMfaRegistered":true,"isPasswordlessCapable":true,"isSsprRegistered":true,"methodsRegistered":["microsoftAuthenticatorPush"]}
	]}`
	c := newTestClient(f, nil)

	regs, err := c.MFARegistrations(context.Background(), "")
	if err != nil {
		t.Fatalf("MFARegistrations: %v", err)
	}
	if len(regs) != 2 {
		t.Fatalf("regs = %d, want 2", len(regs))
	}
	if !regs[0].IsAdmin || regs[0].MFARegistered {
		t.Fatalf("admin gap row = %+v", regs[0])
	}
	if !regs[1].Passwordless || len(regs[1].Methods) != 1 {
		t.Fatalf("registered row = %+v", regs[1])
	}
}

func TestGuestAccountsLive(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users"] = `{"value":[
		{"id":"g1","displayName":"Gia Guest","userPrincipalName":"gia_partner.com#EXT#@contoso.com","mail":"gia@partner.com","accountEnabled":true,"externalUserState":"PendingAcceptance","createdDateTime":"2025-01-05T00:00:00Z","signInActivity":{"lastSignInDateTime":"2026-01-02T10:00:00Z"}}
	]}`
	c := newTestClient(f, nil)

	guests, err := c.GuestAccounts(context.Background(), "")
	if err != nil {
		t.Fatalf("GuestAccounts: %v", err)
	}
	if len(guests) != 1 {
		t.Fatalf("guests = %d, want 1", len(guests))
	}
	g := guests[0]
	if g.Mail != "gia@partner.com" || g.State != "PendingAcceptance" || g.LastSignIn != "2026-01-02T10:00:00Z" {
		t.Fatalf("guest = %+v", g)
	}
}

// Without an Entra ID P1 license Microsoft rejects the signInActivity $select;
// the read must degrade to the plain guest list rather than fail. This test
// needs a query-aware fake: the premium $select 403s, the plain one succeeds.
func TestGuestAccountsDegradeWithoutSignInActivity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		if strings.Contains(r.URL.RawQuery, "signInActivity") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":"Authentication_RequestFromNonPremiumTenant","message":"tenant doesn't have premium license"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"value":[{"id":"g1","displayName":"Gia","userPrincipalName":"gia#EXT#@c.com","mail":"gia@p.com","accountEnabled":true}]}`)
	}))
	t.Cleanup(srv.Close)
	c := newGraphClient(Config{ClientID: "app-id", ClientSecret: "s", TenantID: "home"}, testLogger(), nil)
	c.base, c.loginBase, c.http = srv.URL, srv.URL, srv.Client()

	guests, err := c.GuestAccounts(context.Background(), "")
	if err != nil {
		t.Fatalf("GuestAccounts should degrade, got %v", err)
	}
	if len(guests) != 1 || guests[0].LastSignIn != "" {
		t.Fatalf("guests = %+v", guests)
	}
}

func TestRoleAssignmentsLive(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/directoryRoles"] = `{"value":[{"id":"r1","displayName":"Global Administrator"}]}`
	f.responses["/directoryRoles/r1/members"] = `{"value":[
		{"@odata.type":"#microsoft.graph.user","id":"u1","displayName":"Ada","userPrincipalName":"ada@contoso.com"},
		{"@odata.type":"#microsoft.graph.servicePrincipal","id":"sp1","displayName":"Automation"}
	]}`
	c := newTestClient(f, nil)

	rows, err := c.RoleAssignments(context.Background(), "")
	if err != nil {
		t.Fatalf("RoleAssignments: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].RoleName != "Global Administrator" || rows[0].MemberType != "User" {
		t.Fatalf("row = %+v", rows[0])
	}
	if rows[1].MemberType != "Service Principal" || rows[1].MemberUPN != "—" {
		t.Fatalf("sp row = %+v", rows[1])
	}
}

func TestCAExclusionsLive(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/identity/conditionalAccess/policies"] = `{"value":[
		{"id":"p1","displayName":"Require MFA","state":"enabledForReportingButNotEnforced","conditions":{
			"users":{"excludeUsers":["u9"],"excludeGroups":["g4"]},
			"applications":{"excludeApplications":["appX"]}}}
	]}`
	c := newTestClient(f, nil)

	rows, err := c.CAExclusions(context.Background(), "")
	if err != nil {
		t.Fatalf("CAExclusions: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0].State != "reportOnly" || rows[0].Type != "Excluded user" || rows[0].Target != "u9" {
		t.Fatalf("row = %+v", rows[0])
	}
}

func TestAppCredentialsLive(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/applications"] = `{"value":[
		{"appId":"a1","displayName":"Payroll Sync","passwordCredentials":[{"endDateTime":"2026-01-01T00:00:00Z"}],"keyCredentials":[{"endDateTime":"2027-01-01T00:00:00Z"}]}
	]}`
	c := newTestClient(f, nil)

	creds, err := c.AppCredentials(context.Background(), "")
	if err != nil {
		t.Fatalf("AppCredentials: %v", err)
	}
	if len(creds) != 2 || creds[0].Type != "Secret" || creds[1].Type != "Certificate" {
		t.Fatalf("creds = %+v", creds)
	}
}

func TestLicenseReadinessLive(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users"] = `{"value":[
		{"id":"u1","displayName":"Ada","userPrincipalName":"ada@c.com","accountEnabled":true,"userType":"Member","usageLocation":"US","assignedLicenses":[{"skuId":"s"}]},
		{"id":"u2","displayName":"Bo","userPrincipalName":"bo@c.com","accountEnabled":true,"userType":"Member","usageLocation":"","assignedLicenses":[]},
		{"id":"u3","displayName":"Gia","userPrincipalName":"gia@p.com","accountEnabled":true,"userType":"Guest","assignedLicenses":[]},
		{"id":"u4","displayName":"Dis","userPrincipalName":"dis@c.com","accountEnabled":false,"userType":"Member","assignedLicenses":[]}
	]}`
	c := newTestClient(f, nil)

	issues, err := c.LicenseReadiness(context.Background(), "")
	if err != nil {
		t.Fatalf("LicenseReadiness: %v", err)
	}
	// Bo is flagged twice (no usage location + unlicensed); guests and
	// disabled accounts are excluded.
	if len(issues) != 2 || issues[0].UPN != "bo@c.com" || issues[1].UPN != "bo@c.com" {
		t.Fatalf("issues = %+v", issues)
	}
}

func TestPreflightClassifiesProbes(t *testing.T) {
	f := newFakeGraph(t)
	f.tokenRoles = []string{"Directory.ReadWrite.All", "Sites.ReadWrite.All", "MailboxSettings.ReadWrite", "SecurityIncident.Read.All"}
	// Everything answers except CA (403 = missing consent) and applications
	// (500 = provider error).
	for _, path := range []string{"/users", "/groups", "/subscribedSkus",
		"/reports/authenticationMethods/userRegistrationDetails", "/sites", "/directoryRoles"} {
		f.responses[path] = `{"value":[]}`
	}
	f.responses["/reports/getMailboxUsageDetail(period='D7')"] = "Report Refresh Date,User Principal Name\n"
	f.status["/identity/conditionalAccess/policies"] = http.StatusForbidden
	f.responses["/identity/conditionalAccess/policies"] = `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`
	f.status["/applications"] = http.StatusInternalServerError
	f.status["/security/incidents"] = http.StatusForbidden
	f.responses["/security/incidents"] = `{"error":{"code":"Forbidden","message":"Unauthorized request - Account is not provisioned."}}`
	c := newTestClient(f, nil)

	checks, err := c.Preflight(context.Background(), "")
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	byArea := map[string]string{}
	var userWrite model.PreflightCheck
	var userRead model.PreflightCheck
	var defender model.PreflightCheck
	for _, chk := range checks {
		byArea[chk.Area] = chk.Status
		if chk.Area == "Directory — users" {
			userRead = chk
		}
		if chk.Area == "Directory writes (sign-in and licensing)" {
			userWrite = chk
		}
		if chk.Area == "Security Operations incidents" {
			defender = chk
		}
	}
	if byArea["Directory — users"] != "ok" {
		t.Fatalf("users probe = %q", byArea["Directory — users"])
	}
	if userRead.GrantedVia != "Directory.ReadWrite.All" {
		t.Fatalf("user read check = %+v", userRead)
	}
	if byArea["Conditional Access"] != "missing" {
		t.Fatalf("CA probe = %q", byArea["Conditional Access"])
	}
	if byArea["App registrations"] != "error" {
		t.Fatalf("applications probe = %q", byArea["App registrations"])
	}
	if byArea["Security Operations incidents"] != "not_provisioned" {
		t.Fatalf("Defender probe = %q", byArea["Security Operations incidents"])
	}
	if byArea["Exchange mailbox usage"] != "missing" {
		t.Fatalf("mailbox usage permission = %q", byArea["Exchange mailbox usage"])
	}
	if !strings.Contains(defender.Detail, "SecurityIncident.Read.All is granted") {
		t.Fatalf("Defender detail = %q", defender.Detail)
	}
	if userWrite.Status != "ok" || userWrite.GrantedVia != "Directory.ReadWrite.All" {
		t.Fatalf("directory write check = %+v", userWrite)
	}
	for _, chk := range checks {
		if chk.Status == "unchecked" {
			t.Fatalf("preflight retained unchecked row: %+v", chk)
		}
	}
}

func TestPreflightDoesNotCallAConfirmedGrantMissing(t *testing.T) {
	f := newFakeGraph(t)
	f.tokenRoles = []string{"User.Read.All"}
	f.status["/users"] = http.StatusForbidden
	f.responses["/users"] = `{"error":{"code":"Authorization_RequestDenied","message":"The service rejected this request."}}`
	c := newTestClient(f, nil)

	checks, err := c.Preflight(context.Background(), "")
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	for _, check := range checks {
		if check.Area == "Directory — users" {
			if check.Status != "error" || !strings.Contains(check.Detail, "token contains the required permission") {
				t.Fatalf("confirmed grant conflict = %+v", check)
			}
			return
		}
	}
	t.Fatal("Directory — users check not found")
}

func TestUserRawStripsNullsAndOData(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users/u1"] = `{"@odata.context":"ctx","id":"u1","displayName":"Ada","mobilePhone":null,
		"onPremisesExtensionAttributes":{"extensionAttribute1":"IT-OPS"}}`
	c := newTestClient(f, nil)

	raw, err := c.UserRaw(context.Background(), "", "u1")
	if err != nil {
		t.Fatalf("UserRaw: %v", err)
	}
	if raw.ID != "u1" {
		t.Fatalf("id = %q", raw.ID)
	}
	if _, ok := raw.Attributes["mobilePhone"]; ok {
		t.Fatal("null attribute should be dropped")
	}
	if _, ok := raw.Attributes["@odata.context"]; ok {
		t.Fatal("@odata metadata should be dropped")
	}
	if ext, ok := raw.Attributes["onPremisesExtensionAttributes"].(map[string]any); !ok || ext["extensionAttribute1"] != "IT-OPS" {
		t.Fatalf("extension attributes = %+v", raw.Attributes["onPremisesExtensionAttributes"])
	}
}

// ---- Share Detective reads/writes ----

func TestUserGroupIDsLive(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users/u1/transitiveMemberOf"] = `{"value":[{"id":"g1"},{"id":"g2"}]}`
	c := newTestClient(f, nil)

	ids, err := c.UserGroupIDs(context.Background(), "", "u1")
	if err != nil || len(ids) != 2 || ids[0] != "g1" {
		t.Fatalf("ids = %v, %v", ids, err)
	}
}

func TestSharedItemsWalksDrivesAndReadsPermissions(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/sites/site1/drives"] = `{"value":[{"id":"d1"}]}`
	f.responses["/drives/d1/root/children"] = `{"value":[
		{"id":"i1","name":"Contract.docx","webUrl":"http://x/contract","file":{},"shared":{},"parentReference":{"path":"/drives/d1/root:/Docs"}},
		{"id":"i2","name":"Design","folder":{"childCount":1},"parentReference":{"path":"/drives/d1/root:"}}
	]}`
	f.responses["/drives/d1/items/i2/children"] = `{"value":[
		{"id":"i3","name":"Spec.pdf","webUrl":"http://x/spec","file":{},"shared":{},"parentReference":{"path":"/drives/d1/root:/Design"}}
	]}`
	f.responses["/drives/d1/items/i1/permissions"] = `{"value":[
		{"id":"p1","roles":["write"],"grantedToV2":{"user":{"id":"u9","displayName":"Ivan","email":"ivan@partner.com"}}},
		{"id":"p2","roles":["read"],"link":{"scope":"anonymous"}},
		{"id":"p3","roles":["read"],"link":{"scope":"users"},"grantedToIdentitiesV2":[{"user":{"id":"u2","displayName":"Bianca","email":"bianca@c.com"}}]}
	]}`
	f.responses["/drives/d1/items/i3/permissions"] = `{"value":[
		{"id":"p4","roles":["write"],"inheritedFrom":{"id":"i2"},"grantedToV2":{"group":{"id":"g5","displayName":"Falcon"}}}
	]}`
	c := newTestClient(f, nil)

	items, err := c.SharedItems(context.Background(), "", "site1")
	if err != nil {
		t.Fatalf("SharedItems: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2 (%+v)", len(items), items)
	}
	first := items[0]
	if first.Path != "/Docs/Contract.docx" || first.Type != "file" {
		t.Fatalf("item = %+v", first)
	}
	if len(first.Permissions) != 3 {
		t.Fatalf("permissions = %+v", first.Permissions)
	}
	if p := first.Permissions[0]; p.GranteeType != "user" || p.GranteeUPN != "ivan@partner.com" {
		t.Fatalf("direct perm = %+v", p)
	}
	if p := first.Permissions[1]; p.GranteeType != "link" || p.LinkScope != "anonymous" {
		t.Fatalf("broad link perm = %+v", p)
	}
	if p := first.Permissions[2]; p.GranteeType != "link" || p.LinkScope != "users" || p.GranteeUPN != "bianca@c.com" {
		t.Fatalf("specific link perm = %+v", p)
	}
	nested := items[1]
	if nested.ItemID != "i3" || !nested.Permissions[0].Inherited || nested.Permissions[0].GranteeType != "group" {
		t.Fatalf("nested item = %+v", nested)
	}
}

func TestDeletePermissionsLive(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/sites/site1/permissions/p1"] = `{}`
	f.responses["/drives/d1/items/i1/permissions/p2"] = `{}`
	c := newTestClient(f, nil)

	if err := c.DeleteSitePermission(context.Background(), "", "site1", "p1"); err != nil {
		t.Fatalf("DeleteSitePermission: %v", err)
	}
	if err := c.DeleteItemPermission(context.Background(), "", "site1", "d1", "i1", "p2"); err != nil {
		t.Fatalf("DeleteItemPermission: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.apiCalls[len(f.apiCalls)-2] != "DELETE /sites/site1/permissions/p1" {
		t.Fatalf("calls = %v", f.apiCalls)
	}
	if f.apiCalls[len(f.apiCalls)-1] != "DELETE /drives/d1/items/i1/permissions/p2" {
		t.Fatalf("calls = %v", f.apiCalls)
	}
}
