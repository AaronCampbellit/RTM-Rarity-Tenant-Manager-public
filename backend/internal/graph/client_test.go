package graph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

// fakeGraph serves both the Entra token endpoint and Graph resource paths so
// the live client can be exercised without credentials or network.
type fakeGraph struct {
	srv               *httptest.Server
	expiresIn         int
	tokenRoles        []string
	tokenRolesByScope map[string][]string
	responses         map[string]string // URL path → JSON body
	status            map[string]int    // URL path → non-200 status

	mu              sync.Mutex
	tokenHits       []string // authorities requested
	tokenClients    []string // client_id per token request
	tokenScopes     []string
	tokenAssertions []string
	apiAuthz        []string // Authorization header per Graph call
	apiHits         []string // Graph paths requested
	apiCalls        []string // "METHOD path" per Graph call
	apiBodies       []string // request body per Graph call
	apiAnchors      []string // X-AnchorMailbox per Exchange Admin call
	apiConsistency  []string // ConsistencyLevel per Graph call
	apiQueries      []string // raw query per Graph call
}

func newFakeGraph(t *testing.T) *fakeGraph {
	t.Helper()
	f := &fakeGraph{expiresIn: 3600, responses: map[string]string{}, status: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGraph) handle(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		authority := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/oauth2/v2.0/token")
		_ = r.ParseForm()
		scope := r.PostFormValue("scope")
		f.mu.Lock()
		f.tokenHits = append(f.tokenHits, authority)
		f.tokenClients = append(f.tokenClients, r.PostFormValue("client_id"))
		f.tokenScopes = append(f.tokenScopes, scope)
		f.tokenAssertions = append(f.tokenAssertions, r.PostFormValue("client_assertion"))
		f.mu.Unlock()
		accessToken := "tok-" + authority
		roles := f.tokenRoles
		if scoped := f.tokenRolesByScope[scope]; len(scoped) > 0 {
			roles = scoped
		}
		if len(roles) > 0 {
			payload, _ := json.Marshal(map[string]any{"roles": roles})
			accessToken = "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
		}
		fmt.Fprintf(w, `{"access_token":%q,"expires_in":%d}`, accessToken, f.expiresIn)
		return
	}

	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.apiHits = append(f.apiHits, r.URL.Path)
	f.apiCalls = append(f.apiCalls, r.Method+" "+r.URL.Path)
	f.apiBodies = append(f.apiBodies, string(body))
	f.apiAuthz = append(f.apiAuthz, r.Header.Get("Authorization"))
	f.apiAnchors = append(f.apiAnchors, r.Header.Get("X-AnchorMailbox"))
	f.apiConsistency = append(f.apiConsistency, r.Header.Get("ConsistencyLevel"))
	f.apiQueries = append(f.apiQueries, r.URL.RawQuery)
	f.mu.Unlock()

	if code, ok := f.status[r.URL.Path]; ok {
		w.WriteHeader(code)
		if body, ok := f.responses[r.URL.Path]; ok {
			_, _ = io.WriteString(w, body)
		}
		return
	}
	if body, ok := f.responses[r.URL.Path]; ok {
		_, _ = io.WriteString(w, body)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (f *fakeGraph) tokenRequests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tokenHits...)
}

func newTestClient(f *fakeGraph, resolve AuthorityResolver) *graphClient {
	c := newGraphClient(Config{ClientID: "app-id", ClientSecret: "app-secret", TenantID: "home-tenant"}, testLogger(), resolve)
	c.base = f.srv.URL
	c.loginBase = f.srv.URL
	c.exchangeBase = f.srv.URL
	c.http = f.srv.Client()
	return c
}

const usersJSON = `{"value":[
	{"id":"u1","displayName":"Ada Active","givenName":"Ada","surname":"Active","userPrincipalName":"ada@contoso.com","mail":"ada@contoso.com","department":"Eng","jobTitle":"Engineer","companyName":"Contoso","officeLocation":"HQ","employeeId":"CT-1","employeeType":"Employee","businessPhones":["+1 555 0100"],"mobilePhone":"+1 555 0200","city":"Seattle","state":"WA","country":"United States","usageLocation":"US","preferredLanguage":"en-US","createdDateTime":"2024-01-01T00:00:00Z","accountEnabled":true,"userType":"Member","assignedLicenses":[{"skuId":"sku-e5"}],"signInActivity":{"lastSuccessfulSignInDateTime":"2026-08-26T09:15:00Z"}},
	{"id":"u2","displayName":"Dan Disabled","userPrincipalName":"dan@contoso.com","department":"Ops","accountEnabled":false,"userType":"Member"},
	{"id":"u3","displayName":"Gia Guest","userPrincipalName":"gia@partner.com","department":"","accountEnabled":true,"userType":"Guest"}
]}`

const mfaReportJSON = `{"value":[
	{"id":"u1","isMfaRegistered":true},
	{"id":"u2","isMfaRegistered":false}
]}`

func TestTokenIsCachedPerAuthority(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/subscribedSkus"] = `{"value":[]}`
	c := newTestClient(f, nil)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := c.Licenses(ctx, ""); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	if hits := f.tokenRequests(); len(hits) != 1 || hits[0] != "home-tenant" {
		t.Fatalf("token requests = %v, want one for home-tenant", hits)
	}
}

// Mailboxes is sourced from the directory (users with a mailbox), not the
// fragile usage report. Only users with a non-empty mail are included, and the
// directory object id is the mailbox id.
func TestMailboxesFromDirectory(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users"] = `{"value":[
		{"id":"u1","displayName":"Ada Active","userPrincipalName":"ada@contoso.com","mail":"ada@contoso.com"},
		{"id":"u2","displayName":"No Mailbox","userPrincipalName":"svc@contoso.com","mail":""},
		{"id":"u3","displayName":"Bea Box","userPrincipalName":"bea@contoso.com","mail":"bea@contoso.com"}
	]}`
	c := newTestClient(f, nil)

	boxes, err := c.Mailboxes(context.Background(), "")
	if err != nil {
		t.Fatalf("Mailboxes: %v", err)
	}
	if len(boxes) != 2 {
		t.Fatalf("got %d mailboxes, want 2 (mailbox-less user excluded)", len(boxes))
	}
	if boxes[0].ID != "u1" || boxes[0].Email != "ada@contoso.com" || boxes[0].Name != "Ada Active" {
		t.Fatalf("mailbox 0 = %+v", boxes[0])
	}
	if boxes[1].ID != "u3" {
		t.Fatalf("mailbox 1 id = %q, want u3", boxes[1].ID)
	}
	if boxes[0].UsageAvailable || boxes[0].Size != "—" || boxes[0].UsageDetail == "" {
		t.Fatalf("missing optional report must degrade honestly: %+v", boxes[0])
	}
}

func TestMailboxesMergeOptionalUsageReport(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users"] = `{"value":[{
		"id":"u1","displayName":"Ada Active","userPrincipalName":"ada@contoso.com","mail":"ada@contoso.com",
		"accountEnabled":true,"createdDateTime":"2022-04-18T16:20:00Z","onPremisesSyncEnabled":false,
		"proxyAddresses":["SMTP:ada@contoso.com","smtp:a.quinn@contoso.com"],"assignedLicenses":[{"skuId":"sku1"}]
	}]}`
	f.responses["/reports/getMailboxUsageDetail(period='D7')"] = strings.Join([]string{
		"Report Refresh Date,User Principal Name,Last Activity Date,Item Count,Storage Used (Byte),Deleted Item Count,Deleted Item Size (Byte),Issue Warning Quota (Byte),Prohibit Send Quota (Byte),Prohibit Send/Receive Quota (Byte),Has Archive,Recipient Type",
		"2026-08-24,ada@contoso.com,2026-08-23,1200,2147483648,30,1048576,52613349376,53150220288,53687091200,True,UserMailbox",
	}, "\n")
	c := newTestClient(f, nil)

	boxes, err := c.Mailboxes(context.Background(), "")
	if err != nil {
		t.Fatalf("Mailboxes: %v", err)
	}
	if len(boxes) != 1 {
		t.Fatalf("boxes = %d, want 1", len(boxes))
	}
	box := boxes[0]
	if !box.UsageAvailable || box.Size != "2.0 GB" || box.Items != 1200 || box.Archive != "On" || box.Type != "User" {
		t.Fatalf("usage merge = %+v", box)
	}
	if box.UserPrincipalName != "ada@contoso.com" || len(box.Aliases) != 1 || box.Aliases[0] != "a.quinn@contoso.com" {
		t.Fatalf("identity enrichment = %+v", box)
	}
	if box.SourceOfAuthority != "cloud" || box.LicenseCount != 1 || box.AccountStatus != "Enabled" {
		t.Fatalf("directory state = %+v", box)
	}
}

func TestMailboxesKeepTypeWhenUsageReportConcealsIdentities(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users"] = `{"value":[
		{"id":"u1","displayName":"Ada Active","userPrincipalName":"ada@contoso.com","mail":"ada@contoso.com"},
		{"id":"u2","displayName":"Sales Shared","userPrincipalName":"sales@contoso.com","mail":"sales@contoso.com"}
	]}`
	f.responses["/reports/getMailboxUsageDetail(period='D7')"] = strings.Join([]string{
		"Report Refresh Date,User Principal Name,Item Count,Storage Used (Byte),Has Archive,Recipient Type",
		"2026-08-24,4fa39a3f63f24ea0,1200,2147483648,True,UserMailbox",
		"2026-08-24,ed1ba68a3f034c75,900,1073741824,False,SharedMailbox",
	}, "\n")
	f.responses["/$batch"] = `{"responses":[
		{"id":"0","status":200,"body":{"userPurpose":"user"}},
		{"id":"1","status":200,"body":{"userPurpose":"shared"}}
	]}`
	c := newTestClient(f, nil)

	boxes, err := c.Mailboxes(context.Background(), "")
	if err != nil {
		t.Fatalf("Mailboxes: %v", err)
	}
	if len(boxes) != 2 || boxes[0].Type != "User" || boxes[1].Type != "Shared" {
		t.Fatalf("purpose enrichment = %+v", boxes)
	}
	for _, box := range boxes {
		if box.UsageAvailable || !strings.Contains(box.UsageDetail, "concealing identities") {
			t.Fatalf("concealed usage coverage = %+v", box)
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	var batchBody string
	for i, call := range f.apiCalls {
		if call == "POST /$batch" {
			batchBody = f.apiBodies[i]
			break
		}
	}
	if !strings.Contains(batchBody, "/users/u1/mailboxSettings?$select=userPurpose") ||
		!strings.Contains(batchBody, "/users/u2/mailboxSettings?$select=userPurpose") {
		t.Fatalf("batch body = %s", batchBody)
	}
}

func TestMailboxTypeFromPurpose(t *testing.T) {
	tests := map[string]string{
		"user": "User", "linked": "User", "shared": "Shared",
		"room": "Room", "equipment": "Equipment", "unknown": "",
	}
	for input, want := range tests {
		if got := mailboxTypeFromPurpose(input); got != want {
			t.Errorf("mailboxTypeFromPurpose(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMailboxPermissionsUseExchangeAdminAPIWithExplicitCoverage(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/adminapi/v2.0/customer-tenant/Mailbox"] = `{
		"DisplayName":"Shared Sales",
		"GrantSendOnBehalfTo":["ada@contoso.com","bea@contoso.com"],
		"GrantSendOnBehalfToWithDisplayNames":[
			{"DisplayName":"Ada Active","PrimarySmtpAddress":"ada@contoso.com"},
			{"DisplayName":"Bea Box","PrimarySmtpAddress":"bea@contoso.com"}
		]
	}`
	resolve := func(context.Context, string) (TenantAuth, error) {
		return TenantAuth{
			Authority: "customer-tenant", ClientID: "graph-id", ClientSecret: "graph-secret",
			ExchangeClientID: "exchange-id", ExchangeClientSecret: "exchange-secret",
		}, nil
	}
	c := newTestClient(f, resolve)

	feed, err := c.MailboxPermissions(context.Background(), "ten_1", "mailbox-id")
	if err != nil {
		t.Fatalf("MailboxPermissions: %v", err)
	}
	if len(feed.Permissions) != 2 || feed.Permissions[0].Delegate != "Ada Active" ||
		feed.Permissions[0].Permission != MailboxPermSendOnBehalf {
		t.Fatalf("permissions = %+v", feed.Permissions)
	}
	if len(feed.Coverage) != 3 || feed.Coverage[0].Status != "not_supported" ||
		feed.Coverage[2].Status != "collected" {
		t.Fatalf("coverage = %+v", feed.Coverage)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tokenScopes) != 1 || f.tokenScopes[0] != "https://outlook.office365.com/.default" ||
		f.tokenClients[0] != "exchange-id" {
		t.Fatalf("exchange token request scopes=%v clients=%v", f.tokenScopes, f.tokenClients)
	}
	found := false
	for i, call := range f.apiCalls {
		if call == "POST /adminapi/v2.0/customer-tenant/Mailbox" {
			found = strings.Contains(f.apiBodies[i], `"CmdletName":"Get-Mailbox"`) &&
				strings.Contains(f.apiBodies[i], `"Identity":"mailbox-id"`) &&
				f.apiAnchors[i] == "APP:SystemMailbox{"+exchangeSystemMailboxID+"}@customer-tenant"
		}
	}
	if !found {
		t.Fatalf("Exchange Admin request calls=%v bodies=%v anchors=%v", f.apiCalls, f.apiBodies, f.apiAnchors)
	}
}

func TestSetSendOnBehalfUsesExchangeAdminAPI(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users/delegate-id"] = `{"userPrincipalName":"delegate@contoso.com"}`
	f.responses["/adminapi/v2.0/customer-tenant/Mailbox"] = `{}`
	resolve := func(context.Context, string) (TenantAuth, error) {
		return TenantAuth{Authority: "customer-tenant", ClientID: "app", ClientSecret: "secret"}, nil
	}
	c := newTestClient(f, resolve)

	if err := c.SetMailboxPermission(context.Background(), "ten_1", "mailbox-id", "delegate-id", MailboxPermSendOnBehalf, false); err != nil {
		t.Fatalf("SetMailboxPermission: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var body string
	for i, call := range f.apiCalls {
		if call == "POST /adminapi/v2.0/customer-tenant/Mailbox" {
			body = f.apiBodies[i]
		}
	}
	if !strings.Contains(body, `"CmdletName":"Set-Mailbox"`) ||
		!strings.Contains(body, `"add":["delegate@contoso.com"]`) {
		t.Fatalf("Set-Mailbox body = %s", body)
	}
}

func TestSetUnsupportedMailboxPermissionFailsClosed(t *testing.T) {
	f := newFakeGraph(t)
	c := newTestClient(f, nil)
	err := c.SetMailboxPermission(context.Background(), "ten_1", "mailbox-id", "delegate-id", MailboxPermFullAccess, false)
	if !errors.Is(err, ErrExchangeAdminUnsupported) {
		t.Fatalf("error = %v, want ErrExchangeAdminUnsupported", err)
	}
	if len(f.apiCalls) != 0 {
		t.Fatalf("unsupported permission made calls: %v", f.apiCalls)
	}
}

func TestExchangeAdminPreflightReportsConsentOrRBACGap(t *testing.T) {
	f := newFakeGraph(t)
	f.status["/adminapi/v2.0/home-tenant/Mailbox"] = http.StatusForbidden
	f.responses["/adminapi/v2.0/home-tenant/Mailbox"] = `{"error":{"code":"Authorization_RequestDenied","message":"Forbidden"}}`
	c := newTestClient(f, nil)

	check := c.exchangeAdminPreflight(context.Background(), "")
	if check.Status != "missing" || check.Permission != "Exchange.ManageAsAppV2" ||
		!strings.Contains(check.Detail, "Recipient Management") {
		t.Fatalf("preflight = %+v", check)
	}
}

func TestMailboxSettingsIncludesAllForwardingActions(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users/u1/mailboxSettings"] = `{
		"timeZone":"Pacific Standard Time","dateFormat":"M/d/yyyy","timeFormat":"h:mm tt",
		"language":{"locale":"en-US","displayName":"English (United States)"},"userPurpose":"shared",
		"delegateMeetingMessageDeliveryOptions":"sendToDelegateAndInformationToPrincipal",
		"workingHours":{"daysOfWeek":["monday","tuesday"],"startTime":"08:00:00","endTime":"17:00:00","timeZone":{"name":"Pacific Standard Time"}},
		"automaticRepliesSetting":{"status":"scheduled","internalReplyMessage":"Away","externalReplyMessage":"Away external","externalAudience":"contactsOnly","scheduledStartDateTime":{"dateTime":"2026-08-24T17:00:00"},"scheduledEndDateTime":{"dateTime":"2026-08-31T08:00:00"}}
	}`
	f.responses["/users/u1/mailFolders/inbox/messageRules"] = `{"value":[
		{"id":"r1","displayName":"RTM Managed Forwarding","isEnabled":true,"actions":{"forwardTo":[{"emailAddress":{"address":"archive@contoso.com"}}]}},
		{"id":"r2","displayName":"Vendor invoices","isEnabled":true,"hasError":false,"isReadOnly":false,"actions":{"redirectTo":[{"emailAddress":{"address":"processor@partner.example"}}]}}
	]}`
	c := newTestClient(f, nil)

	settings, err := c.MailboxSettings(context.Background(), "", "u1")
	if err != nil {
		t.Fatalf("MailboxSettings: %v", err)
	}
	if !settings.AutoReply || settings.AutoReplyStatus != "scheduled" || settings.UserPurpose != "shared" {
		t.Fatalf("settings = %+v", settings)
	}
	if !settings.RulesAvailable || len(settings.ForwardingRules) != 2 || settings.ForwardingTo != "archive@contoso.com" {
		t.Fatalf("forwarding = %+v", settings)
	}
	if settings.ForwardingRules[1].Mode != "Redirect" || settings.ForwardingRules[1].Recipients[0] != "processor@partner.example" {
		t.Fatalf("redirect rule = %+v", settings.ForwardingRules[1])
	}
}

// TestConnection must never reuse a cached token: Entra consent changes only
// appear on freshly issued tokens, so each test mints a new one.
func TestConnectionBypassesTokenCache(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/organization"] = `{"value":[{"id":"org"}]}`
	c := newTestClient(f, nil)
	ctx := context.Background()

	// Warm the cache via a normal read, then test twice.
	if err := c.TestConnection(ctx, ""); err != nil {
		t.Fatalf("test 1: %v", err)
	}
	if err := c.TestConnection(ctx, ""); err != nil {
		t.Fatalf("test 2: %v", err)
	}
	if hits := f.tokenRequests(); len(hits) != 2 {
		t.Fatalf("token requests = %d, want 2 (fresh token per test)", len(hits))
	}
}

func TestTokenRefetchedNearExpiry(t *testing.T) {
	f := newFakeGraph(t)
	// Inside the client's one-minute expiry margin, so every call re-tokens.
	f.expiresIn = 30
	f.responses["/organization"] = `{"value":[{"id":"org"}]}`
	c := newTestClient(f, nil)
	ctx := context.Background()

	_ = c.TestConnection(ctx, "")
	_ = c.TestConnection(ctx, "")
	if hits := f.tokenRequests(); len(hits) != 2 {
		t.Fatalf("token requests = %d, want 2 (no caching near expiry)", len(hits))
	}
}

func TestPerTenantAuthority(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/subscribedSkus"] = `{"value":[]}`
	resolve := func(_ context.Context, tenantID string) (TenantAuth, error) {
		return TenantAuth{Authority: map[string]string{
			"ten_1": "contoso.example",
			"ten_2": "fabrikam.example",
		}[tenantID]}, nil
	}
	c := newTestClient(f, resolve)
	ctx := context.Background()

	if _, err := c.Licenses(ctx, "ten_1"); err != nil {
		t.Fatalf("ten_1: %v", err)
	}
	if _, err := c.Licenses(ctx, "ten_2"); err != nil {
		t.Fatalf("ten_2: %v", err)
	}
	// Cached per authority: repeat calls add no token requests.
	if _, err := c.Licenses(ctx, "ten_1"); err != nil {
		t.Fatalf("ten_1 again: %v", err)
	}
	if hits := f.tokenRequests(); len(hits) != 2 || hits[0] != "contoso.example" || hits[1] != "fabrikam.example" {
		t.Fatalf("token requests = %v", hits)
	}

	// Each Graph call carried its own tenant's token.
	f.mu.Lock()
	authz := append([]string(nil), f.apiAuthz...)
	f.mu.Unlock()
	if authz[0] != "Bearer tok-contoso.example" || authz[1] != "Bearer tok-fabrikam.example" {
		t.Fatalf("authorization headers = %v", authz)
	}

	// Unmapped tenant ("" from the resolver) falls back to the home tenant.
	if _, err := c.Licenses(ctx, "ten_unknown"); err != nil {
		t.Fatalf("fallback tenant: %v", err)
	}
	hits := f.tokenRequests()
	if hits[len(hits)-1] != "home-tenant" {
		t.Fatalf("fallback authority = %q, want home-tenant", hits[len(hits)-1])
	}
}

func TestResolverErrorPropagates(t *testing.T) {
	f := newFakeGraph(t)
	resolve := func(context.Context, string) (TenantAuth, error) {
		return TenantAuth{}, errors.New("tenant not found")
	}
	c := newTestClient(f, resolve)

	if _, err := c.Users(context.Background(), "ten_x"); err == nil || !strings.Contains(err.Error(), "tenant not found") {
		t.Fatalf("err = %v, want resolver error", err)
	}
	if len(f.tokenRequests()) != 0 {
		t.Fatal("no token should be requested when authority resolution fails")
	}
}

func TestPerTenantClientCredentials(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/organization"] = `{"value":[{"id":"org"}]}`
	resolve := func(_ context.Context, tenantID string) (TenantAuth, error) {
		if tenantID == "ten_own_app" {
			return TenantAuth{Authority: "customer.example", ClientID: "customer-app", ClientSecret: "customer-secret"}, nil
		}
		// Tenant without its own app: authority only, global app creds.
		return TenantAuth{Authority: "shared.example"}, nil
	}
	c := newTestClient(f, resolve)
	ctx := context.Background()

	if err := c.TestConnection(ctx, "ten_own_app"); err != nil {
		t.Fatalf("own-app tenant: %v", err)
	}
	if err := c.TestConnection(ctx, "ten_shared"); err != nil {
		t.Fatalf("shared-app tenant: %v", err)
	}

	f.mu.Lock()
	clients := append([]string(nil), f.tokenClients...)
	f.mu.Unlock()
	if len(clients) != 2 || clients[0] != "customer-app" || clients[1] != "app-id" {
		t.Fatalf("token client ids = %v, want [customer-app app-id]", clients)
	}
}

func TestUsersMapping(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users"] = usersJSON
	f.responses["/reports/authenticationMethods/userRegistrationDetails"] = mfaReportJSON
	f.responses["/subscribedSkus"] = `{"value":[{"skuId":"sku-e5","skuPartNumber":"SPE_E5","consumedUnits":1,"prepaidUnits":{"enabled":2}}]}`
	c := newTestClient(f, nil)

	users, err := c.Users(context.Background(), "")
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("len = %d, want 3", len(users))
	}

	want := []struct{ status, mfa string }{
		{"Active", "Enabled"},
		{"Disabled", "Disabled"},
		{"Guest", "Unknown"}, // guest wins over enabled; missing from MFA report
	}
	for i, w := range want {
		if users[i].Status != w.status || users[i].MFA != w.mfa {
			t.Fatalf("user %d = status %q mfa %q, want %q/%q", i, users[i].Status, users[i].MFA, w.status, w.mfa)
		}
	}
	if users[0].Name != "Ada Active" || users[0].UPN != "ada@contoso.com" || users[0].Department != "Eng" {
		t.Fatalf("user 0 = %+v", users[0])
	}
	if users[0].License != "Microsoft 365 E5" || len(users[0].Licenses) != 1 {
		t.Fatalf("user 0 licensing = %+v", users[0])
	}
	if users[0].LastSignIn != "2026-08-26T09:15:00Z" || !users[0].LastSignInAvailable {
		t.Fatalf("user 0 sign-in = %+v", users[0])
	}
	if users[0].JobTitle != "Engineer" || users[0].Mail != "ada@contoso.com" || len(users[0].BusinessPhones) != 1 {
		t.Fatalf("user 0 directory attributes = %+v", users[0])
	}
}

func TestUsersDegradeWithoutLicensedSignInActivity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		switch r.URL.Path {
		case "/users":
			if strings.Contains(r.URL.RawQuery, "signInActivity") {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"error":{"code":"Authentication_RequestFromNonPremiumTenant","message":"premium license required"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"value":[{"id":"u1","displayName":"Ada","userPrincipalName":"ada@contoso.com","accountEnabled":true,"userType":"Member","assignedLicenses":[{"skuId":"sku-e5"}]}]}`)
		case "/reports/authenticationMethods/userRegistrationDetails":
			_, _ = io.WriteString(w, `{"value":[]}`)
		case "/subscribedSkus":
			_, _ = io.WriteString(w, `{"value":[{"skuId":"sku-e5","skuPartNumber":"SPE_E5","consumedUnits":1,"prepaidUnits":{"enabled":2}}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := newGraphClient(Config{ClientID: "app-id", ClientSecret: "secret", TenantID: "home"}, testLogger(), nil)
	c.base, c.loginBase, c.http = srv.URL, srv.URL, srv.Client()

	users, err := c.Users(context.Background(), "")
	if err != nil {
		t.Fatalf("Users should degrade without sign-in activity: %v", err)
	}
	if len(users) != 1 || users[0].LastSignInAvailable || users[0].LastSignIn != "" {
		t.Fatalf("users = %+v, want explicit unavailable sign-in state", users)
	}
	if users[0].License != "Microsoft 365 E5" {
		t.Fatalf("license = %q", users[0].License)
	}
}

func TestUserCountUsesLightweightAdvancedQuery(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users"] = `{"@odata.count":7,"value":[{"id":"u1"}]}`
	c := newTestClient(f, nil)

	count, err := c.UserCount(context.Background(), "")
	if err != nil || count != 7 {
		t.Fatalf("UserCount = %d, %v; want 7", count, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.apiConsistency[len(f.apiConsistency)-1]; got != "eventual" {
		t.Fatalf("ConsistencyLevel = %q, want eventual", got)
	}
	query := f.apiQueries[len(f.apiQueries)-1]
	if !strings.Contains(query, "%24count=true") && !strings.Contains(query, "$count=true") {
		t.Fatalf("query = %q, want $count=true", query)
	}
}

func TestUsersDegradeWhenMFAReportUnavailable(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users"] = usersJSON
	f.status["/reports/authenticationMethods/userRegistrationDetails"] = http.StatusForbidden
	c := newTestClient(f, nil)

	users, err := c.Users(context.Background(), "")
	if err != nil {
		t.Fatalf("Users should tolerate a missing MFA report: %v", err)
	}
	for _, u := range users {
		if u.MFA != "Unknown" {
			t.Fatalf("user %s MFA = %q, want Unknown", u.ID, u.MFA)
		}
	}
}

func TestGroupsMapping(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/groups"] = `{"value":[
		{"id":"g1","displayName":"Everyone","mailEnabled":true,"securityEnabled":false,"groupTypes":["Unified"]},
		{"id":"g2","displayName":"Dynamic Sec","mailEnabled":false,"securityEnabled":true,"groupTypes":["DynamicMembership"]},
		{"id":"g3","displayName":"Plain Sec","mailEnabled":false,"securityEnabled":true,"groupTypes":[]},
		{"id":"g4","displayName":"Old DL","mailEnabled":true,"securityEnabled":false,"groupTypes":[]},
		{"id":"g5","displayName":"Helpdesk","mailEnabled":true,"securityEnabled":true,"groupTypes":[]}
	]}`
	c := newTestClient(f, nil)

	groups, err := c.Groups(context.Background(), "")
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	want := []struct{ typ, membership, mail string }{
		{"M365", "Assigned", "Yes"},
		{"Security", "Dynamic", "No"},
		{"Security", "Assigned", "No"},
		{"Distribution", "Assigned", "Yes"},
		{"Mail-enabled Sec.", "Assigned", "Yes"},
	}
	for i, w := range want {
		g := groups[i]
		if g.Type != w.typ || g.Membership != w.membership || g.Mail != w.mail {
			t.Fatalf("group %d (%s) = %s/%s/%s, want %s/%s/%s", i, g.Name, g.Type, g.Membership, g.Mail, w.typ, w.membership, w.mail)
		}
	}
}

func TestGroupMembersMarksOwners(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/groups/g1/owners"] = `{"value":[{"id":"u1"}]}`
	f.responses["/groups/g1/members"] = `{"value":[
		{"id":"u1","displayName":"Ada","userPrincipalName":"ada@contoso.com"},
		{"id":"u2","displayName":"Dan","userPrincipalName":"dan@contoso.com"}
	]}`
	c := newTestClient(f, nil)

	members, err := c.GroupMembers(context.Background(), "", "g1")
	if err != nil {
		t.Fatalf("GroupMembers: %v", err)
	}
	if members[0].Role != "Owner" || members[1].Role != "Member" {
		t.Fatalf("roles = %s/%s, want Owner/Member", members[0].Role, members[1].Role)
	}
}

func TestLicensesMapping(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/subscribedSkus"] = `{"value":[
		{"skuPartNumber":"SPE_E5","consumedUnits":96,"prepaidUnits":{"enabled":100}},
		{"skuPartNumber":"SPE_E3","consumedUnits":50,"prepaidUnits":{"enabled":100}},
		{"skuPartNumber":"POWER_BI_PRO","consumedUnits":10,"prepaidUnits":{"enabled":10}}
	]}`
	c := newTestClient(f, nil)

	lics, err := c.Licenses(context.Background(), "")
	if err != nil {
		t.Fatalf("Licenses: %v", err)
	}
	want := []struct {
		pool string
		util int
	}{{"Low", 96}, {"OK", 50}, {"Full", 100}}
	for i, w := range want {
		if lics[i].Pool != w.pool || lics[i].Utilization != w.util {
			t.Fatalf("license %d = pool %q util %d, want %q/%d", i, lics[i].Pool, lics[i].Utilization, w.pool, w.util)
		}
	}
	if lics[0].Product != "Microsoft 365 E5" {
		t.Fatalf("product = %q", lics[0].Product)
	}
}

func TestGraphErrorSurfaces(t *testing.T) {
	f := newFakeGraph(t)
	f.status["/organization"] = http.StatusInternalServerError
	c := newTestClient(f, nil)

	if err := c.TestConnection(context.Background(), ""); err == nil {
		t.Fatal("expected an error from a 500 Graph response")
	}
}

func TestGraphErrorCarriesMicrosoftReason(t *testing.T) {
	f := newFakeGraph(t)
	f.status["/organization"] = http.StatusForbidden
	f.responses["/organization"] = `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}`
	c := newTestClient(f, nil)

	err := c.TestConnection(context.Background(), "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %T %v, want *APIError", err, err)
	}
	if apiErr.Status != http.StatusForbidden || apiErr.Code != "Authorization_RequestDenied" {
		t.Fatalf("apiErr = %+v", apiErr)
	}
	if !strings.Contains(apiErr.Error(), "Insufficient privileges") {
		t.Fatalf("error text = %q", apiErr.Error())
	}
}

func TestTokenErrorCarriesEntraReason(t *testing.T) {
	f := newFakeGraph(t)
	// Make the token endpoint itself reject the credentials.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`)
	}))
	t.Cleanup(srv.Close)
	c := newTestClient(f, nil)
	c.loginBase = srv.URL

	err := c.TestConnection(context.Background(), "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %T %v, want *APIError", err, err)
	}
	if apiErr.Code != "invalid_client" || !strings.Contains(apiErr.Message, "AADSTS7000215") {
		t.Fatalf("apiErr = %+v", apiErr)
	}
}

func TestGroupMemberWrites(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/groups/g1/members/$ref"] = `{}`
	f.responses["/groups/g1/members/u1/$ref"] = `{}`
	f.responses["/groups/g1/members/u2/$ref"] = `{}`
	c := newTestClient(f, nil)
	ctx := context.Background()

	if err := c.AddGroupMembers(ctx, "", "g1", []string{"u1", "u2"}); err != nil {
		t.Fatalf("AddGroupMembers: %v", err)
	}
	if err := c.RemoveGroupMembers(ctx, "", "g1", []string{"u1", "u2"}); err != nil {
		t.Fatalf("RemoveGroupMembers: %v", err)
	}

	f.mu.Lock()
	hits := append([]string(nil), f.apiHits...)
	f.mu.Unlock()
	// Two POST $ref adds, then two DELETE $ref removals.
	want := []string{"/groups/g1/members/$ref", "/groups/g1/members/$ref", "/groups/g1/members/u1/$ref", "/groups/g1/members/u2/$ref"}
	if len(hits) != 4 {
		t.Fatalf("api hits = %v", hits)
	}
	for i, w := range want {
		if hits[i] != w {
			t.Fatalf("hit %d = %q, want %q (all: %v)", i, hits[i], w, hits)
		}
	}
}

func TestUserWriteOperations(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users/u1"] = `{}`
	f.responses["/users/u1/assignLicense"] = `{}`
	f.responses["/users/u1/revokeSignInSessions"] = `{}`
	f.responses["/users/u1/authentication/methods"] = `{"value":[{"id":"password","@odata.type":"#microsoft.graph.passwordAuthenticationMethod"},{"id":"auth-1","@odata.type":"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"},{"id":"phone-1","@odata.type":"#microsoft.graph.phoneAuthenticationMethod"}]}`
	f.responses["/users/u1/authentication/microsoftAuthenticatorMethods/auth-1"] = `{}`
	f.responses["/users/u1/authentication/phoneMethods/phone-1"] = `{}`
	c := newTestClient(f, nil)
	ctx := context.Background()

	if err := c.SetAccountEnabled(ctx, "", "u1", false); err != nil {
		t.Fatalf("SetAccountEnabled: %v", err)
	}
	if err := c.AssignLicense(ctx, "", "u1", "sku-guid", false); err != nil {
		t.Fatalf("AssignLicense add: %v", err)
	}
	if err := c.AssignLicense(ctx, "", "u1", "sku-guid", true); err != nil {
		t.Fatalf("AssignLicense remove: %v", err)
	}
	if err := c.RevokeSessions(ctx, "", "u1"); err != nil {
		t.Fatalf("RevokeSessions: %v", err)
	}
	if err := c.ResetPassword(ctx, "", "u1", "Rtm-one-time-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if err := c.ResetMFA(ctx, "", "u1"); err != nil {
		t.Fatalf("ResetMFA: %v", err)
	}

	f.mu.Lock()
	calls := append([]string(nil), f.apiCalls...)
	bodies := append([]string(nil), f.apiBodies...)
	f.mu.Unlock()

	wantCalls := []string{
		"PATCH /users/u1",
		"POST /users/u1/assignLicense",
		"POST /users/u1/assignLicense",
		"POST /users/u1/revokeSignInSessions",
		"PATCH /users/u1",
		"GET /users/u1/authentication/methods",
		"DELETE /users/u1/authentication/microsoftAuthenticatorMethods/auth-1",
		"DELETE /users/u1/authentication/phoneMethods/phone-1",
	}
	for i, w := range wantCalls {
		if calls[i] != w {
			t.Fatalf("call %d = %q, want %q", i, calls[i], w)
		}
	}
	if !strings.Contains(bodies[0], `"accountEnabled":false`) {
		t.Fatalf("block body = %s", bodies[0])
	}
	if !strings.Contains(bodies[1], `"addLicenses":[{"skuId":"sku-guid"}]`) {
		t.Fatalf("assign body = %s", bodies[1])
	}
	if !strings.Contains(bodies[2], `"removeLicenses":["sku-guid"]`) {
		t.Fatalf("remove body = %s", bodies[2])
	}
	if !strings.Contains(bodies[4], `"forceChangePasswordNextSignIn":true`) || !strings.Contains(bodies[4], `"password":"Rtm-one-time-password"`) {
		t.Fatalf("password reset body = %s", bodies[4])
	}
}

func TestCreateGroup(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/groups"] = `{"id":"grp-new-1","displayName":"Marketing Team"}`
	c := newTestClient(f, nil)
	ctx := context.Background()

	// Security group.
	g, err := c.CreateGroup(ctx, "", NewGroup{DisplayName: "Marketing Team", MailNickname: "marketing", Type: GroupTypeSecurity})
	if err != nil {
		t.Fatalf("CreateGroup security: %v", err)
	}
	if g.ID != "grp-new-1" || g.Type != "Security" || g.Mail != "No" || g.Membership != "Assigned" {
		t.Fatalf("security group = %+v", g)
	}
	f.mu.Lock()
	securityBody := f.apiBodies[len(f.apiBodies)-1]
	f.mu.Unlock()
	if !strings.Contains(securityBody, `"securityEnabled":true`) || !strings.Contains(securityBody, `"mailEnabled":false`) ||
		strings.Contains(securityBody, `"Unified"`) {
		t.Fatalf("security body = %s", securityBody)
	}

	// M365 group.
	g, err = c.CreateGroup(ctx, "", NewGroup{DisplayName: "Marketing Team", MailNickname: "marketing", Type: GroupTypeM365})
	if err != nil {
		t.Fatalf("CreateGroup M365: %v", err)
	}
	if g.Type != "M365" || g.Mail != "Yes" {
		t.Fatalf("m365 group = %+v", g)
	}
	f.mu.Lock()
	m365Body := f.apiBodies[len(f.apiBodies)-1]
	f.mu.Unlock()
	if !strings.Contains(m365Body, `"groupTypes":["Unified"]`) || !strings.Contains(m365Body, `"mailEnabled":true`) {
		t.Fatalf("m365 body = %s", m365Body)
	}
}

func TestCreateGroupErrorSurfaces(t *testing.T) {
	f := newFakeGraph(t)
	f.status["/groups"] = http.StatusForbidden
	f.responses["/groups"] = `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges."}}`
	c := newTestClient(f, nil)

	_, err := c.CreateGroup(context.Background(), "", NewGroup{DisplayName: "X", MailNickname: "x", Type: GroupTypeSecurity})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "Authorization_RequestDenied" {
		t.Fatalf("err = %v, want APIError", err)
	}
}

func TestSampleProviderCreateGroupPersists(t *testing.T) {
	p := NewProvider(Config{}, testLogger(), nil) // sample mode
	ctx := context.Background()

	before, _ := p.Groups(ctx, "ten_1")
	g, err := p.CreateGroup(ctx, "ten_1", NewGroup{DisplayName: "New Sample Group", Type: GroupTypeSecurity})
	if err != nil || g.ID == "" {
		t.Fatalf("CreateGroup = %+v, %v", g, err)
	}
	after, _ := p.Groups(ctx, "ten_1")
	if len(after) != len(before)+1 {
		t.Fatalf("groups after create = %d, want %d", len(after), len(before)+1)
	}
	if after[len(after)-1].Name != "New Sample Group" {
		t.Fatalf("last group = %+v", after[len(after)-1])
	}
	// A different tenant doesn't see it.
	other, _ := p.Groups(ctx, "ten_other")
	if len(other) != len(before) {
		t.Fatalf("other tenant groups = %d, want %d", len(other), len(before))
	}
}

func TestGroupMemberWriteErrorSurfaces(t *testing.T) {
	f := newFakeGraph(t)
	f.status["/groups/g1/members/$ref"] = http.StatusForbidden
	f.responses["/groups/g1/members/$ref"] = `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}`
	c := newTestClient(f, nil)

	err := c.AddGroupMembers(context.Background(), "", "g1", []string{"u1"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "Authorization_RequestDenied" {
		t.Fatalf("err = %v, want APIError with Microsoft reason", err)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{512, "512 B"},
		{5 << 20, "5.0 MB"},
		{3 << 30, "3.0 GB"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.in); got != tc.want {
			t.Fatalf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSkuProductName(t *testing.T) {
	if got := skuProductName("SPE_E3"); got != "Microsoft 365 E3" {
		t.Fatalf("known sku = %q", got)
	}
	if got := skuProductName("SOMETHING_NEW"); got != "SOMETHING NEW" {
		t.Fatalf("unknown sku should remain readable, got %q", got)
	}
}

func TestSampleProvider(t *testing.T) {
	p := NewProvider(Config{}, testLogger(), nil) // no creds → sample
	if p.Mode() != "sample" {
		t.Fatalf("mode = %q", p.Mode())
	}
	ctx := context.Background()

	users, err := p.Users(ctx, "ten_1")
	if err != nil || len(users) == 0 {
		t.Fatalf("sample users = %d, %v", len(users), err)
	}
	rep, err := p.GlobalReport(ctx, "license")
	if err != nil || len(rep.Rows) == 0 {
		t.Fatalf("license report = %+v, %v", rep, err)
	}
	// Unknown types fall back to the MFA report rather than erroring.
	fallback, err := p.GlobalReport(ctx, "nonsense")
	if err != nil || len(fallback.Rows) == 0 {
		t.Fatalf("fallback report = %+v, %v", fallback, err)
	}
}

func TestNewProviderLiveWhenConfigured(t *testing.T) {
	p := NewProvider(Config{ClientID: "a", ClientSecret: "b", TenantID: "c"}, testLogger(), nil)
	if p.Mode() != "graph" {
		t.Fatalf("mode = %q, want graph", p.Mode())
	}
}

func TestNewProviderHybridWithResolverOnly(t *testing.T) {
	resolve := func(context.Context, string) (TenantAuth, error) { return TenantAuth{}, nil }
	if p := NewProvider(Config{}, testLogger(), resolve); p.Mode() != "auto" {
		t.Fatalf("mode = %q, want auto (resolver, no global app)", p.Mode())
	}
	if p := NewProvider(Config{}, testLogger(), nil); p.Mode() != "sample" {
		t.Fatalf("mode = %q, want sample (no resolver)", p.Mode())
	}
}

func TestHybridRoutesPerTenant(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/users"] = usersJSON
	f.responses["/reports/authenticationMethods/userRegistrationDetails"] = mfaReportJSON
	f.responses["/organization"] = `{"value":[{"id":"org"}]}`

	resolve := func(_ context.Context, tenantID string) (TenantAuth, error) {
		switch tenantID {
		case "ten_live":
			return TenantAuth{Authority: "customer.example", ClientID: "customer-app", ClientSecret: "customer-secret"}, nil
		case "ten_broken":
			return TenantAuth{}, errors.New("not found")
		default:
			// Seeded example tenant: authority only, no app credentials.
			return TenantAuth{Authority: "contoso.example"}, nil
		}
	}
	h := &hybridProvider{live: newTestClient(f, resolve), sample: sampleProvider{}, resolve: resolve}
	ctx := context.Background()

	// Cred-bearing tenant reads live (from the fake Graph server).
	liveUsers, err := h.Users(ctx, "ten_live")
	if err != nil {
		t.Fatalf("live users: %v", err)
	}
	if len(liveUsers) != 3 || liveUsers[0].Name != "Ada Active" {
		t.Fatalf("live users = %+v", liveUsers)
	}

	// Credential-less tenant serves sample data with no Graph traffic.
	before := len(f.tokenRequests())
	sampleUsers, err := h.Users(ctx, "ten_1")
	if err != nil {
		t.Fatalf("sample users: %v", err)
	}
	if len(sampleUsers) != 12 || len(f.tokenRequests()) != before {
		t.Fatalf("sample path leaked to Graph: users=%d tokens=%d→%d", len(sampleUsers), before, len(f.tokenRequests()))
	}

	// Resolver failure degrades to sample rather than erroring.
	if _, err := h.Users(ctx, "ten_broken"); err != nil {
		t.Fatalf("broken tenant should fall back to sample: %v", err)
	}
	if err := h.TestConnection(ctx, "ten_live"); err != nil {
		t.Fatalf("live test connection: %v", err)
	}
}
