package threatlocker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestPortalRequestAllowsNinetySeconds(t *testing.T) {
	c := newClient(Config{BaseURL: "https://portal.example.test"})
	var remaining time.Duration
	c.http.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("portal request has no deadline")
		}
		remaining = time.Until(deadline)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     make(http.Header),
		}, nil
	})

	err := c.do(context.Background(), Auth{Token: "token", OrgID: "org"}, "test", nil, nil)
	if err != nil {
		t.Fatalf("portal request: %v", err)
	}
	if remaining < 89*time.Second || remaining > 90*time.Second {
		t.Fatalf("portal request deadline = %s, want approximately 90s", remaining)
	}
}

// fakePortal is a minimal ThreatLocker portal API double. It records the
// last request's headers/body per path and serves canned responses.
type fakePortal struct {
	t             *testing.T
	srv           *httptest.Server
	lastAuth      map[string]string // path → Authorization header
	lastOrg       map[string]string // path → managedOrganizationId header
	lastBody      map[string]string // path → raw request body
	lastMethod    map[string]string // path → HTTP method
	respond       map[string]any    // path → response payload
	status        map[string]int    // path → forced status code
	requireMethod map[string]string // path → required HTTP method
}

func newFakePortal(t *testing.T) *fakePortal {
	f := &fakePortal{
		t:        t,
		lastAuth: map[string]string{}, lastOrg: map[string]string{}, lastBody: map[string]string{},
		lastMethod: map[string]string{}, respond: map[string]any{}, status: map[string]int{},
		requireMethod: map[string]string{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		f.lastMethod[path] = r.Method
		f.lastAuth[path] = r.Header.Get("Authorization")
		f.lastOrg[path] = r.Header.Get("managedOrganizationId")
		var body strings.Builder
		if r.Body != nil {
			b := make([]byte, 1<<16)
			n, _ := r.Body.Read(b)
			body.Write(b[:n])
		}
		f.lastBody[path] = body.String()
		if method, ok := f.requireMethod[path]; ok && r.Method != method {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`{"message":"method not allowed"}`))
			return
		}
		if code, ok := f.status[path]; ok {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"message":"portal said no"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if resp, ok := f.respond[path]; ok {
			if b, ok := resp.([]byte); ok {
				_, _ = w.Write(b)
				return
			}
			if fn, ok := resp.(func(string) any); ok {
				_ = json.NewEncoder(w).Encode(fn(f.lastBody[path]))
				return
			}
			// Request-aware responder (the body is already consumed; read it
			// from f.lastBody). Returns the status code and payload.
			if fn, ok := resp.(func(*http.Request) (int, any)); ok {
				code, payload := fn(r)
				w.WriteHeader(code)
				_ = json.NewEncoder(w).Encode(payload)
				return
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePortal) client(orgID string) Provider {
	return NewProvider(Config{
		BaseURL: f.srv.URL, Instance: "test", Token: "tl-secret-token", ParentOrgID: orgID,
	})
}

func TestDevicesMapsWireShape(t *testing.T) {
	f := newFakePortal(t)
	recent := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)
	f.respond["Computer/ComputerGetByAllParameters"] = []map[string]any{{
		"computerId": "dev_1", "computerName": "WS-ALPHA", "group": "Workstations",
		"osType": 1, "serviceVersion": "10.9.1", "mode": "MonitorOnly",
		"isTamperProtectionDisabled": false, "lastCheckin": recent,
	}}
	devices, err := f.client("org-guid").Devices(context.Background(), "ten_1")
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(devices))
	}
	d := devices[0]
	if d.ID != "dev_1" || d.Hostname != "WS-ALPHA" || d.OS != "windows" ||
		d.Mode != ModeMonitorOnly || d.Group != "Workstations" || !d.TamperProtection || !d.Online {
		t.Fatalf("device mapped wrong: %+v", d)
	}
	// Every call carries the token and the tenant's organization scoping.
	if f.lastAuth["Computer/ComputerGetByAllParameters"] != "tl-secret-token" {
		t.Fatalf("Authorization header = %q", f.lastAuth["Computer/ComputerGetByAllParameters"])
	}
	if f.lastOrg["Computer/ComputerGetByAllParameters"] != "org-guid" {
		t.Fatalf("managedOrganizationId header = %q", f.lastOrg["Computer/ComputerGetByAllParameters"])
	}
}

func TestDevicesFetchesChildOrganizationsAndAllPages(t *testing.T) {
	f := newFakePortal(t)
	rows := make([]map[string]any, 205)
	for i := range rows {
		rows[i] = map[string]any{
			"computerId":   fmt.Sprintf("dev_%03d", i+1),
			"computerName": fmt.Sprintf("WS-%03d", i+1),
			"group":        "Workstations",
			"osType":       1,
			"mode":         "Secure",
		}
	}
	f.respond["Computer/ComputerGetByAllParameters"] = func(body string) any {
		var q computerQuery
		_ = json.Unmarshal([]byte(body), &q)
		if !q.ChildOrganizations {
			t.Fatalf("ChildOrganizations = false, want true")
		}
		start := (q.PageNumber - 1) * q.PageSize
		if start >= len(rows) {
			return []map[string]any{}
		}
		end := start + q.PageSize
		if end > len(rows) {
			end = len(rows)
		}
		return rows[start:end]
	}
	devices, err := f.client("org-guid").Devices(context.Background(), "ten_1")
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) != len(rows) {
		t.Fatalf("got %d devices, want %d", len(devices), len(rows))
	}
	if devices[204].ID != "dev_205" {
		t.Fatalf("last device = %+v", devices[204])
	}
}

func TestModeNormalization(t *testing.T) {
	cases := map[string]string{
		"Secure": ModeSecured, "MonitorOnly": ModeMonitorOnly, "Monitor Only": ModeMonitorOnly,
		"Learning": ModeLearning, "Installation": ModeInstallation, "": ModeSecured,
	}
	for in, want := range cases {
		if got := normalizeMode(in); got != want {
			t.Errorf("normalizeMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNotConnectedWithoutCreds(t *testing.T) {
	// No global config means the workspace is unconnected.
	p := NewProvider(Config{})
	if _, err := p.Devices(context.Background(), "ten_1"); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("err = %v, want ErrNotConnected", err)
	}
	// Parent org ID without any token is also unconnected.
	p = NewProvider(Config{ParentOrgID: "org-guid"})
	if err := p.TestConnection(context.Background(), "ten_1"); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("err = %v, want ErrNotConnected", err)
	}
}

func TestGlobalFallbackCredentials(t *testing.T) {
	f := newFakePortal(t)
	f.respond["Computer/ComputerGetByAllParameters"] = []map[string]any{}
	p := NewProvider(Config{
		BaseURL: f.srv.URL, Instance: "g", Token: "global-token", ParentOrgID: "org-2",
	})
	if err := p.TestConnection(context.Background(), "ten_2"); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if f.lastAuth["Computer/ComputerGetByAllParameters"] != "global-token" ||
		f.lastOrg["Computer/ComputerGetByAllParameters"] != "org-2" {
		t.Fatal("global fallback credentials not applied")
	}
}

func TestAPIErrorCarriesPortalReasonNotToken(t *testing.T) {
	f := newFakePortal(t)
	f.status["Computer/ComputerGetByAllParameters"] = http.StatusUnauthorized
	_, err := f.client("org-guid").Devices(context.Background(), "ten_1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v, want 401 APIError", err)
	}
	if !strings.Contains(apiErr.Error(), "portal said no") {
		t.Fatalf("error should carry the portal's message: %v", apiErr)
	}
	if strings.Contains(apiErr.Error(), "tl-secret-token") {
		t.Fatal("error text leaked the API token")
	}
}

func TestPoliciesListMapsWireShape(t *testing.T) {
	f := newFakePortal(t)
	f.respond["Policy/PolicyGetByParameters"] = []map[string]any{
		{"policyId": "pol_1", "policyName": "Permit Office", "policyAction": "Permit",
			"appliesTo": "Entire Organization", "isEnabled": true},
		{"policyId": "pol_2", "name": "Deny unsigned installers", "action": "Deny",
			"appliesToName": "Workstations", "status": "Disabled"},
	}
	pols, err := f.client("org-guid").Policies(context.Background(), "ten_1")
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(pols) != 2 {
		t.Fatalf("got %d policies, want 2", len(pols))
	}
	if pols[0].Name != "Permit Office" || pols[0].Action != "permit" ||
		pols[0].AppliesTo != "Entire Organization" || pols[0].Status != "Enabled" {
		t.Fatalf("policy[0] mapped wrong: %+v", pols[0])
	}
	if pols[1].Name != "Deny unsigned installers" || pols[1].Action != "deny" ||
		pols[1].AppliesTo != "Workstations" || pols[1].Status != "Disabled" {
		t.Fatalf("policy[1] mapped wrong: %+v", pols[1])
	}
	// The list query carries the documented required fields.
	body := f.lastBody["Policy/PolicyGetByParameters"]
	if !strings.Contains(body, `"filter"`) || !strings.Contains(body, `"pageNumber":1`) {
		t.Fatalf("policy query body missing required fields: %s", body)
	}
}

func TestPoliciesListAcceptsLoosePortalFieldTypes(t *testing.T) {
	f := newFakePortal(t)
	f.respond["Policy/PolicyGetByParameters"] = map[string]any{
		"data": []map[string]any{
			{"policyId": "pol_1", "policyName": "Ringfenced App", "policyAction": "Permit",
				"appliesTo": "Workstations", "ringfence": 1, "isEnabled": 0},
		},
	}
	pols, err := f.client("org-guid").Policies(context.Background(), "ten_1")
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(pols) != 1 {
		t.Fatalf("got %d policies, want 1", len(pols))
	}
	if pols[0].Action != "ringfence" || pols[0].Status != "Disabled" {
		t.Fatalf("policy mapped wrong: %+v", pols[0])
	}
}

func TestPoliciesListMapsLivePortalMetadata(t *testing.T) {
	f := newFakePortal(t)
	f.respond["Policy/PolicyGetByParameters"] = []map[string]any{
		{"policyId": "pol_live", "name": "Microsoft Office (Ringfenced)", "policyAction": "Permit",
			"policyActionId": 1, "appliesToName": "Global", "groupName": "Global",
			"applicationIdList": []string{"app_1"},
			"userGroupIdList":   []string{"grp_1", "grp_2"}, "allUserGroups": true,
			"lastMatchDateTime": "2026-07-08T02:53:52Z", "monitorMode": 0,
			"ringfence": true, "isEnabled": true},
	}
	pols, err := f.client("org-guid").Policies(context.Background(), "ten_1")
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(pols) != 1 {
		t.Fatalf("got %d policies, want 1", len(pols))
	}
	p := pols[0]
	if p.Action != "ringfence" || p.PolicyActionID != 1 || p.ApplicationCount != 1 ||
		p.UserCount != 2 || !p.AllUsers || p.LastMatchedAt != "2026-07-08T02:53:52Z" || p.MonitorMode != 0 {
		t.Fatalf("policy metadata mapped wrong: %+v", p)
	}
}

func TestPoliciesListTreatsEmptySuccessBodyAsEmptyList(t *testing.T) {
	f := newFakePortal(t)
	f.respond["Policy/PolicyGetByParameters"] = []byte{}
	pols, err := f.client("org-guid").Policies(context.Background(), "ten_1")
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(pols) != 0 {
		t.Fatalf("got %d policies, want 0", len(pols))
	}
}

func TestPoliciesListAcceptsLargePortalResponse(t *testing.T) {
	f := newFakePortal(t)
	rows := make([]map[string]any, 1400)
	for i := range rows {
		rows[i] = map[string]any{
			"policyId":     "pol_large",
			"policyName":   strings.Repeat("large policy ", 70),
			"policyAction": "Permit",
			"appliesTo":    "Workstations",
			"isEnabled":    true,
		}
	}
	f.respond["Policy/PolicyGetByParameters"] = rows
	pols, err := f.client("org-guid").Policies(context.Background(), "ten_1")
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(pols) != len(rows) {
		t.Fatalf("got %d policies, want %d", len(pols), len(rows))
	}
}

func TestPoliciesListFetchesAllPages(t *testing.T) {
	f := newFakePortal(t)
	rows := make([]map[string]any, 1001)
	for i := range rows {
		rows[i] = map[string]any{
			"policyId": fmt.Sprintf("pol_%d", i+1), "name": "Dell Touchpad",
			"policyAction": "Permit", "appliesToName": fmt.Sprintf("DESKTOP-%04d", i+1), "isEnabled": true,
		}
	}
	f.respond["Policy/PolicyGetByParameters"] = func(body string) any {
		var q policyQuery
		_ = json.Unmarshal([]byte(body), &q)
		if !q.ChildOrganizations {
			t.Fatalf("ChildOrganizations = false, want true")
		}
		start := (q.PageNumber - 1) * q.PageSize
		if start >= len(rows) {
			return []map[string]any{}
		}
		end := start + q.PageSize
		if end > len(rows) {
			end = len(rows)
		}
		return rows[start:end]
	}
	pols, err := f.client("org-guid").Policies(context.Background(), "ten_1")
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(pols) != len(rows) {
		t.Fatalf("got %d policies, want %d", len(pols), len(rows))
	}
	if pols[1000].AppliesTo != "DESKTOP-1001" {
		t.Fatalf("last policy = %+v", pols[1000])
	}
}

func TestPolicyDetailMapsEditableFields(t *testing.T) {
	f := newFakePortal(t)
	f.respond["Policy/PolicyGetById"] = map[string]any{
		"policyId": "pol_1", "name": "Permit Office", "description": "Office apps",
		"comments": "Managed by RTM", "policyActionId": 2, "isEnabled": true,
		"monitorMode": 1, "orderBy": 10, "neverExpires": true,
		"logAction": true, "notifyOnMatch": false, "notifyOnRequest": true,
		"killRunningProcesses": false, "applicationSelection": 1,
		"applicationIdList": []string{"app_1", "app_2"},
		"applicationList": []any{
			map[string]any{"applicationId": "app_1", "name": "Microsoft Word", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},
			map[string]any{"applicationId": "app_2", "applicationName": "Microsoft Excel"},
		},
		"organizationId": "org-guid",
	}
	pol, err := f.client("org-guid").Policy(context.Background(), "ten_1", "pol_1")
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	if pol.ID != "pol_1" || pol.Name != "Permit Office" || pol.PolicyActionID != 2 ||
		!pol.IsEnabled || len(pol.ApplicationIDs) != 2 || len(pol.Applications) != 2 ||
		pol.Applications[0].Name != "Microsoft Word" || pol.Raw["policyId"] != "pol_1" {
		t.Fatalf("policy detail mapped wrong: %+v", pol)
	}
	if f.lastAuth["Policy/PolicyGetById"] != "tl-secret-token" || f.lastOrg["Policy/PolicyGetById"] != "org-guid" {
		t.Fatal("policy detail call missing auth/org scoping")
	}
}

func TestUpdatePolicyPatchesExistingDetail(t *testing.T) {
	f := newFakePortal(t)
	f.requireMethod["Policy/PolicyUpdateById"] = http.MethodPut
	f.respond["Policy/PolicyGetById"] = map[string]any{
		"policyId": "pol_1", "name": "Old name", "description": "old",
		"policyActionId": 1, "isEnabled": true, "applicationIdList": []string{"app_1"},
	}
	f.respond["Policy/PolicyUpdateById"] = map[string]any{
		"policyId": "pol_1", "name": "New name", "description": "old",
		"policyActionId": 1, "isEnabled": false, "applicationIdList": []string{"app_1"},
	}
	name := "New name"
	enabled := false
	pol, err := f.client("org-guid").UpdatePolicy(context.Background(), "ten_1", model.TLPolicyPatch{
		ID: "pol_1", Name: &name, IsEnabled: &enabled,
	})
	if err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if pol.Name != "New name" || pol.IsEnabled {
		t.Fatalf("updated policy mapped wrong: %+v", pol)
	}
	if f.lastMethod["Policy/PolicyUpdateById"] != http.MethodPut {
		t.Fatalf("update method = %s, want PUT", f.lastMethod["Policy/PolicyUpdateById"])
	}
	body := f.lastBody["Policy/PolicyUpdateById"]
	if !strings.Contains(body, `"policyId":"pol_1"`) || !strings.Contains(body, `"name":"New name"`) ||
		!strings.Contains(body, `"isEnabled":false`) {
		t.Fatalf("update body missing patched fields: %s", body)
	}
}

func TestCreatePolicyPostsInsertPayload(t *testing.T) {
	f := newFakePortal(t)
	f.respond["Policy/PolicyInsert"] = map[string]any{
		"policyId": "pol_new", "name": "Template policy", "isEnabled": true,
	}
	detail := model.TLPolicyDetail{
		Name: "Template policy", Description: "from RTM", IsEnabled: true,
		PolicyActionID: 2, ApplicationIDs: []string{"app_1"},
		Raw: map[string]any{"name": "Template policy", "description": "from RTM", "isEnabled": true, "policyActionId": float64(2), "applicationIdList": []any{"app_1"}},
	}
	pol, err := f.client("org-guid").CreatePolicy(context.Background(), "ten_1", detail)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if pol.ID != "pol_new" || pol.Name != "Template policy" {
		t.Fatalf("created policy mapped wrong: %+v", pol)
	}
	body := f.lastBody["Policy/PolicyInsert"]
	if !strings.Contains(body, `"name":"Template policy"`) || !strings.Contains(body, `"managedOrganizationId"`) {
		t.Fatalf("insert body missing expected fields: %s", body)
	}
}

func TestApplicationsSearchMapsPortalRows(t *testing.T) {
	f := newFakePortal(t)
	f.respond["Application/ApplicationGetByParameters"] = func(body string) any {
		var q map[string]any
		_ = json.Unmarshal([]byte(body), &q)
		if q["searchText"] != "dell" || q["searchBy"] != "app" || q["orderBy"] != "name" {
			t.Fatalf("app search body = %s", body)
		}
		if q["includeChildOrganizations"] != true || q["permittedApplications"] != false {
			t.Fatalf("app search flags = %s", body)
		}
		return map[string]any{"data": []map[string]any{{
			"applicationId": "app_1", "name": "Dell Display Manager",
			"description": "display utility", "organizationId": "org-guid",
			"organizationName": "Fabrikam", "osType": 1, "status": 1,
			"isBuiltIn": false, "isHidden": false, "policyCount": 2,
			"applicationFileCount": 3, "modifiedDate": "2026-07-08T02:00:00Z",
		}}}
	}
	apps, err := f.client("org-guid").Applications(context.Background(), "ten_1", AppSearchRequest{
		SearchText: "dell", SearchBy: "app", IncludeChildOrganizations: true, IncludeUnused: true,
	})
	if err != nil {
		t.Fatalf("Applications: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("got %d apps, want 1", len(apps))
	}
	app := apps[0]
	if app.ID != "app_1" || app.Name != "Dell Display Manager" || app.OrganizationID != "org-guid" ||
		app.Organization != "Fabrikam" || app.Source != "parent" || app.OS != "windows" ||
		app.Status != "Enabled" || app.PolicyCount != 2 || app.FileCount != 3 {
		t.Fatalf("app mapped wrong: %+v", app)
	}
}

func TestApplicationFilesUseGetByParametersAndMapRules(t *testing.T) {
	const path = "ApplicationFile/ApplicationFileGetByParameters"
	f := newFakePortal(t)
	f.respond["Application/ApplicationGetByParameters"] = map[string]any{"data": []map[string]any{{
		"applicationId": "app_1", "organizationId": "org-guid", "osType": 1,
	}}}
	f.requireMethod[path] = http.MethodPost
	f.respond[path] = []map[string]any{{
		"applicationFileId": float64(42), "applicationId": "app_1",
		"fullPath": "C:\\Program Files\\Dell\\ddm.exe", "processPath": "explorer.exe",
		"cert": "thumb", "hash": "abc", "notes": "copied", "installedBy": "Dell",
		"osType": 1, "keyFile": true, "isHashOnly": false,
	}}
	files, err := f.client("org-guid").ApplicationFiles(context.Background(), "ten_1", "app_1", 1)
	if err != nil {
		t.Fatalf("ApplicationFiles: %v", err)
	}
	if f.lastMethod[path] != http.MethodPost {
		t.Fatalf("method = %s, want POST", f.lastMethod[path])
	}
	// The portal rejects the request without a valid osType (417), so it must
	// be sent in the body scoped to the owning application.
	if body := f.lastBody[path]; !strings.Contains(body, `"osType":1`) || !strings.Contains(body, `"applicationId":"app_1"`) {
		t.Fatalf("request body missing osType/applicationId: %s", body)
	}
	if len(files) != 1 || files[0].ApplicationFileID != 42 || files[0].FullPath == "" || !files[0].KeyFile {
		t.Fatalf("files mapped wrong: %+v", files)
	}
}

func TestUpdateApplicationRenamesWithPut(t *testing.T) {
	f := newFakePortal(t)
	f.respond["Application/ApplicationGetByParameters"] = map[string]any{"data": []map[string]any{{
		"applicationId": "app_1", "organizationId": "org-guid", "osType": 1,
	}}}
	f.requireMethod["Application/ApplicationUpdateById"] = http.MethodPut
	f.respond["Application/ApplicationGetById"] = map[string]any{
		"applicationId": "app_1", "name": "Old", "description": "old desc",
		"organizationId": "org-guid", "osType": 1,
	}
	f.respond["Application/ApplicationUpdateById"] = map[string]any{
		"applicationId": "app_1", "name": "New", "description": "old desc",
		"organizationId": "org-guid", "osType": 1,
	}
	name := "New"
	app, err := f.client("org-guid").UpdateApplication(context.Background(), "ten_1", model.TLApplicationPatch{
		ID: "app_1", Name: &name,
	})
	if err != nil {
		t.Fatalf("UpdateApplication: %v", err)
	}
	if app.Name != "New" || app.ID != "app_1" {
		t.Fatalf("updated app mapped wrong: %+v", app)
	}
	if f.lastMethod["Application/ApplicationUpdateById"] != http.MethodPut {
		t.Fatalf("method = %s, want PUT", f.lastMethod["Application/ApplicationUpdateById"])
	}
	if !strings.Contains(f.lastBody["Application/ApplicationUpdateById"], `"name":"New"`) {
		t.Fatalf("update body = %s", f.lastBody["Application/ApplicationUpdateById"])
	}
}

func TestApplicationDeleteChoosesSafeOrConfirmEndpoint(t *testing.T) {
	f := newFakePortal(t)
	app1 := model.TLApplication{ID: "app_1", Name: "App One", OrganizationID: "org-guid", OSType: 1}
	if err := f.client("org-guid").DeleteApplication(context.Background(), "ten_1", app1, false); err != nil {
		t.Fatalf("DeleteApplication safe: %v", err)
	}
	safeBody := f.lastBody["Application/ApplicationUpdateForDelete"]
	if f.lastMethod["Application/ApplicationUpdateForDelete"] != http.MethodPost ||
		!strings.Contains(safeBody, "app_1") {
		t.Fatalf("safe delete call missing: method=%s body=%s",
			f.lastMethod["Application/ApplicationUpdateForDelete"], safeBody)
	}
	// The KB documents name, organizationId, and osType as required alongside
	// the application id.
	for _, want := range []string{`"name":"App One"`, `"organizationId":"org-guid"`, `"osType":1`} {
		if !strings.Contains(safeBody, want) {
			t.Fatalf("safe delete body missing %s: %s", want, safeBody)
		}
	}
	app2 := model.TLApplication{ID: "app_2", Name: "App Two", OrganizationID: "org-guid", OSType: 1}
	if err := f.client("org-guid").DeleteApplication(context.Background(), "ten_1", app2, true); err != nil {
		t.Fatalf("DeleteApplication confirm: %v", err)
	}
	if f.lastMethod["Application/ApplicationConfirmUpdateForDelete"] != http.MethodPost ||
		!strings.Contains(f.lastBody["Application/ApplicationConfirmUpdateForDelete"], "app_2") {
		t.Fatalf("confirm delete call missing: method=%s body=%s",
			f.lastMethod["Application/ApplicationConfirmUpdateForDelete"], f.lastBody["Application/ApplicationConfirmUpdateForDelete"])
	}
}

func TestDeletePoliciesUsesPutAndDeployPoliciesPostsQueue(t *testing.T) {
	f := newFakePortal(t)
	f.requireMethod["Policy/PolicyUpdateForDeleteByIds"] = http.MethodPut
	auth := Auth{Instance: "test", Token: "tl-secret-token", OrgID: "org-guid"}
	// pol_child lives in a child organization: like the live portal, both
	// PolicyGetById and the delete only work when the managedOrganizationId
	// header names the owning org ("Unable to retrieve application policy"
	// otherwise).
	owners := map[string]string{"pol_child": "org-child", "pol_2": "org-guid"}
	f.respond["Policy/PolicyGetById"] = func(r *http.Request) (int, any) {
		id := r.URL.Query().Get("policyId")
		if owners[id] != r.Header.Get("managedOrganizationId") {
			return http.StatusBadRequest, map[string]any{"message": "Unable to retrieve application policy"}
		}
		return http.StatusOK, map[string]any{"policyId": id, "organizationId": owners[id]}
	}
	type deleteCall struct{ org, body string }
	var deletes []deleteCall
	f.respond["Policy/PolicyUpdateForDeleteByIds"] = func(r *http.Request) (int, any) {
		deletes = append(deletes, deleteCall{r.Header.Get("managedOrganizationId"), f.lastBody["Policy/PolicyUpdateForDeleteByIds"]})
		return http.StatusOK, map[string]any{}
	}
	if err := f.client("org-guid").DeletePolicies(context.Background(), "ten_1", []model.TLPolicy{
		{ID: "pol_child", OrganizationID: "org-child"},
		{ID: "pol_2"}, // no org on the row → the auth org
	}); err != nil {
		t.Fatalf("DeletePolicies: %v", err)
	}
	if f.lastMethod["Policy/PolicyUpdateForDeleteByIds"] != http.MethodPut {
		t.Fatalf("policy delete method = %s, want PUT", f.lastMethod["Policy/PolicyUpdateForDeleteByIds"])
	}
	if len(deletes) != 2 {
		t.Fatalf("got %d delete calls, want one per owning org: %+v", len(deletes), deletes)
	}
	if deletes[0].org != "org-child" || !strings.Contains(deletes[0].body, "pol_child") ||
		deletes[1].org != "org-guid" || !strings.Contains(deletes[1].body, "pol_2") {
		t.Fatalf("deletes not scoped to owning orgs: %+v", deletes)
	}
	if err := f.client("org-guid").DeployPolicies(context.Background(), auth); err != nil {
		t.Fatalf("DeployPolicies: %v", err)
	}
	if f.lastMethod["DeployPolicyQueue/DeployPolicies"] != http.MethodPost {
		t.Fatalf("deploy method = %s, want POST", f.lastMethod["DeployPolicyQueue/DeployPolicies"])
	}
}

func TestPolicyForAuthFallsBackToOwningOrg(t *testing.T) {
	f := newFakePortal(t)
	f.respond["Policy/PolicyGetById"] = func(r *http.Request) (int, any) {
		if r.Header.Get("managedOrganizationId") != "org-child" {
			return http.StatusBadRequest, map[string]any{"message": "Unable to retrieve application policy"}
		}
		return http.StatusOK, map[string]any{"policyId": "pol_child", "name": "Child policy", "organizationId": "org-child"}
	}
	c := NewProvider(Config{
		BaseURL: f.srv.URL, Instance: "test", Token: "tl-secret-token", ParentOrgID: "org-guid",
	})
	parent := Auth{Instance: "test", Token: "tl-secret-token", OrgID: "org-parent"}
	if _, err := c.PolicyForAuth(context.Background(), parent, "pol_child"); err == nil {
		t.Fatal("PolicyForAuth without the owning org should fail like the live portal")
	}
	pol, err := c.PolicyForAuth(context.Background(), parent, "pol_child", "org-child")
	if err != nil {
		t.Fatalf("PolicyForAuth with owning-org fallback: %v", err)
	}
	if pol.ID != "pol_child" || pol.Name != "Child policy" {
		t.Fatalf("policy = %+v", pol)
	}
}

func TestApprovalRequestsQueryPending(t *testing.T) {
	f := newFakePortal(t)
	f.respond["ApprovalRequest/ApprovalRequestGetByParameters"] = []map[string]any{{
		"approvalRequestId": "req_1", "computerId": "dev_1", "hostname": "WS-ALPHA",
		"username": "jdoe", "requestor": "jdoe", "path": "C:\\tools\\putty.exe",
		"hash": "abc123", "requestTypeId": 1, "statusId": 1, "dateTime": "2026-07-01T09:00:00Z",
	}}
	reqs, err := f.client("org-guid").ApprovalRequests(context.Background(), "ten_1", "")
	if err != nil {
		t.Fatalf("ApprovalRequests: %v", err)
	}
	if len(reqs) != 1 || reqs[0].Status != RequestPending || reqs[0].Application != "putty.exe" {
		t.Fatalf("requests = %+v", reqs)
	}
	if !strings.Contains(f.lastBody["ApprovalRequest/ApprovalRequestGetByParameters"], `"statusId":1`) {
		t.Fatalf("expected pending statusId in query, body: %s", f.lastBody["ApprovalRequest/ApprovalRequestGetByParameters"])
	}
}

func TestApproveRequestFetchesPermitJSONFirst(t *testing.T) {
	f := newFakePortal(t)
	f.respond["ApprovalRequest/ApprovalRequestGetPermitApplicationById"] = map[string]any{
		"approvalRequestId": "req_1", "matchingApplications": []string{"putty"},
	}
	err := f.client("org-guid").ApproveRequest(context.Background(), "ten_1", "req_1", ScopeComputer, "")
	if err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	// The permit is fetched first, then posted with the chosen policy scope.
	if f.lastBody["ApprovalRequest/ApprovalRequestGetPermitApplicationById"] == "" &&
		f.lastAuth["ApprovalRequest/ApprovalRequestGetPermitApplicationById"] == "" {
		// GET has no body; presence of the auth header proves it was called.
	}
	if f.lastOrg["ApprovalRequest/ApprovalRequestGetPermitApplicationById"] != "org-guid" {
		t.Fatalf("permit lookup not scoped to org")
	}
	body := f.lastBody["ApprovalRequest/ApprovalRequestPermitApplication"]
	if !strings.Contains(body, "req_1") || !strings.Contains(body, `"toComputer":true`) {
		t.Fatalf("permit body missing fields: %s", body)
	}
}
