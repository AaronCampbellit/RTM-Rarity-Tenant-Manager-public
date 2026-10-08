package server_test

import (
	"net/http"
	"testing"

	"github.com/rarity/rtm/internal/model"
)

// ---- Preflight ----

func TestPreflightSampleMode(t *testing.T) {
	h, st := newTestAPI(t)
	token := login(t, h, techEmail, "RtmDemo!2026").AccessToken

	var pf model.Preflight
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/preflight", token, "", &pf); rec.Code != http.StatusOK {
		t.Fatalf("preflight: status %d", rec.Code)
	}
	if pf.Mode != "sample" || len(pf.Checks) == 0 {
		t.Fatalf("preflight = %+v", pf)
	}
	categories := map[string]bool{}
	sample, unchecked := 0, 0
	for _, c := range pf.Checks {
		if c.Category == "" {
			t.Fatalf("preflight row has no RTM category: %+v", c)
		}
		categories[c.Category] = true
		switch c.Status {
		case "sample":
			sample++
		case "unchecked":
			if c.Permission == "" {
				t.Fatalf("unchecked row without required permission: %+v", c)
			}
			unchecked++
		}
	}
	if sample == 0 || unchecked != 0 {
		t.Fatalf("expected only honest sample rows and no unchecked rows, got sample=%d unchecked=%d", sample, unchecked)
	}
	for _, category := range []string{"Security Operations", "SharePoint", "Exchange", "Directory & Identity", "Licensing"} {
		if !categories[category] {
			t.Fatalf("preflight missing category %q: %+v", category, categories)
		}
	}

	var cached model.Preflight
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/preflight", token, "", &cached); rec.Code != http.StatusOK {
		t.Fatalf("cached preflight: status %d", rec.Code)
	}
	if cached.RanAt != pf.RanAt || len(cached.Checks) != len(pf.Checks) {
		t.Fatalf("cached preflight = %+v, want ranAt %s and %d checks", cached, pf.RanAt, len(pf.Checks))
	}

	// The run is audited.
	audit, _ := st.Audit(t.Context())
	found := false
	for _, e := range audit {
		if e.Action == "tenant.preflight" {
			found = true
		}
	}
	if !found {
		t.Fatal("preflight run was not audited")
	}
}

func TestPreflightGetBeforeFirstRunIsNotFound(t *testing.T) {
	h, _ := newTestAPI(t)
	token := login(t, h, techEmail, "RtmDemo!2026").AccessToken
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/preflight", token, "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cached preflight before run = %d, want 404", rec.Code)
	}
}

func TestPreflightUnknownTenant(t *testing.T) {
	h, _ := newTestAPI(t)
	token := login(t, h, techEmail, "RtmDemo!2026").AccessToken
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants/nope/preflight", token, "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant: status %d", rec.Code)
	}
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants/nope/preflight", token, "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant cached preflight: status %d", rec.Code)
	}
}

func TestPreflightIncludesSharePointPermissionBundle(t *testing.T) {
	h, _ := newTestAPI(t)
	token := login(t, h, techEmail, "RtmDemo!2026").AccessToken
	var pf model.Preflight
	call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/preflight", token, "", &pf)

	required := []struct{ permission, resource string }{
		{"GroupMember.Read.All", "Microsoft Graph"},
		{"Sites.ReadWrite.All", "Microsoft Graph"},
		{"Sites.FullControl.All", "Microsoft Graph"},
		{"Sites.FullControl.All", "SharePoint Online"},
	}
	for _, requirement := range required {
		found := false
		for _, check := range pf.Checks {
			if check.Permission == requirement.permission && check.Resource == requirement.resource {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("preflight missing %s on %s: %+v", requirement.permission, requirement.resource, pf.Checks)
		}
	}
}

// ---- Raw user view (User Blowout) ----

func TestUserRawViewAndAudit(t *testing.T) {
	h, st := newTestAPI(t)
	token := login(t, h, techEmail, "RtmDemo!2026").AccessToken

	var raw model.UserRaw
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/users/usr_3/raw", token, "", &raw); rec.Code != http.StatusOK {
		t.Fatalf("raw view: status %d", rec.Code)
	}
	if raw.ID != "usr_3" || raw.Attributes["displayName"] != "Caleb Stone" {
		t.Fatalf("raw = %+v", raw)
	}
	// Caleb is synced from on-prem AD — the raw view must expose the on-prem
	// facet including extension attributes.
	if _, ok := raw.Attributes["onPremisesExtensionAttributes"]; !ok {
		t.Fatalf("expected on-prem extension attributes, got %v", raw.Attributes)
	}

	audit, _ := st.Audit(t.Context())
	found := false
	for _, e := range audit {
		if e.Action == "user.raw_view" && e.Resource == "usr_3" {
			found = true
		}
	}
	if !found {
		t.Fatal("raw user view was not audited")
	}
}

func TestUserRawUnknownUser(t *testing.T) {
	h, _ := newTestAPI(t)
	token := login(t, h, techEmail, "RtmDemo!2026").AccessToken
	rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/users/usr_missing/raw", token, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown user: status %d (%s)", rec.Code, rec.Body.String())
	}
}

// ---- Entra readiness global reports (through the API) ----

func TestEntraReadinessReportsServed(t *testing.T) {
	h, _ := newTestAPI(t)
	token := login(t, h, techEmail, "RtmDemo!2026").AccessToken

	for _, reportType := range []string{"license-readiness", "mfa-gaps", "stale-guests", "privileged-roles", "ca-exclusions", "app-credentials"} {
		var rep model.GlobalReport
		if rec := call(t, h, http.MethodGet, "/api/v1/global-reports/"+reportType, token, "", &rep); rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", reportType, rec.Code)
		}
		if len(rep.Columns) == 0 || rep.Columns[0] != "Tenant" {
			t.Fatalf("%s columns = %v", reportType, rep.Columns)
		}
		// The seeded Contoso tenant contributes rows to every readiness report.
		if len(rep.Rows) == 0 {
			t.Fatalf("%s: no rows from the seeded tenant", reportType)
		}
		if rep.Rows[0][0].Text != "Contoso Ltd" {
			t.Fatalf("%s first cell = %+v", reportType, rep.Rows[0][0])
		}
	}
}
