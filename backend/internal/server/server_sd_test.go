package server_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

// startInvestigation kicks off a scan for the subject and polls until it
// finishes (the scan runs in a background goroutine).
func startInvestigation(t *testing.T, h http.Handler, token, tenantID, subjectID string) model.ShareInvestigation {
	t.Helper()
	var inv model.ShareInvestigation
	rec := call(t, h, http.MethodPost, "/api/v1/tenants/"+tenantID+"/share-detective/investigations", token,
		fmt.Sprintf(`{"subjectId":%q}`, subjectID), &inv)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start investigation: status %d (%s)", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for inv.Status == "running" {
		if time.Now().After(deadline) {
			t.Fatalf("investigation did not finish: %+v", inv)
		}
		time.Sleep(20 * time.Millisecond)
		if rec := call(t, h, http.MethodGet, "/api/v1/tenants/"+tenantID+"/share-detective/investigations/"+inv.ID, token, "", &inv); rec.Code != http.StatusOK {
			t.Fatalf("poll investigation: status %d", rec.Code)
		}
	}
	return inv
}

func TestShareDetectiveInvestigationLifecycle(t *testing.T) {
	h, st := newTestAPI(t)
	token := login(t, h, techEmail, "RtmDemo!2026").AccessToken

	// Investigate the guest, Ivan Petrov — the classic offboarding case.
	inv := startInvestigation(t, h, token, "ten_1", "usr_9")
	if inv.Status != "completed" {
		t.Fatalf("status = %q (%s)", inv.Status, inv.Error)
	}
	if inv.Subject.Type != "Guest" || inv.Subject.UPN != "ivan.petrov@partner.com" {
		t.Fatalf("subject = %+v", inv.Subject)
	}
	// Coverage is honest: all six seeded sites discovered and scanned.
	if inv.Summary.SitesDiscovered != 6 || inv.Summary.SitesScanned != 6 || inv.Summary.SitesSkipped != 0 {
		t.Fatalf("summary = %+v", inv.Summary)
	}
	if len(inv.Coverage) != 6 {
		t.Fatalf("coverage rows = %d", len(inv.Coverage))
	}

	// The seeded data gives Ivan: a direct site grant on Project Falcon, a
	// direct file grant, a direct folder grant, group-based access via the
	// Project Falcon group, and broad links he may be using.
	byClass := map[string]int{}
	revocable := 0
	for _, f := range inv.Findings {
		byClass[f.Classification]++
		if f.Revocable {
			revocable++
			if f.PermissionID == "" {
				t.Fatalf("revocable finding without a permission id: %+v", f)
			}
		}
	}
	if byClass[model.ShareDirectUser] < 3 {
		t.Fatalf("direct findings = %+v", byClass)
	}
	if byClass[model.ShareGroupBased] == 0 || byClass[model.ShareBroadLink] == 0 {
		t.Fatalf("classification spread = %+v", byClass)
	}
	if inv.Summary.Revocable != revocable || revocable == 0 {
		t.Fatalf("revocable = %d, summary %+v", revocable, inv.Summary)
	}

	// Starting a scan is audited.
	audit, _ := st.Audit(t.Context())
	found := false
	for _, e := range audit {
		if e.Action == "share_detective.start" {
			found = true
		}
	}
	if !found {
		t.Fatal("investigation start was not audited")
	}
}

func TestShareDetectiveUnknownSubject(t *testing.T) {
	h, _ := newTestAPI(t)
	token := login(t, h, techEmail, "RtmDemo!2026").AccessToken
	rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/share-detective/investigations", token, `{"subjectId":"usr_nope"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown subject: status %d", rec.Code)
	}
}

// Investigations are tenant-scoped: another tenant's URL cannot read them.
func TestShareDetectiveTenantIsolation(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)
	tech := login(t, h, techEmail, "RtmDemo!2026").AccessToken

	var created model.Tenant
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants", admin,
		`{"name":"Fabrikam","domain":"fabrikam.com","microsoftTenantId":"11111111-1111-1111-1111-111111111111"}`, &created); rec.Code != http.StatusCreated {
		t.Fatalf("create tenant: status %d", rec.Code)
	}

	inv := startInvestigation(t, h, tech, "ten_1", "usr_9")
	rec := call(t, h, http.MethodGet, "/api/v1/tenants/"+created.ID+"/share-detective/investigations/"+inv.ID, tech, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant read: status %d", rec.Code)
	}

	// And the other tenant's list doesn't include it.
	var list []model.ShareInvestigation
	call(t, h, http.MethodGet, "/api/v1/tenants/"+created.ID+"/share-detective/investigations", tech, "", &list)
	if len(list) != 0 {
		t.Fatalf("cross-tenant list = %+v", list)
	}
}

func TestShareDetectiveRevokeRequiresAdmin(t *testing.T) {
	h, _ := newTestAPI(t)
	tech := login(t, h, techEmail, "RtmDemo!2026").AccessToken
	inv := startInvestigation(t, h, tech, "ten_1", "usr_9")

	rec := call(t, h, http.MethodPost,
		"/api/v1/tenants/ten_1/share-detective/investigations/"+inv.ID+"/revoke-preview", tech, `{"findingIds":["f_1"]}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("technician revoke preview: status %d", rec.Code)
	}
}

func TestShareDetectiveRevokePipeline(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)
	inv := startInvestigation(t, h, admin, "ten_1", "usr_9")

	// Select every finding: revocable ones become delete_permission rows, the
	// rest are manual review.
	ids := make([]string, 0, len(inv.Findings))
	wantRevocable := 0
	for _, f := range inv.Findings {
		ids = append(ids, f.ID)
		if f.Revocable {
			wantRevocable++
		}
	}
	body, _ := json.Marshal(map[string]any{"findingIds": ids})

	var preview model.ShareRevokePreview
	rec := call(t, h, http.MethodPost,
		"/api/v1/tenants/ten_1/share-detective/investigations/"+inv.ID+"/revoke-preview", admin, string(body), &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke preview: status %d (%s)", rec.Code, rec.Body.String())
	}
	if preview.RevocableCount != wantRevocable || len(preview.Actions) != len(ids) {
		t.Fatalf("preview = %+v", preview)
	}
	manual := 0
	for _, a := range preview.Actions {
		if a.Action == "manual_review" {
			manual++
		}
	}
	if manual != len(ids)-wantRevocable {
		t.Fatalf("manual rows = %d", manual)
	}

	// Execute (test env: the approval gate is production-only, matching the
	// existing change pipeline tests).
	var result model.ShareRevokeResult
	rec = call(t, h, http.MethodPost,
		"/api/v1/tenants/ten_1/share-detective/investigations/"+inv.ID+"/revoke", admin, string(body), &result)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: status %d (%s)", rec.Code, rec.Body.String())
	}
	if result.Status != "Completed" || len(result.Revoked) != wantRevocable || len(result.Failed) != 0 {
		t.Fatalf("result = %+v", result)
	}

	// The revoke is audited and recorded in change history (not revertible).
	audit, _ := st.Audit(t.Context())
	audited := false
	for _, e := range audit {
		if e.Action == "share_detective.revoke" && e.Result == "Success" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("revoke was not audited")
	}
	changes, _ := st.Changes(t.Context())
	recorded := false
	for _, c := range changes {
		if c.Action == "Revoke shared access" && c.Target == "ivan.petrov@partner.com" && c.Revert == "Not supported" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatalf("revoke missing from change history: %+v", changes)
	}

	// A fresh scan confirms the grants are really gone (sample-mode writes
	// persist, like the rest of the demo).
	fresh := startInvestigation(t, h, admin, "ten_1", "usr_9")
	if fresh.Summary.Revocable != 0 {
		t.Fatalf("fresh scan still finds revocable grants: %+v", fresh.Findings)
	}
}
