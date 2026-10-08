package server_test

import (
	"net/http"
	"testing"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/seed"
)

func TestOfflineInvestigationLifecycleAndDeletePermission(t *testing.T) {
	h, _ := newTestAPI(t)
	technician := login(t, h, techEmail, seed.DemoPassword).AccessToken
	var created model.OfflineInvestigation
	rec := call(t, h, http.MethodPost, "/api/v1/security/offline-investigations", technician,
		`{"name":"August sign-in review","tenantLabel":"Contoso"}`, &created)
	if rec.Code != http.StatusCreated || created.ID == "" || created.Status != "draft" {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}

	var detail model.OfflineInvestigationDetail
	rec = call(t, h, http.MethodGet, "/api/v1/security/offline-investigations/"+created.ID, technician, "", &detail)
	if rec.Code != http.StatusOK || detail.Name != created.Name || detail.Files == nil || detail.Timeline == nil {
		t.Fatalf("detail status=%d body=%s detail=%+v", rec.Code, rec.Body.String(), detail)
	}
	rec = call(t, h, http.MethodDelete, "/api/v1/security/offline-investigations/"+created.ID, technician, "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("technician delete status=%d body=%s", rec.Code, rec.Body.String())
	}

	admin := adminToken(t, h)
	rec = call(t, h, http.MethodDelete, "/api/v1/security/offline-investigations/"+created.ID, admin, "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("admin delete status=%d body=%s", rec.Code, rec.Body.String())
	}
}
