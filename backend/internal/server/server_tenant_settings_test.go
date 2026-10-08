package server_test

import (
	"net/http"
	"testing"

	"github.com/rarity/rtm/internal/model"
)

func TestTenantSettingsAdminCanEditWithoutReplacingSecrets(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	var updated struct {
		Tenant model.Tenant `json:"tenant"`
	}
	body := `{"name":"Contoso Managed","sharePointAdminUrl":"https://contoso-admin.sharepoint.com"}`
	rec := call(t, h, http.MethodPut, "/api/v1/tenants/ten_1", admin, body, &updated)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d body=%s", rec.Code, rec.Body.String())
	}
	if updated.Tenant.Name != "Contoso Managed" || !updated.Tenant.Connections.SharePoint {
		t.Fatalf("updated tenant = %+v", updated.Tenant)
	}
	creds, _ := st.TenantCreds(t.Context(), "ten_1")
	if creds.SharePointAdminURL != "https://contoso-admin.sharepoint.com" {
		t.Fatalf("creds = %+v", creds)
	}
}

func TestTenantSettingsRejectsTechnicianAndUnsafeClientIDChange(t *testing.T) {
	h, _ := newTestAPI(t)
	tech := login(t, h, techEmail, "RtmDemo!2026").AccessToken
	if rec := call(t, h, http.MethodPut, "/api/v1/tenants/ten_1", tech, `{"name":"Nope"}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("technician update status = %d", rec.Code)
	}
	admin := adminToken(t, h)
	if rec := call(t, h, http.MethodPut, "/api/v1/tenants/ten_1", admin, `{"clientId":"new-app"}`, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unsafe client id status = %d body=%s", rec.Code, rec.Body.String())
	}
}
