package server_test

import (
	"net/http"
	"testing"

	"github.com/rarity/rtm/internal/model"
)

func TestSharePointFolderPermissionsGuideInheritedRevokeToSource(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)
	target := `{"siteId":"site_1","driveId":"drive_site_1","itemId":"item_site_1_restricted","kind":"folder","path":"/Documents/Restricted"}`

	var permissions []model.SharePointScopePermission
	rec := call(t, h, http.MethodGet,
		"/api/v1/tenants/ten_1/sharepoint/permissions?siteId=site_1&driveId=drive_site_1&itemId=item_site_1_restricted&kind=folder&path=%2FDocuments%2FRestricted",
		admin, "", &permissions)
	if rec.Code != http.StatusOK || len(permissions) == 0 {
		t.Fatalf("permissions = %d %+v", rec.Code, permissions)
	}
	var inherited *model.SharePointScopePermission
	for i := range permissions {
		if permissions[i].Inherited {
			inherited = &permissions[i]
			break
		}
	}
	if inherited == nil || inherited.SourceTarget == nil {
		t.Fatalf("no inherited permission with source target: %+v", permissions)
	}

	body := `{"target":` + target + `,"principalId":"` + inherited.PrincipalID + `","operation":"revoke","role":"` + inherited.Role + `"}`
	var preview model.SharePointPermissionPreview
	rec = call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/sharepoint/permissions/preview", admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	if preview.EffectiveTarget == nil || preview.EffectiveTarget.Kind != "site" || preview.BreaksInheritance {
		t.Fatalf("preview did not guide to source: %+v", preview)
	}
	if len(preview.Warnings) == 0 || preview.ApprovalToken == "" {
		t.Fatalf("preview warnings/token = %+v", preview)
	}
}

func TestSharePointPermissionExecuteRecordsRevertibleChange(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)
	body := `{"target":{"siteId":"site_1","kind":"site","path":"/"},"principalId":"usr_3","principalUpn":"caleb.stone@contoso.com","operation":"grant","role":"Read"}`

	var preview model.SharePointPermissionPreview
	rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/sharepoint/permissions/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || preview.ApprovalToken == "" {
		t.Fatalf("preview = %d %+v", rec.Code, preview)
	}

	executeBody := `{"target":{"siteId":"site_1","kind":"site","path":"/"},"principalId":"usr_3","principalUpn":"caleb.stone@contoso.com","operation":"grant","role":"Read","approvalToken":"` + preview.ApprovalToken + `"}`
	var result model.SharePointPermissionResult
	rec = call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/sharepoint/permissions/execute", admin, executeBody, &result)
	if rec.Code != http.StatusOK || result.Status != "Completed" || result.ChangeID == "" {
		t.Fatalf("execute = %d %+v (%s)", rec.Code, result, rec.Body.String())
	}
	change, err := st.Change(t.Context(), result.ChangeID)
	if err != nil || !change.RevertEligible || change.RevertPayload == "" {
		t.Fatalf("change = %+v, %v", change, err)
	}

	rec = call(t, h, http.MethodPost,
		"/api/v1/tenants/ten_1/sharepoint/permissions/revert", admin,
		`{"changeId":"`+result.ChangeID+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revert = %d %s", rec.Code, rec.Body.String())
	}
	change, _ = st.Change(t.Context(), result.ChangeID)
	if change.Revert != "Reverted" {
		t.Fatalf("revert state = %q", change.Revert)
	}
}

func TestSharePointLocalInheritanceBreakIsExplicit(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)
	body := `{"target":{"siteId":"site_1","driveId":"drive_site_1","itemId":"item_site_1_restricted","kind":"folder","path":"/Documents/Restricted"},"principalId":"grp_1","operation":"revoke","role":"Read","breakInheritance":true,"copyAssignments":true}`

	var preview model.SharePointPermissionPreview
	rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/sharepoint/permissions/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || !preview.BreaksInheritance || preview.Risk != "High" {
		t.Fatalf("break preview = %d %+v", rec.Code, preview)
	}
}
