package server_test

// Hybrid AD / Entra source-of-authority tests: the tenant identity summary,
// the write gate that refuses on-prem-mastered changes (fail closed + audited),
// and the rule that cloud-authoritative actions still work on synced users.
// The sample Contoso tenant is "mixed": usr_3/usr_10 and grp_4/grp_8 are
// synced from on-prem AD.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
)

func TestHybridIdentitySummary(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)

	var tn model.Tenant
	rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_1", admin, "", &tn)
	if rec.Code != http.StatusOK {
		t.Fatalf("get tenant = %d %s", rec.Code, rec.Body.String())
	}
	if tn.IdentityMode != model.IdentityMixed {
		t.Fatalf("identityMode = %q, want mixed", tn.IdentityMode)
	}
	if tn.SyncedUsers != 2 || tn.CloudUsers != 10 || tn.SyncedGroups != 2 || tn.CloudGroups != 7 {
		t.Fatalf("counts = synced %d/%d cloud %d/%d (users/groups)", tn.SyncedUsers, tn.SyncedGroups, tn.CloudUsers, tn.CloudGroups)
	}
}

func TestHybridBlocksSignInOnSyncedUser(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	// block_signin on usr_3 (synced from on-prem AD) is refused, not queued.
	body := `{"action":"block_signin","tenantId":"ten_1","userIds":["usr_3"]}`
	var preview model.WhatIfPreview
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	if preview.TargetCount != 0 || len(preview.Blocked) != 1 {
		t.Fatalf("preview = %+v", preview)
	}
	b := preview.Blocked[0]
	if b.Object != "Caleb Stone" || !strings.Contains(b.Reason, "on-prem") || b.Resolution == "" {
		t.Fatalf("blocked = %+v", b)
	}
	// The preview should point the technician at the cloud alternative.
	warned := false
	for _, w := range preview.Warnings {
		if strings.Contains(w, "revoke their sessions") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("block_signin on synced user should suggest revoking sessions: %v", preview.Warnings)
	}

	// Execute fails closed (nothing executable) and leaves a Denied audit entry.
	rec = call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, body, nil)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != httpx.CodeValidationFailed {
		t.Fatalf("execute of blocked = %d %s", rec.Code, rec.Body.String())
	}
	audit, _ := st.Audit(t.Context())
	blockedAudited := false
	for _, a := range audit {
		if a.Action == "changes.blocked" && a.Result == "Denied" {
			blockedAudited = true
		}
	}
	if !blockedAudited {
		t.Fatalf("blocked write was not audited: %+v", audit)
	}
}

func TestHybridBlocksSyncedGroupMembership(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)

	// grp_4 (IT Admins) is synced from on-prem AD → its membership is mastered
	// there, so adding even a cloud user (usr_1) is blocked.
	body := `{"action":"add_to_group","tenantId":"ten_1","groupId":"grp_4","userIds":["usr_1"]}`
	var preview model.WhatIfPreview
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	if preview.TargetCount != 0 || len(preview.Blocked) != 1 {
		t.Fatalf("preview = %+v", preview)
	}
	if !strings.Contains(preview.Blocked[0].Reason, "IT Admins") {
		t.Fatalf("blocked reason should name the synced group: %+v", preview.Blocked[0])
	}
}

func TestHybridAllowsCloudActionsOnSyncedUser(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	// Licensing is cloud-authoritative: assigning a license to a synced user is
	// allowed and runs the real pipeline.
	body := `{"action":"assign_license","tenantId":"ten_1","skuId":"sku-SPE_E5","userIds":["usr_3"]}`
	var preview model.WhatIfPreview
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || preview.TargetCount != 1 || len(preview.Blocked) != 0 {
		t.Fatalf("license preview on synced user = %d %+v", rec.Code, preview)
	}
	var ref model.JobRef
	rec = call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, body, &ref)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("execute = %d %s", rec.Code, rec.Body.String())
	}
	if job := waitForJob(t, st, ref.JobID); job.Status != "Completed" {
		t.Fatalf("license job on synced user = %+v", job)
	}

	// Cloud group membership is allowed for a synced user: grp_1 (Sales — All
	// Staff) is a cloud group, so adding synced usr_3 is a real target.
	cloudGroup := `{"action":"add_to_group","tenantId":"ten_1","groupId":"grp_1","userIds":["usr_3"]}`
	var p2 model.WhatIfPreview
	call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, cloudGroup, &p2)
	if p2.TargetCount != 1 || len(p2.Blocked) != 0 {
		t.Fatalf("synced user into cloud group should be allowed: %+v", p2)
	}
}
