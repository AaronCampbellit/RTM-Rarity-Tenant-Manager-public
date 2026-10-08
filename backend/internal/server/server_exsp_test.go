package server_test

// Exchange + SharePoint feature tests: the read endpoints (mailbox settings,
// mailbox permissions, site permissions) and the write actions through the
// full preview → execute → change record → revert pipeline, including the
// sample provider's persisted state so reads reflect executed writes.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/seed"
)

func TestExchangeSharePointReads(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)

	var ms model.MailboxSettings
	rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/exchange/mailboxes/mbx_4/settings", admin, "", &ms)
	if rec.Code != http.StatusOK || !ms.AutoReply || ms.AutoReplyMessage == "" {
		t.Fatalf("mbx_4 settings = %d %+v", rec.Code, ms)
	}
	rec = call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/exchange/mailboxes/mbx_7/settings", admin, "", &ms)
	if rec.Code != http.StatusOK || ms.ForwardingTo != "it-archive@contoso.com" {
		t.Fatalf("mbx_7 settings = %d %+v", rec.Code, ms)
	}

	var perms model.MailboxPermissionFeed
	rec = call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/exchange/mailboxes/mbx_5/permissions", admin, "", &perms)
	if rec.Code != http.StatusOK || len(perms.Permissions) != 3 || len(perms.Coverage) != 3 {
		t.Fatalf("mbx_5 permissions = %d %+v", rec.Code, perms)
	}
	rec = call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/exchange/mailboxes/mbx_3/permissions", admin, "", &perms)
	if rec.Code != http.StatusOK || len(perms.Permissions) != 0 || len(perms.Coverage) != 3 {
		t.Fatalf("mbx_3 permissions = %d %+v, want empty list", rec.Code, perms)
	}

	var sp []model.SitePermission
	rec = call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/sharepoint/sites/site_3/permissions", admin, "", &sp)
	if rec.Code != http.StatusOK || len(sp) != 3 {
		t.Fatalf("site_3 permissions = %d %+v", rec.Code, sp)
	}
	external := false
	for _, p := range sp {
		if p.Type == "External" {
			external = true
		}
	}
	if !external {
		t.Fatalf("site_3 should list an external user: %+v", sp)
	}
}

func TestForwardingPipelineWithRevert(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	body := `{"action":"set_forwarding","tenantId":"ten_1","mailboxIds":["mbx_1","mbx_3"],"forwardTo":"archive@contoso.com"}`

	var preview model.WhatIfPreview
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || preview.TargetCount != 2 {
		t.Fatalf("preview = %d %+v", rec.Code, preview)
	}
	if preview.RequiredPermission != "MailboxSettings.ReadWrite" {
		t.Fatalf("required permission = %q", preview.RequiredPermission)
	}
	warned := false
	for _, w := range preview.Warnings {
		if strings.Contains(w, "exfiltrate") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("forwarding preview must warn about exfiltration: %v", preview.Warnings)
	}

	var ref model.JobRef
	rec = call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, body, &ref)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("execute = %d %s", rec.Code, rec.Body.String())
	}
	if job := waitForJob(t, st, ref.JobID); job.Status != "Completed" {
		t.Fatalf("job = %+v", job)
	}

	// The write persisted: the settings read now shows the forwarding target.
	var ms model.MailboxSettings
	call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/exchange/mailboxes/mbx_1/settings", admin, "", &ms)
	if ms.ForwardingTo != "archive@contoso.com" {
		t.Fatalf("mbx_1 forwarding after execute = %q", ms.ForwardingTo)
	}

	changes, _ := st.Changes(t.Context())
	if len(changes) != 1 || changes[0].Revert != "Available" || changes[0].Target != "2 mailboxes" {
		t.Fatalf("change = %+v", changes)
	}

	// Revert clears the forwarding rule on exactly the succeeded mailboxes.
	var revRef model.JobRef
	rec = call(t, h, http.MethodPost, "/api/v1/changes/revert", admin, fmt.Sprintf(`{"id":%q}`, changes[0].ID), &revRef)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("revert = %d %s", rec.Code, rec.Body.String())
	}
	if job := waitForJob(t, st, revRef.JobID); job.Status != "Completed" {
		t.Fatalf("revert job = %+v", job)
	}
	call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/exchange/mailboxes/mbx_1/settings", admin, "", &ms)
	if ms.ForwardingTo != "" {
		t.Fatalf("mbx_1 forwarding after revert = %q, want cleared", ms.ForwardingTo)
	}
	orig, _ := st.Change(t.Context(), changes[0].ID)
	if orig.Revert != "Reverted" {
		t.Fatalf("original revert state = %q", orig.Revert)
	}
}

func TestMailboxPermissionGrantAndRevert(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	body := `{"action":"grant_mailbox_permission","tenantId":"ten_1","mailboxIds":["mbx_1"],"delegateId":"usr_3","permission":"Full Access"}`

	var preview model.WhatIfPreview
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || preview.TargetCount != 1 || preview.Risk != "Medium" {
		t.Fatalf("preview = %d %+v", rec.Code, preview)
	}
	if !strings.Contains(preview.Action, "Caleb Stone") {
		t.Fatalf("preview title should name the delegate: %q", preview.Action)
	}

	var ref model.JobRef
	call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, body, &ref)
	if job := waitForJob(t, st, ref.JobID); job.Status != "Completed" {
		t.Fatalf("job = %+v", job)
	}

	var perms model.MailboxPermissionFeed
	call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/exchange/mailboxes/mbx_1/permissions", admin, "", &perms)
	found := false
	for _, p := range perms.Permissions {
		if p.Delegate == "Caleb Stone" && p.Permission == "Full Access" {
			found = true
		}
	}
	if !found {
		t.Fatalf("granted permission missing: %+v", perms)
	}

	changes, _ := st.Changes(t.Context())
	var revRef model.JobRef
	rec = call(t, h, http.MethodPost, "/api/v1/changes/revert", admin, fmt.Sprintf(`{"id":%q}`, changes[0].ID), &revRef)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("revert = %d %s", rec.Code, rec.Body.String())
	}
	if job := waitForJob(t, st, revRef.JobID); job.Status != "Completed" {
		t.Fatalf("revert job = %+v", job)
	}
	call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/exchange/mailboxes/mbx_1/permissions", admin, "", &perms)
	for _, p := range perms.Permissions {
		if p.Delegate == "Caleb Stone" && p.Permission == "Full Access" {
			t.Fatalf("permission still present after revert: %+v", perms)
		}
	}
}

func TestSiteSharingPipeline(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	// site_1 is already Internal → skipped; site_3 is External → real target.
	body := `{"action":"set_site_sharing","tenantId":"ten_1","siteIds":["site_1","site_3"],"sharingLevel":"Internal"}`
	var preview model.WhatIfPreview
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || preview.TargetCount != 1 || len(preview.Skipped) != 1 {
		t.Fatalf("preview = %d %+v", rec.Code, preview)
	}
	if preview.Skipped[0].Reason != "Already at this sharing level" {
		t.Fatalf("skip reason = %q", preview.Skipped[0].Reason)
	}

	var ref model.JobRef
	call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, body, &ref)
	if job := waitForJob(t, st, ref.JobID); job.Status != "Completed" {
		t.Fatalf("job = %+v", job)
	}

	// The sites list reflects the new level.
	var sites []model.Site
	call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/sharepoint/sites", admin, "", &sites)
	for _, s := range sites {
		if s.ID == "site_3" && s.ExternalSharing != "Internal" {
			t.Fatalf("site_3 sharing = %q, want Internal", s.ExternalSharing)
		}
	}

	// Sharing changes aren't revertible (no prior-level snapshot).
	changes, _ := st.Changes(t.Context())
	if changes[0].Revert == "Available" {
		t.Fatalf("set_site_sharing must not offer revert: %+v", changes[0])
	}
	rec = call(t, h, http.MethodPost, "/api/v1/changes/revert", admin, fmt.Sprintf(`{"id":%q}`, changes[0].ID), nil)
	if rec.Code != http.StatusConflict || errCode(t, rec) != httpx.CodeRevertConflict {
		t.Fatalf("revert of sharing change = %d", rec.Code)
	}
}

func TestSiteAccessGrantPipeline(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	body := `{"action":"grant_site_access","tenantId":"ten_1","siteId":"site_2","role":"Read","userIds":["usr_4"]}`
	var preview model.WhatIfPreview
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || preview.TargetCount != 1 {
		t.Fatalf("preview = %d %+v", rec.Code, preview)
	}
	if preview.RequiredPermission != "Sites.FullControl.All" {
		t.Fatalf("required permission = %q", preview.RequiredPermission)
	}

	var ref model.JobRef
	call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, body, &ref)
	if job := waitForJob(t, st, ref.JobID); job.Status != "Completed" {
		t.Fatalf("job = %+v", job)
	}

	var perms []model.SitePermission
	call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/sharepoint/sites/site_2/permissions", admin, "", &perms)
	found := false
	for _, p := range perms {
		if p.Principal == "Dana White" && p.Role == "Read" && p.Source == "Direct" {
			found = true
		}
	}
	if !found {
		t.Fatalf("granted site access missing: %+v", perms)
	}

	changes, _ := st.Changes(t.Context())
	if changes[0].Target != "Company Intranet" || changes[0].Revert != "Available" {
		t.Fatalf("change = %+v", changes[0])
	}
}

func TestExchangeSharePointValidation(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)

	bad := []string{
		// forwarding needs a plausible address
		`{"action":"set_forwarding","tenantId":"ten_1","mailboxIds":["mbx_1"],"forwardTo":"not-an-email"}`,
		// auto-reply needs a message
		`{"action":"enable_auto_reply","tenantId":"ten_1","mailboxIds":["mbx_1"],"autoReplyMessage":"  "}`,
		// permission enum enforced
		`{"action":"grant_mailbox_permission","tenantId":"ten_1","mailboxIds":["mbx_1"],"delegateId":"usr_3","permission":"Owner"}`,
		// unknown delegate refused
		`{"action":"grant_mailbox_permission","tenantId":"ten_1","mailboxIds":["mbx_1"],"delegateId":"usr_999","permission":"Send As"}`,
		// site access needs a known site + valid role
		`{"action":"grant_site_access","tenantId":"ten_1","role":"Read","userIds":["usr_4"]}`,
		`{"action":"grant_site_access","tenantId":"ten_1","siteId":"site_2","role":"Admin","userIds":["usr_4"]}`,
		// sharing level enum enforced; target list required
		`{"action":"set_site_sharing","tenantId":"ten_1","siteIds":["site_1"],"sharingLevel":"Everyone"}`,
		`{"action":"set_site_sharing","tenantId":"ten_1","sharingLevel":"Internal"}`,
		`{"action":"set_forwarding","tenantId":"ten_1","forwardTo":"a@b.com"}`,
	}
	for _, body := range bad {
		rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("preview %s = %d, want 400", body, rec.Code)
		}
	}

	// Technicians without admin can't run Exchange/SharePoint writes either.
	tech := login(t, h, techEmail, seed.DemoPassword)
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", tech.AccessToken,
		`{"action":"set_forwarding","tenantId":"ten_1","mailboxIds":["mbx_1"],"forwardTo":"a@b.com"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin exchange preview = %d, want 403", rec.Code)
	}
}

// TestTenantServiceCredentials covers the per-tenant Exchange Online and
// SharePoint admin app registrations: validation, write-only storage, the
// connections flags surfaced in the API, and the fallback to the Graph app.
func TestTenantServiceCredentials(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	// Validation: each service credential is a both-or-neither pair.
	bad := []string{
		`{"name":"A","domain":"a.com","microsoftTenantId":"g","exchangeClientId":"only-id"}`,
		`{"name":"A","domain":"a.com","microsoftTenantId":"g","sharePointClientId":"only-id"}`,
		// SharePoint app without an admin URL.
		`{"name":"A","domain":"a.com","microsoftTenantId":"g","sharePointClientId":"sp-id","sharePointClientSecret":"sp-sec"}`,
	}
	for _, body := range bad {
		if rec := call(t, h, http.MethodPost, "/api/v1/tenants", admin, body, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("create %s = %d, want 400", body, rec.Code)
		}
	}

	// Full setup: dedicated Graph, Exchange, and SharePoint apps.
	full := `{"name":"Fabrikam","domain":"fabrikam.com","microsoftTenantId":"dir-guid",
		"clientId":"graph-id","clientSecret":"graph-sec",
		"exchangeClientId":"exo-id","exchangeClientSecret":"exo-sec",
		"sharePointClientId":"sp-id","sharePointClientSecret":"sp-sec",
		"sharePointAdminUrl":"https://fabrikam-admin.sharepoint.com"}`
	var created model.Tenant
	rec := call(t, h, http.MethodPost, "/api/v1/tenants", admin, full, &created)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	if !created.Connections.Graph || !created.Connections.Exchange || !created.Connections.SharePoint {
		t.Fatalf("connections = %+v, want all true", created.Connections)
	}
	// No secret material may appear in the response.
	for _, secret := range []string{"graph-sec", "exo-sec", "sp-sec", "exchangeClientSecret", "sharePointClientSecret"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("secret material %q leaked into response", secret)
		}
	}
	// The stored creds are available to the integration layer verbatim.
	creds, err := st.TenantCreds(t.Context(), created.ID)
	if err != nil || creds.ExchangeClientID != "exo-id" || creds.SharePointClientID != "sp-id" ||
		creds.SharePointAdminURL != "https://fabrikam-admin.sharepoint.com" {
		t.Fatalf("stored creds = %+v, %v", creds, err)
	}

	// Graph-only setup: Exchange/SharePoint inherit the Graph app (connections
	// flags false, but Resolved() fills them from the Graph credentials).
	graphOnly := `{"name":"Northwind","domain":"northwind.com","microsoftTenantId":"nw-guid","clientId":"nw-graph","clientSecret":"nw-sec"}`
	var nw model.Tenant
	call(t, h, http.MethodPost, "/api/v1/tenants", admin, graphOnly, &nw)
	if nw.Connections.Exchange || nw.Connections.SharePoint {
		t.Fatalf("graph-only connections = %+v, want exchange/sharepoint false", nw.Connections)
	}
	nwCreds, _ := st.TenantCreds(t.Context(), nw.ID)
	resolved := nwCreds.Resolved()
	if resolved.ExchangeClientID != "nw-graph" || resolved.SharePointClientSecret != "nw-sec" {
		t.Fatalf("fallback resolution = %+v, want Graph creds", resolved)
	}

	// The seeded example tenant has no dedicated apps stored.
	var contoso model.Tenant
	call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/", admin, "", &contoso)
	if contoso.Connections.Graph || contoso.Connections.Exchange || contoso.Connections.SharePoint {
		t.Fatalf("seeded tenant connections = %+v, want all false", contoso.Connections)
	}
}
