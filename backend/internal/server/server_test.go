package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/config"
	"github.com/rarity/rtm/internal/exchangebootstrap"
	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/jobs"
	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/offlineinvestigations"
	"github.com/rarity/rtm/internal/seed"
	"github.com/rarity/rtm/internal/server"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
)

const (
	techEmail = "aisha.rivera@rarity.io" // seeded technician: ten_1
	// adminPassword is what tests rotate the default admin credential to.
	adminPassword = "test-rotated-password"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

// newTestAPI builds the full HTTP stack the way cmd/api does in memory mode:
// in-memory store, sample Graph provider, real auth, inline job executor (the
// real pipeline, run in-process).
func newTestAPI(t *testing.T) (http.Handler, *store.Mem) {
	t.Helper()
	h, st := newTestAPIWithGraph(t, nil)
	return h, st
}

// newTestAPIWithGraph lets a test substitute the Graph provider (e.g. one that
// fails writes). nil uses the sample provider.
func newTestAPIWithGraph(t *testing.T, gp graph.Provider) (http.Handler, *store.Mem) {
	t.Helper()
	return newTestAPIWithEnv(t, gp, "test")
}

func newTestAPIWithEnv(t *testing.T, gp graph.Provider, env string) (http.Handler, *store.Mem) {
	t.Helper()
	cfg := &config.Config{Env: env, CORSOrigin: "http://localhost:5173"}
	log := discardLogger()
	st := store.NewMem()
	if gp == nil {
		gp = graph.NewProvider(graph.Config{}, log, nil)
	}
	au := auth.NewService(st, []byte("test-signing-key"), log)
	tlp := threatlocker.NewProvider(threatlocker.Config{})
	audit := m365audit.NewService(st, m365audit.NewProvider(m365audit.Config{}, log, nil), log)
	offline := offlineinvestigations.New(st, log)
	enq := jobs.Inline{Store: st, Graph: gp, ThreatLocker: tlp, Log: log, Audit: audit, Offline: offline}
	api := server.New(cfg, log, st, gp, tlp, au, enq)
	api.SetOfflineInvestigationService(offline)
	return api.Handler(), st
}

// call performs a request against the handler and decodes the JSON body into
// out (when non-nil), returning the recorder for header/status checks.
func call(t *testing.T, h http.Handler, method, path, token, body string, out any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if out != nil {
		if err := json.NewDecoder(rec.Body).Decode(out); err != nil {
			t.Fatalf("%s %s: decoding body: %v", method, path, err)
		}
	}
	return rec
}

type loginResponse struct {
	AccessToken  string         `json:"accessToken"`
	RefreshToken string         `json:"refreshToken"`
	User         auth.Principal `json:"user"`
}

func login(t *testing.T, h http.Handler, email, password string) loginResponse {
	t.Helper()
	var lr loginResponse
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	rec := call(t, h, http.MethodPost, "/api/v1/auth/login", "", body, &lr)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s: status %d", email, rec.Code)
	}
	return lr
}

// adminToken bootstraps the default admin the way a real operator would:
// first login with the default credentials, then the forced password rotation.
func adminToken(t *testing.T, h http.Handler) string {
	t.Helper()
	lr := login(t, h, seed.DefaultAdminEmail, seed.DefaultAdminPassword)
	if !lr.User.MustChangePassword {
		t.Fatal("default admin should require a password change")
	}
	var rotated loginResponse
	body := fmt.Sprintf(`{"currentPassword":%q,"newPassword":%q}`, seed.DefaultAdminPassword, adminPassword)
	rec := call(t, h, http.MethodPost, "/api/v1/auth/change-password", lr.AccessToken, body, &rotated)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password: status %d", rec.Code)
	}
	return rotated.AccessToken
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env httpx.ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decoding error envelope: %v (body %q)", err, rec.Body.String())
	}
	return env.Error.Code
}

func TestEmptyTenantPathFailsClosedWithErrorEnvelope(t *testing.T) {
	h, _ := newTestAPI(t)
	rec := call(t, h, http.MethodGet, "/api/v1/tenants//users", "", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if code := errCode(t, rec); code != string(httpx.CodeValidationFailed) {
		t.Fatalf("code=%q body=%s", code, rec.Body.String())
	}
}

func TestHealthAndVersion(t *testing.T) {
	h, _ := newTestAPI(t)

	rec := call(t, h, http.MethodGet, "/healthz", "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz = %d", rec.Code)
	}

	var v map[string]string
	call(t, h, http.MethodGet, "/api/v1/version", "", "", &v)
	if v["graph"] != "sample" || v["store"] != "memory" {
		t.Fatalf("version = %v", v)
	}
}

func TestExchangeBootstrapUsesOneTimeGUICredentialsAndIsAdminOnly(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)
	var preview struct {
		ApprovalToken string `json:"approvalToken"`
		CallbackURL   string `json:"callbackUrl"`
		HTTPSReady    bool   `json:"httpsReady"`
	}
	rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/exchange/bootstrap/preview", admin, "", &preview)
	if rec.Code != http.StatusOK || preview.ApprovalToken == "" || preview.CallbackURL != "http://localhost:5173/api/v1/microsoft/exchange/bootstrap/callback" || !preview.HTTPSReady {
		t.Fatalf("bootstrap preview = %d %+v %s", rec.Code, preview, rec.Body.String())
	}
	rec = call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/exchange/bootstrap", admin, `{"approvalToken":"`+preview.ApprovalToken+`"}`, nil)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != httpx.CodeValidationFailed {
		t.Fatalf("missing GUI credentials = %d %s", rec.Code, rec.Body.String())
	}
	var start exchangebootstrap.StartResult
	body := `{"approvalToken":"` + preview.ApprovalToken + `","clientId":"11111111-1111-1111-1111-111111111111","clientSecret":"one-time-secret"}`
	rec = call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/exchange/bootstrap", admin, body, &start)
	if rec.Code != http.StatusOK || start.AuthorizationURL == "" {
		t.Fatalf("GUI bootstrap start = %d %+v %s", rec.Code, start, rec.Body.String())
	}
	tech := login(t, h, techEmail, seed.DemoPassword)
	rec = call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/exchange/bootstrap/preview", tech.AccessToken, "", nil)
	if rec.Code != http.StatusForbidden || errCode(t, rec) != httpx.CodeAuthorizationDenied {
		t.Fatalf("technician bootstrap = %d %s", rec.Code, rec.Body.String())
	}
}

func TestLoginFlow(t *testing.T) {
	h, st := newTestAPI(t)

	lr := login(t, h, techEmail, seed.DemoPassword)
	if lr.AccessToken == "" || lr.RefreshToken == "" || lr.User.IsAdmin || lr.User.MustChangePassword {
		t.Fatalf("login response = %+v", lr)
	}

	var me auth.Principal
	call(t, h, http.MethodGet, "/api/v1/auth/me", lr.AccessToken, "", &me)
	if me.Email != techEmail {
		t.Fatalf("me = %+v", me)
	}

	// Failed login → 401 envelope + audited denial.
	rec := call(t, h, http.MethodPost, "/api/v1/auth/login", "", `{"email":"aisha.rivera@rarity.io","password":"nope"}`, nil)
	if rec.Code != http.StatusUnauthorized || errCode(t, rec) != httpx.CodeAuthenticationFailed {
		t.Fatalf("bad login = %d %s", rec.Code, rec.Body.String())
	}
	entries, _ := st.Audit(t.Context())
	if entries[0].Action != "auth.login" || entries[0].Result != "Denied" {
		t.Fatalf("latest audit = %+v", entries[0])
	}
}

func TestRefreshRotationViaAPI(t *testing.T) {
	h, _ := newTestAPI(t)
	lr := login(t, h, techEmail, seed.DemoPassword)

	var next loginResponse
	body := fmt.Sprintf(`{"refreshToken":%q}`, lr.RefreshToken)
	rec := call(t, h, http.MethodPost, "/api/v1/auth/refresh", "", body, &next)
	if rec.Code != http.StatusOK || next.AccessToken == "" {
		t.Fatalf("refresh = %d %+v", rec.Code, next)
	}

	// Reusing the rotated-out token fails.
	rec = call(t, h, http.MethodPost, "/api/v1/auth/refresh", "", body, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("reuse = %d, want 401", rec.Code)
	}
}

func TestAuthenticationRequired(t *testing.T) {
	h, _ := newTestAPI(t)
	for _, path := range []string{"/api/v1/tenants", "/api/v1/jobs", "/api/v1/audit", "/api/v1/global-reports/mfa"} {
		if rec := call(t, h, http.MethodGet, path, "", "", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated = %d, want 401", path, rec.Code)
		}
	}
}

func TestTenantAccessForAll(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken
	if rec := call(t, h, http.MethodPut, "/api/v1/admin/roles/Admin", admin,
		`{"description":"Administrators retain recovery access.","permissionKeys":[]}`, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("admin recovery permission removal = %d, want 400", rec.Code)
	}

	// Every RTM user can read every managed tenant — no grant model.
	for _, token := range []string{tech, admin} {
		if rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/users", token, "", nil); rec.Code != http.StatusOK {
			t.Fatalf("tenant read = %d, want 200", rec.Code)
		}
	}
	// Unknown tenants still 404 on detail.
	rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_none/", admin, "", nil)
	if rec.Code != http.StatusNotFound || errCode(t, rec) != httpx.CodeObjectNotFound {
		t.Fatalf("unknown tenant = %d %s", rec.Code, rec.Body.String())
	}
}

func TestTenantSummariesUseProviderUserCount(t *testing.T) {
	h, _ := newTestAPI(t)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken

	var users []model.User
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/users", tech, "", &users); rec.Code != http.StatusOK {
		t.Fatalf("users = %d %s", rec.Code, rec.Body.String())
	}
	var tenants []model.Tenant
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants", tech, "", &tenants); rec.Code != http.StatusOK {
		t.Fatalf("tenants = %d %s", rec.Code, rec.Body.String())
	}
	if len(tenants) != 1 || tenants[0].Users != len(users) {
		t.Fatalf("tenant user count = %+v, inventory count = %d", tenants, len(users))
	}
	var detail model.Tenant
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_1", tech, "", &detail); rec.Code != http.StatusOK || detail.Users != len(users) {
		t.Fatalf("tenant detail count = %d %+v, inventory count = %d", rec.Code, detail, len(users))
	}
}

// changeBody is a valid group-membership change against the sample tenant
// (usr_3/usr_4 are not members of grp_1 in the sample data).
const changeBody = `{"action":"add_to_group","tenantId":"ten_1","groupId":"grp_1","userIds":["usr_3","usr_4"]}`

// waitForJob polls until the job leaves Queued/Running (the inline executor
// runs it on a goroutine) and returns its final state.
func waitForJob(t *testing.T, st *store.Mem, jobID string) model.Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		jobsList, _ := st.Jobs(t.Context())
		for _, j := range jobsList {
			if j.ID == jobID && j.Status != "Queued" && j.Status != "Running" {
				return j
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish", jobID)
	return model.Job{}
}

func TestWriteActionsRequireAdmin(t *testing.T) {
	h, _ := newTestAPI(t)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken

	// v1 write gate: technicians cannot execute changes.
	rec := call(t, h, http.MethodPost, "/api/v1/changes/execute", tech, changeBody, nil)
	if rec.Code != http.StatusForbidden || errCode(t, rec) != httpx.CodeAuthorizationDenied {
		t.Fatalf("tech execute = %d %s", rec.Code, rec.Body.String())
	}
}

func TestWhatIfPreviewComputed(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)

	// Empty/invalid requests are rejected — no canned preview.
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, "{}", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty preview = %d, want 400", rec.Code)
	}

	var preview model.WhatIfPreview
	rec = call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, changeBody, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	if preview.Tenant != "Contoso Ltd" || preview.TargetCount != 2 || len(preview.Changes) != 2 {
		t.Fatalf("preview = %+v", preview)
	}
	if preview.Changes[0].Object != "Caleb Stone" || preview.Changes[0].Change != "Add as Member" {
		t.Fatalf("first change = %+v", preview.Changes[0])
	}
	if preview.RequiredPermission != "GroupMember.ReadWrite.All" {
		t.Fatalf("permission = %q", preview.RequiredPermission)
	}

	// Unknown users are skipped with a reason, not silently included.
	var withUnknown model.WhatIfPreview
	call(t, h, http.MethodPost, "/api/v1/changes/preview", admin,
		`{"action":"add_to_group","tenantId":"ten_1","groupId":"grp_1","userIds":["usr_3","usr_ghost"]}`, &withUnknown)
	if withUnknown.TargetCount != 1 || len(withUnknown.Skipped) != 1 || len(withUnknown.Warnings) == 0 {
		t.Fatalf("preview with unknown = %+v", withUnknown)
	}
}

func TestSensitiveUserActionsReturnPasswordsOnceWithoutPersistingThem(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	var preview model.WhatIfPreview
	body := `{"action":"reset_password","tenantId":"ten_1","userIds":["usr_4"]}`
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || !strings.Contains(preview.RequiredPermission, "User-PasswordProfile.ReadWrite.All") {
		t.Fatalf("password preview = %d %+v", rec.Code, preview)
	}
	var reset model.JobRef
	execute := fmt.Sprintf(`{"action":"reset_password","tenantId":"ten_1","userIds":["usr_4"],"approvalToken":%q}`, preview.ApprovalToken)
	rec = call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, execute, &reset)
	if rec.Code != http.StatusOK || reset.Status != "succeeded" || len(reset.OneTimePasswords) != 1 {
		t.Fatalf("password execute = %d %+v", rec.Code, reset)
	}
	if !strings.HasPrefix(reset.OneTimePasswords[0].Password, "Rtm-") || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("one-time response/header = %+v / %q", reset, rec.Header().Get("Cache-Control"))
	}
	secret := reset.OneTimePasswords[0].Password

	var containmentPreview model.WhatIfPreview
	containmentBody := `{"action":"revoke_user_access","tenantId":"ten_1","userIds":["usr_4"]}`
	call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, containmentBody, &containmentPreview)
	if !strings.Contains(containmentPreview.RequiredPermission, "UserAuthenticationMethod.ReadWrite.All") || containmentPreview.Risk != "Medium" {
		t.Fatalf("containment preview = %+v", containmentPreview)
	}
	var containment model.JobRef
	containmentExecute := fmt.Sprintf(`{"action":"revoke_user_access","tenantId":"ten_1","userIds":["usr_4"],"approvalToken":%q}`, containmentPreview.ApprovalToken)
	rec = call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, containmentExecute, &containment)
	if rec.Code != http.StatusOK || containment.Status != "succeeded" || len(containment.OneTimePasswords) != 1 {
		t.Fatalf("containment execute = %d %+v", rec.Code, containment)
	}

	changes, _ := st.Changes(t.Context())
	audit, _ := st.Audit(t.Context())
	persisted, _ := json.Marshal(struct {
		Changes []model.Change
		Audit   []model.AuditEntry
	}{changes, audit})
	if strings.Contains(string(persisted), secret) || strings.Contains(string(persisted), containment.OneTimePasswords[0].Password) {
		t.Fatalf("one-time password was persisted: %s", persisted)
	}
	for _, change := range changes {
		detail, err := st.Change(t.Context(), change.ID)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(detail)
		if strings.Contains(string(raw), secret) || strings.Contains(string(raw), containment.OneTimePasswords[0].Password) {
			t.Fatalf("one-time password leaked into change detail: %s", raw)
		}
	}

	tooMany := `{"action":"reset_password","tenantId":"ten_1","userIds":["u1","u2","u3","u4","u5","u6","u7","u8","u9","u10","u11"]}`
	rec = call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, tooMany, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "limited to 10 users") {
		t.Fatalf("password target bound = %d %s", rec.Code, rec.Body.String())
	}
}

func TestExecuteRunsRealPipeline(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	var ref model.JobRef
	rec := call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, changeBody, &ref)
	if rec.Code != http.StatusAccepted || ref.JobID == "" || ref.Status != "queued" {
		t.Fatalf("execute = %d %+v", rec.Code, ref)
	}

	// The inline executor runs the full pipeline: job → Completed with a
	// real duration, change recorded with detail + revert payload.
	job := waitForJob(t, st, ref.JobID)
	if job.Status != "Completed" || job.Duration == "—" || job.Tenant != "Contoso Ltd" {
		t.Fatalf("job = %+v", job)
	}

	changes, _ := st.Changes(t.Context())
	if len(changes) != 1 {
		t.Fatalf("changes = %d, want 1", len(changes))
	}
	c := changes[0]
	if c.Action != "Added 2 members" || c.Target != "Sales — All Staff" || c.Status != "Completed" || c.Revert != "Available" {
		t.Fatalf("change = %+v", c)
	}
	detail, err := st.Change(t.Context(), c.ID)
	if err != nil || !detail.RevertEligible || detail.RevertPayload == "" || len(detail.ExecutionLog) == 0 {
		t.Fatalf("detail = %+v, %v", detail, err)
	}

	// Revert: queues the stored reverse payload and marks the original.
	var revRef model.JobRef
	rec = call(t, h, http.MethodPost, "/api/v1/changes/revert", admin, fmt.Sprintf(`{"id":%q}`, c.ID), &revRef)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("revert = %d %s", rec.Code, rec.Body.String())
	}
	revJob := waitForJob(t, st, revRef.JobID)
	if revJob.Status != "Completed" {
		t.Fatalf("revert job = %+v", revJob)
	}
	orig, _ := st.Change(t.Context(), c.ID)
	if orig.Revert != "Reverted" {
		t.Fatalf("original revert state = %q, want Reverted", orig.Revert)
	}
	// Double-revert is refused.
	rec = call(t, h, http.MethodPost, "/api/v1/changes/revert", admin, fmt.Sprintf(`{"id":%q}`, c.ID), nil)
	if rec.Code != http.StatusConflict || errCode(t, rec) != httpx.CodeRevertConflict {
		t.Fatalf("double revert = %d %s", rec.Code, rec.Body.String())
	}
}

// failingWritesGraph authenticates and reads fine but rejects writes, like a
// tenant whose app lacks GroupMember.ReadWrite.All.
type failingWritesGraph struct {
	graph.Provider
}

func (failingWritesGraph) AddGroupMembers(context.Context, string, string, []string) error {
	return &graph.APIError{Status: http.StatusForbidden, Code: "Authorization_RequestDenied",
		Message: "Insufficient privileges to complete the operation.", Path: "POST /groups/x/members/$ref"}
}

func TestExecuteFailureIsRecordedHonestly(t *testing.T) {
	gp := failingWritesGraph{graph.NewProvider(graph.Config{}, discardLogger(), nil)}
	h, st := newTestAPIWithGraph(t, gp)
	admin := adminToken(t, h)

	var ref model.JobRef
	rec := call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, changeBody, &ref)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("execute = %d", rec.Code)
	}
	job := waitForJob(t, st, ref.JobID)
	if job.Status != "Failed" {
		t.Fatalf("job = %+v, want Failed", job)
	}
	changes, _ := st.Changes(t.Context())
	if len(changes) != 1 || changes[0].Status != "Failed" || changes[0].Revert != "—" {
		t.Fatalf("failed change = %+v", changes)
	}
	detail, _ := st.Change(t.Context(), changes[0].ID)
	found := false
	for _, line := range detail.ExecutionLog {
		if strings.Contains(line, "Authorization_RequestDenied") {
			found = true
		}
	}
	if !found {
		t.Fatalf("execution log lacks the Microsoft reason: %v", detail.ExecutionLog)
	}
}

func TestPreviewPerAction(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)

	preview := func(body string) model.WhatIfPreview {
		t.Helper()
		var p model.WhatIfPreview
		rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &p)
		if rec.Code != http.StatusOK {
			t.Fatalf("preview %s = %d %s", body, rec.Code, rec.Body.String())
		}
		return p
	}

	// remove_from_group: only current members are targets (usr_1 is a member,
	// usr_4 is not — sample data).
	p := preview(`{"action":"remove_from_group","tenantId":"ten_1","groupId":"grp_1","userIds":["usr_1","usr_4"]}`)
	if p.TargetCount != 1 || len(p.Skipped) != 1 || p.Skipped[0].Reason != "Not a member of this group" {
		t.Fatalf("remove preview = %+v", p)
	}

	// block_signin: usr_7 is already Disabled in sample data → skipped;
	// destructive action floors risk at Medium and warns.
	p = preview(`{"action":"block_signin","tenantId":"ten_1","userIds":["usr_4","usr_7"]}`)
	if p.TargetCount != 1 || len(p.Skipped) != 1 || p.Skipped[0].Reason != "Sign-in is already blocked" {
		t.Fatalf("block preview = %+v", p)
	}
	if p.Risk != "Medium" || p.RequiredPermission != "User.ReadWrite.All" {
		t.Fatalf("block risk/permission = %s/%s", p.Risk, p.RequiredPermission)
	}

	// unblock_signin: only blocked users are targets.
	p = preview(`{"action":"unblock_signin","tenantId":"ten_1","userIds":["usr_4","usr_7"]}`)
	if p.TargetCount != 1 || p.Changes[0].Object != "Gavin Reed" {
		t.Fatalf("unblock preview = %+v", p)
	}

	// assign_license: resolves the SKU by id and warns about usage location.
	p = preview(`{"action":"assign_license","tenantId":"ten_1","skuId":"sku-SPE_E5","userIds":["usr_4"]}`)
	if p.TargetCount != 1 || !strings.Contains(p.Action, "Microsoft 365 E5") {
		t.Fatalf("assign preview = %+v", p)
	}
	found := false
	for _, w := range p.Warnings {
		if strings.Contains(w, "usage location") {
			found = true
		}
	}
	if !found {
		t.Fatalf("assign warnings = %v", p.Warnings)
	}

	// revoke_sessions: warns it cannot be reverted.
	p = preview(`{"action":"revoke_sessions","tenantId":"ten_1","userIds":["usr_4"]}`)
	found = false
	for _, w := range p.Warnings {
		if strings.Contains(w, "cannot be reverted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("revoke warnings = %v", p.Warnings)
	}

	// Validation: license action without a skuId, unknown sku, unknown action.
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin,
		`{"action":"assign_license","tenantId":"ten_1","userIds":["usr_4"]}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing skuId = %d, want 400", rec.Code)
	}
	rec = call(t, h, http.MethodPost, "/api/v1/changes/preview", admin,
		`{"action":"assign_license","tenantId":"ten_1","skuId":"sku-NOPE","userIds":["usr_4"]}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown sku = %d, want 400", rec.Code)
	}
	rec = call(t, h, http.MethodPost, "/api/v1/changes/preview", admin,
		`{"action":"delete_everything","tenantId":"ten_1","userIds":["usr_4"]}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown action = %d, want 400", rec.Code)
	}
}

func TestBlockUnblockRoundTrip(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	// Block an active user → job completes → change is revertible.
	var ref model.JobRef
	rec := call(t, h, http.MethodPost, "/api/v1/changes/execute", admin,
		`{"action":"block_signin","tenantId":"ten_1","userIds":["usr_4"]}`, &ref)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("execute = %d %s", rec.Code, rec.Body.String())
	}
	job := waitForJob(t, st, ref.JobID)
	if job.Status != "Completed" || job.Type != "Sign-in Block" {
		t.Fatalf("job = %+v", job)
	}
	changes, _ := st.Changes(t.Context())
	c := changes[0]
	if c.Action != "Blocked sign-in for 1 user" || c.Revert != "Available" {
		t.Fatalf("change = %+v", c)
	}

	// Revert queues the unblock and marks the original.
	var revRef model.JobRef
	rec = call(t, h, http.MethodPost, "/api/v1/changes/revert", admin, fmt.Sprintf(`{"id":%q}`, c.ID), &revRef)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("revert = %d %s", rec.Code, rec.Body.String())
	}
	// The revert job is labeled by what it does (unblocking).
	revJob := waitForJob(t, st, revRef.JobID)
	if revJob.Status != "Completed" || revJob.Type != "Revert — Sign-in Unblock" {
		t.Fatalf("revert job = %+v", revJob)
	}
	orig, _ := st.Change(t.Context(), c.ID)
	if orig.Revert != "Reverted" {
		t.Fatalf("original = %+v", orig.Change)
	}
	changes, _ = st.Changes(t.Context())
	if changes[0].Action != "Revert — Unblocked sign-in for 1 user" {
		t.Fatalf("revert change = %+v", changes[0])
	}
}

func TestRevokeSessionsNotRevertibleViaAPI(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	var ref model.JobRef
	call(t, h, http.MethodPost, "/api/v1/changes/execute", admin,
		`{"action":"revoke_sessions","tenantId":"ten_1","userIds":["usr_4"]}`, &ref)
	waitForJob(t, st, ref.JobID)
	changes, _ := st.Changes(t.Context())
	if changes[0].Revert != "Not supported" {
		t.Fatalf("revoke change = %+v", changes[0])
	}
	rec := call(t, h, http.MethodPost, "/api/v1/changes/revert", admin, fmt.Sprintf(`{"id":%q}`, changes[0].ID), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("revert of revoke = %d, want 409", rec.Code)
	}
}

func TestCreateGroup(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken

	// Group creation is admin-only.
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/groups", tech,
		`{"name":"X","type":"Security"}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("tech create = %d, want 403", rec.Code)
	}

	// Validation: name, description, and a valid type are required.
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/groups", admin, `{"type":"Security"}`, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("nameless = %d, want 400", rec.Code)
	}
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/groups", admin, `{"name":"X","type":"Security"}`, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("descriptionless = %d, want 400", rec.Code)
	}
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/groups", admin, `{"name":"X","description":"Test group","type":"Distribution"}`, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad type = %d, want 400", rec.Code)
	}

	// Create a security group → 201, appears in the list, audited.
	var g model.Group
	rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/groups", admin,
		`{"name":"Project Phoenix","description":"Launch team","type":"Security"}`, &g)
	if rec.Code != http.StatusCreated || g.ID == "" || g.Type != "Security" || g.Name != "Project Phoenix" {
		t.Fatalf("create = %d %+v", rec.Code, g)
	}

	var groups []model.Group
	call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/groups", admin, "", &groups)
	found := false
	for _, x := range groups {
		if x.Name == "Project Phoenix" && x.Type == "Security" {
			found = true
		}
	}
	if !found {
		t.Fatalf("created group not in list (%d groups)", len(groups))
	}

	entries, _ := st.Audit(t.Context())
	if entries[0].Action != "group.create" || entries[0].Resource != "Project Phoenix" {
		t.Fatalf("latest audit = %+v", entries[0])
	}

	// M365 group also works.
	rec = call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/groups", admin,
		`{"name":"Marketing 365","description":"Marketing collaboration workspace","type":"M365"}`, &g)
	if rec.Code != http.StatusCreated || g.Type != "M365" || g.Mail != "Yes" {
		t.Fatalf("m365 create = %d %+v", rec.Code, g)
	}
}

func TestDashboardStatsComputed(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)

	var stats []model.DashboardStat
	call(t, h, http.MethodGet, "/api/v1/dashboard/stats", admin, "", &stats)
	byLabel := map[string]model.DashboardStat{}
	for _, s := range stats {
		byLabel[s.Label] = s
	}
	if byLabel["Managed Tenants"].Value != "1" {
		t.Fatalf("tenants stat = %+v", byLabel["Managed Tenants"])
	}
	if byLabel["Active Jobs"].Value != "0" || byLabel["Changes Today"].Value != "0" {
		t.Fatalf("fresh install stats = %+v", stats)
	}
}

func TestDashboardStatsMoveWithActivity(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	var ref model.JobRef
	call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, changeBody, &ref)
	waitForJob(t, st, ref.JobID)

	var stats []model.DashboardStat
	call(t, h, http.MethodGet, "/api/v1/dashboard/stats", admin, "", &stats)
	byLabel := map[string]model.DashboardStat{}
	for _, s := range stats {
		byLabel[s.Label] = s
	}
	if byLabel["Changes Today"].Value != "1" {
		t.Fatalf("changes today = %+v", byLabel["Changes Today"])
	}
	if byLabel["Failed Jobs"].Value != "0" {
		t.Fatalf("failed jobs = %+v", byLabel["Failed Jobs"])
	}
}

func TestJobAcknowledgePersistsAndAudits(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)
	job, _ := st.CreateJob(t.Context(), model.Job{
		Type: "Mailbox Permission", Tenant: "Contoso Ltd", Status: "Failed",
		Progress: 38, Started: "14:09", TriggeredBy: "T. Tester",
	})

	if rec := call(t, h, http.MethodPost, "/api/v1/jobs/"+job.ID+"/acknowledge", admin, `{}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("acknowledge = %d %s", rec.Code, rec.Body.String())
	}
	jobs, _ := st.Jobs(t.Context())
	for _, got := range jobs {
		if got.ID == job.ID && !got.Acknowledged {
			t.Fatalf("job not acknowledged: %+v", got)
		}
	}
	entries, _ := st.Audit(t.Context())
	if entries[0].Action != "jobs.acknowledge" || entries[0].Resource != job.ID {
		t.Fatalf("ack audit = %+v", entries[0])
	}
}

func TestTechnicianCRUD(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken

	// Admin-only.
	if rec := call(t, h, http.MethodPost, "/api/v1/admin/technicians", tech, `{}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("tech create = %d, want 403", rec.Code)
	}

	// Invite: creates a real account with a one-time temp password.
	var created struct {
		Technician   model.Technician `json:"technician"`
		TempPassword string           `json:"tempPassword"`
	}
	body := `{"name":"Nina Wells","email":"nina.wells@rarity.io","role":"Technician"}`
	rec := call(t, h, http.MethodPost, "/api/v1/admin/technicians", admin, body, &created)
	if rec.Code != http.StatusCreated || created.Technician.ID == "" || created.TempPassword == "" {
		t.Fatalf("create = %d %+v", rec.Code, created)
	}
	// Duplicate email is rejected.
	if rec := call(t, h, http.MethodPost, "/api/v1/admin/technicians", admin, body, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate = %d, want 400", rec.Code)
	}

	// The invitee can log in with the temp password and must rotate it.
	lr := login(t, h, "nina.wells@rarity.io", created.TempPassword)
	if !lr.User.MustChangePassword {
		t.Fatal("invited account should require a password change")
	}
	// Only the two RTM roles are accepted.
	if rec := call(t, h, http.MethodPatch, "/api/v1/admin/technicians/"+created.Technician.ID, admin, `{"role":"Auditor"}`, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bogus role = %d, want 400", rec.Code)
	}
	// Promoting to Admin also grants admin rights (isAdmin derives from role).
	rec = call(t, h, http.MethodPatch, "/api/v1/admin/technicians/"+created.Technician.ID, admin, `{"role":"Admin"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d", rec.Code)
	}

	// The list reflects reality.
	var techs []model.Technician
	call(t, h, http.MethodGet, "/api/v1/admin/technicians", admin, "", &techs)
	foundNina := false
	for _, tt := range techs {
		if tt.Email == "nina.wells@rarity.io" && tt.Role == "Admin" && tt.Tenants == "All" {
			foundNina = true
		}
	}
	if !foundNina {
		t.Fatalf("technicians = %+v", techs)
	}

	// Self-delete is refused; deleting the invitee works.
	var me auth.Principal
	call(t, h, http.MethodGet, "/api/v1/auth/me", admin, "", &me)
	if rec := call(t, h, http.MethodDelete, "/api/v1/admin/technicians/"+me.ID, admin, "", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("self delete = %d, want 400", rec.Code)
	}
	if rec := call(t, h, http.MethodDelete, "/api/v1/admin/technicians/"+created.Technician.ID, admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	rec = call(t, h, http.MethodPost, "/api/v1/auth/login", "",
		fmt.Sprintf(`{"email":"nina.wells@rarity.io","password":%q}`, created.TempPassword), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("deleted account login = %d, want 401", rec.Code)
	}
}

func TestAdminPasswordResetRevokesSessionsAndForcesRotation(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken

	var created struct {
		Technician   model.Technician `json:"technician"`
		TempPassword string           `json:"tempPassword"`
	}
	rec := call(t, h, http.MethodPost, "/api/v1/admin/technicians", admin,
		`{"name":"Password Reset Test","email":"reset.test@rarity.io","role":"Technician"}`, &created)
	if rec.Code != http.StatusCreated || !created.Technician.MustChangePassword {
		t.Fatalf("create = %d %+v", rec.Code, created)
	}

	initial := login(t, h, "reset.test@rarity.io", created.TempPassword)
	const permanentPassword = "permanent-password-2026"
	var rotated loginResponse
	rec = call(t, h, http.MethodPost, "/api/v1/auth/change-password", initial.AccessToken,
		fmt.Sprintf(`{"currentPassword":%q,"newPassword":%q}`, created.TempPassword, permanentPassword), &rotated)
	if rec.Code != http.StatusOK {
		t.Fatalf("initial rotation = %d %s", rec.Code, rec.Body.String())
	}

	// Technician role cannot reset accounts, and admins use self-service for
	// their own credential instead of accidentally locking their current login.
	if rec := call(t, h, http.MethodPost, "/api/v1/admin/technicians/"+created.Technician.ID+"/reset-password", tech, "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("technician reset = %d, want 403", rec.Code)
	}
	var me auth.Principal
	call(t, h, http.MethodGet, "/api/v1/auth/me", admin, "", &me)
	if rec := call(t, h, http.MethodPost, "/api/v1/admin/technicians/"+me.ID+"/reset-password", admin, "", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("self reset = %d, want 400", rec.Code)
	}

	var reset struct {
		Status       string `json:"status"`
		TempPassword string `json:"tempPassword"`
	}
	rec = call(t, h, http.MethodPost, "/api/v1/admin/technicians/"+created.Technician.ID+"/reset-password", admin, "", &reset)
	if rec.Code != http.StatusOK || reset.Status != "reset" || len(reset.TempPassword) < auth.MinPasswordLength {
		t.Fatalf("reset = %d %+v", rec.Code, reset)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("reset Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}

	// Password versioning invalidates both token types immediately.
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants", rotated.AccessToken, "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old access token = %d, want 401", rec.Code)
	}
	if rec := call(t, h, http.MethodPost, "/api/v1/auth/refresh", "",
		fmt.Sprintf(`{"refreshToken":%q}`, rotated.RefreshToken), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old refresh token = %d, want 401", rec.Code)
	}
	if rec := call(t, h, http.MethodPost, "/api/v1/auth/login", "",
		fmt.Sprintf(`{"email":"reset.test@rarity.io","password":%q}`, permanentPassword), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password = %d, want 401", rec.Code)
	}
	if relogin := login(t, h, "reset.test@rarity.io", reset.TempPassword); !relogin.User.MustChangePassword {
		t.Fatalf("temporary-password login = %+v", relogin.User)
	}

	entries, _ := st.Audit(t.Context())
	found := false
	for _, entry := range entries {
		if entry.Action == "technician.password.reset" && entry.Resource == "reset.test@rarity.io" && entry.Result == "Success" {
			found = true
		}
		if strings.Contains(entry.Resource, reset.TempPassword) {
			t.Fatalf("audit leaked temporary password: %+v", entry)
		}
	}
	if !found {
		t.Fatalf("reset audit entry missing: %+v", entries)
	}
}

func TestSettingsToggle(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)

	// Unlocked settings persist.
	rec := call(t, h, http.MethodPatch, "/api/v1/admin/settings/require_approval", admin, `{"enabled":true}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle = %d", rec.Code)
	}
	var settings []model.AppSetting
	call(t, h, http.MethodGet, "/api/v1/admin/settings", admin, "", &settings)
	for _, s := range settings {
		if s.Key == "require_approval" && !s.Enabled {
			t.Fatal("toggle did not persist")
		}
	}

	// Locked settings are policy and refuse changes.
	rec = call(t, h, http.MethodPatch, "/api/v1/admin/settings/require_whatif", admin, `{"enabled":false}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("locked toggle = %d, want 400", rec.Code)
	}

	// Session timeout accepts only the bounded policy choices and persists the
	// selected minute value for subsequent token issuance.
	rec = call(t, h, http.MethodPatch, "/api/v1/admin/settings/session_timeout", admin, `{"value":"480"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("session timeout = %d %s", rec.Code, rec.Body.String())
	}
	settings = nil
	call(t, h, http.MethodGet, "/api/v1/admin/settings", admin, "", &settings)
	foundTimeout := false
	for _, setting := range settings {
		if setting.Key == "session_timeout" {
			foundTimeout = true
			if setting.Value != "480" {
				t.Fatalf("session timeout value = %q, want 480", setting.Value)
			}
		}
	}
	if !foundTimeout {
		t.Fatal("session_timeout setting not returned")
	}
	rec = call(t, h, http.MethodPatch, "/api/v1/admin/settings/session_timeout", admin, `{"value":"45"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported session timeout = %d, want 400", rec.Code)
	}
}

func TestEditableRolePermissionsApplyImmediately(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken

	// The default Technician role cannot execute tenant changes.
	if rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", tech, `{}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("default technician preview = %d, want 403", rec.Code)
	}

	// The Admin recovery floor cannot be weakened through the editable policy.
	if rec := call(t, h, http.MethodPut, "/api/v1/admin/roles/Admin", admin,
		`{"description":"Platform administrators retain recovery access.","permissionKeys":["roles.manage"]}`, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("weaken admin role = %d, want 400", rec.Code)
	}

	body := `{"description":"Technicians can execute approved tenant changes.","permissionKeys":["changes.execute"]}`
	var updated model.Role
	if rec := call(t, h, http.MethodPut, "/api/v1/admin/roles/Technician", admin, body, &updated); rec.Code != http.StatusOK {
		t.Fatalf("update role = %d: %s", rec.Code, rec.Body.String())
	}
	if len(updated.PermissionKeys) != 1 || updated.PermissionKeys[0] != seed.PermissionExecuteChanges || updated.Level != "Custom" {
		t.Fatalf("updated role = %+v", updated)
	}

	// Middleware reloads the role on every request, so the already-issued
	// technician token reaches handler validation instead of authorization.
	if rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", tech, `{}`, nil); rec.Code == http.StatusForbidden {
		t.Fatalf("granted technician preview still forbidden: %s", rec.Body.String())
	}

	if rec := call(t, h, http.MethodPut, "/api/v1/admin/roles/Technician", admin,
		`{"description":"Read access across all managed tenants.","permissionKeys":[]}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("revoke role = %d", rec.Code)
	}
	if rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", tech, `{}`, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("revoked technician preview = %d, want 403", rec.Code)
	}

	audit, err := st.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	updates := 0
	for _, entry := range audit {
		if entry.Action == "role.update" && entry.Resource == seed.RoleTechnician {
			updates++
		}
	}
	if updates != 2 {
		t.Fatalf("role update audit entries = %d, want 2", updates)
	}
}

func TestCreateWorkingSet(t *testing.T) {
	h, st := newTestAPI(t)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken

	// Validation: name is required.
	rec := call(t, h, http.MethodPost, "/api/v1/working-sets", tech, `{"description":"no name"}`, nil)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != httpx.CodeValidationFailed {
		t.Fatalf("nameless working set = %d %s", rec.Code, rec.Body.String())
	}

	rec = call(t, h, http.MethodPost, "/api/v1/working-sets", tech, `{"name":"MFA Cleanup","tenantId":"ten_1","userIds":[]}`, nil)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != httpx.CodeValidationFailed {
		t.Fatalf("empty working set = %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, h, http.MethodPost, "/api/v1/working-sets", tech, `{"name":"MFA Cleanup","tenantId":"missing","userIds":["u1"]}`, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant = %d %s", rec.Code, rec.Body.String())
	}

	var ws model.WorkingSet
	rec = call(t, h, http.MethodPost, "/api/v1/working-sets", tech, `{"name":"MFA Cleanup","description":"Users without MFA","tenantId":"ten_1","userIds":["u1","u2","u1",""]}`, &ws)
	if rec.Code != http.StatusCreated || ws.Items != 2 || ws.CreatedBy != "Aisha Rivera" || ws.TenantID != "ten_1" || ws.Tenant != "Contoso Ltd" || ws.Description != "Users without MFA" {
		t.Fatalf("created = %d %+v", rec.Code, ws)
	}
	if len(ws.UserIDs) != 2 || ws.UserIDs[0] != "u1" || ws.UserIDs[1] != "u2" {
		t.Fatalf("created user IDs = %v", ws.UserIDs)
	}

	var listed []model.WorkingSet
	rec = call(t, h, http.MethodGet, "/api/v1/working-sets", tech, "", &listed)
	if rec.Code != http.StatusOK || len(listed) != 1 || listed[0].ID != ws.ID || len(listed[0].UserIDs) != 2 {
		t.Fatalf("listed = %d %+v", rec.Code, listed)
	}
	audit, err := st.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	foundAudit := false
	for _, entry := range audit {
		if entry.Action == "working_set.create" && entry.Resource == "MFA Cleanup" && entry.Result == "Success" {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Fatal("working_set.create audit entry not found")
	}

	var fetched model.WorkingSet
	rec = call(t, h, http.MethodGet, "/api/v1/working-sets/"+ws.ID, tech, "", &fetched)
	if rec.Code != http.StatusOK || fetched.ID != ws.ID {
		t.Fatalf("fetched = %d %+v", rec.Code, fetched)
	}
	rec = call(t, h, http.MethodPut, "/api/v1/working-sets/"+ws.ID, tech,
		`{"name":"Priority MFA Cleanup","description":"Updated scope","userIds":["u2","u3","u3"]}`, &fetched)
	if rec.Code != http.StatusOK || fetched.Name != "Priority MFA Cleanup" || fetched.Description != "Updated scope" || fetched.Items != 2 || len(fetched.UserIDs) != 2 {
		t.Fatalf("updated = %d %+v", rec.Code, fetched)
	}
	rec = call(t, h, http.MethodPut, "/api/v1/working-sets/"+ws.ID, tech,
		`{"name":"Empty","userIds":[]}`, nil)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != httpx.CodeValidationFailed {
		t.Fatalf("empty update = %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, h, http.MethodGet, "/api/v1/working-sets/missing", tech, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing working set = %d, want 404", rec.Code)
	}
	audit, err = st.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	foundUpdate := false
	for _, entry := range audit {
		if entry.Action == "working_set.update" && entry.Resource == "Priority MFA Cleanup" && entry.Result == "Success" {
			foundUpdate = true
		}
	}
	if !foundUpdate {
		t.Fatal("working_set.update audit entry not found")
	}
}

func TestGlobalReportSampleMode(t *testing.T) {
	h, _ := newTestAPI(t)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken

	var rep model.GlobalReport
	rec := call(t, h, http.MethodGet, "/api/v1/global-reports/mfa", tech, "", &rep)
	if rec.Code != http.StatusOK || len(rep.Columns) == 0 || len(rep.Rows) == 0 {
		t.Fatalf("mfa report = %d %+v", rec.Code, rep)
	}
	if rep.Columns[0] != "Tenant" {
		t.Fatalf("first column = %q, want Tenant", rep.Columns[0])
	}
}

func TestAdminEndpointsRequireAdmin(t *testing.T) {
	h, _ := newTestAPI(t)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken
	admin := adminToken(t, h)

	if rec := call(t, h, http.MethodGet, "/api/v1/admin/technicians", tech, "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("tech admin read = %d, want 403", rec.Code)
	}
	if rec := call(t, h, http.MethodGet, "/api/v1/admin/technicians", admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("admin read = %d, want 200", rec.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	h, _ := newTestAPI(t)

	// The login route allows 10/min per IP; httptest requests share one
	// RemoteAddr, so the 11th attempt trips the limiter.
	var last *httptest.ResponseRecorder
	for i := 0; i < 11; i++ {
		last = call(t, h, http.MethodPost, "/api/v1/auth/login", "", `{"email":"x@x","password":"x"}`, nil)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("11th login = %d, want 429", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
}

func TestForcedPasswordChange(t *testing.T) {
	h, _ := newTestAPI(t)

	// Default admin logs in with the shipped credentials…
	lr := login(t, h, seed.DefaultAdminEmail, seed.DefaultAdminPassword)
	if !lr.User.MustChangePassword {
		t.Fatal("default admin should be flagged for password change")
	}

	// …and is locked out of everything except identity + rotation.
	rec := call(t, h, http.MethodGet, "/api/v1/tenants", lr.AccessToken, "", nil)
	if rec.Code != http.StatusForbidden || errCode(t, rec) != httpx.CodePasswordChangeRequired {
		t.Fatalf("gated endpoint = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, h, http.MethodGet, "/api/v1/auth/me", lr.AccessToken, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("/auth/me while gated = %d, want 200", rec.Code)
	}

	// Weak or wrong inputs are rejected.
	rec = call(t, h, http.MethodPost, "/api/v1/auth/change-password", lr.AccessToken,
		fmt.Sprintf(`{"currentPassword":%q,"newPassword":"short"}`, seed.DefaultAdminPassword), nil)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != httpx.CodeValidationFailed {
		t.Fatalf("weak password = %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, h, http.MethodPost, "/api/v1/auth/change-password", lr.AccessToken,
		`{"currentPassword":"wrong","newPassword":"long-enough-password"}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current password = %d, want 401", rec.Code)
	}

	// Rotation succeeds and the fresh token opens the API.
	var rotated loginResponse
	rec = call(t, h, http.MethodPost, "/api/v1/auth/change-password", lr.AccessToken,
		fmt.Sprintf(`{"currentPassword":%q,"newPassword":%q}`, seed.DefaultAdminPassword, adminPassword), &rotated)
	if rec.Code != http.StatusOK || rotated.User.MustChangePassword {
		t.Fatalf("rotation = %d %+v", rec.Code, rotated.User)
	}
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants", rotated.AccessToken, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("post-rotation read = %d, want 200", rec.Code)
	}

	// Password rotation immediately revokes the pre-rotation access token.
	rec = call(t, h, http.MethodGet, "/api/v1/tenants", lr.AccessToken, "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("old token = %d, want 401", rec.Code)
	}

	// Old password is dead; new one logs in clean.
	rec = call(t, h, http.MethodPost, "/api/v1/auth/login", "",
		fmt.Sprintf(`{"email":%q,"password":%q}`, seed.DefaultAdminEmail, seed.DefaultAdminPassword), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password login = %d, want 401", rec.Code)
	}
	if again := login(t, h, seed.DefaultAdminEmail, adminPassword); again.User.MustChangePassword {
		t.Fatalf("re-login = %+v", again.User)
	}
}

func TestTenantLifecycle(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken

	newTenant := `{"name":"Fabrikam, Inc.","domain":"fabrikam.com","microsoftTenantId":"b8c2e6a1-4d9f-4e72-8a3b-1f6c9d0e5a47","clientId":"app-123","clientSecret":"s3cret-value"}`

	// Only admins can connect tenants.
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants", tech, newTenant, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("tech create = %d, want 403", rec.Code)
	}

	// Validation: required fields and the creds-pair rule.
	rec := call(t, h, http.MethodPost, "/api/v1/tenants", admin, `{"name":"X"}`, nil)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != httpx.CodeValidationFailed {
		t.Fatalf("missing fields = %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, h, http.MethodPost, "/api/v1/tenants", admin,
		`{"name":"X","domain":"x.com","microsoftTenantId":"guid","clientId":"only-id"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("lone client id = %d, want 400", rec.Code)
	}

	// Create: 201, connection tested (sample mode → Connected), secret never echoed.
	rec = call(t, h, http.MethodPost, "/api/v1/tenants", admin, newTenant, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	if strings.Contains(raw, "s3cret-value") || strings.Contains(raw, "clientSecret") {
		t.Fatalf("secret material leaked into the response: %s", raw)
	}
	var created model.Tenant
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding created tenant: %v", err)
	}
	if created.ID == "" || created.Status != "Connected" {
		t.Fatalf("created = %+v", created)
	}

	// The stored credentials are available to the Graph layer.
	creds, err := st.TenantCreds(t.Context(), created.ID)
	if err != nil || creds.ClientID != "app-123" || creds.ClientSecret != "s3cret-value" {
		t.Fatalf("stored creds = %+v, %v", creds, err)
	}

	// It shows up in the list alongside the seeded example tenant.
	var tenants []model.Tenant
	call(t, h, http.MethodGet, "/api/v1/tenants", admin, "", &tenants)
	if len(tenants) != 2 {
		t.Fatalf("tenant count = %d, want 2", len(tenants))
	}

	// Deletion is admin-only, cascades grants, and audits.
	if rec := call(t, h, http.MethodDelete, "/api/v1/tenants/ten_1/", tech, "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("tech delete = %d, want 403", rec.Code)
	}
	if rec := call(t, h, http.MethodDelete, "/api/v1/tenants/"+created.ID+"/", admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("admin delete = %d", rec.Code)
	}
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants/"+created.ID+"/", admin, "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("deleted tenant read = %d, want 404", rec.Code)
	}

	if rec := call(t, h, http.MethodDelete, "/api/v1/tenants/ten_1/", admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("delete ten_1 = %d", rec.Code)
	}

	entries, _ := st.Audit(t.Context())
	var sawCreate, sawDelete bool
	for _, e := range entries {
		if e.Action == "tenant.create" && e.Resource == "Fabrikam, Inc." {
			sawCreate = true
		}
		if e.Action == "tenant.delete" && e.Resource == "Contoso Ltd" {
			sawDelete = true
		}
	}
	if !sawCreate || !sawDelete {
		t.Fatalf("audit trail missing tenant.create/tenant.delete (create=%v delete=%v)", sawCreate, sawDelete)
	}
}

func TestTenantHistoryOnboardingStartNow(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)
	body := `{"name":"History Co","domain":"history.example","microsoftTenantId":"history-directory","historyWindow":"start_now","historicalIncidentMode":"recent_24h"}`
	var created struct {
		model.Tenant
		HistoryImport model.SecurityHistoryImport `json:"historyImport"`
	}
	rec := call(t, h, http.MethodPost, "/api/v1/tenants", admin, body, &created)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	if created.HistoryImport.Status != "completed" || created.HistoryImport.Progress != 100 || created.HistoryImport.WindowHours != 0 {
		t.Fatalf("history import = %+v", created.HistoryImport)
	}
	if created.HistoryImport.IncidentCutoffAt.IsZero() {
		t.Fatalf("start-now policy has no incident cutoff: %+v", created.HistoryImport)
	}
	stored, err := st.SecurityHistoryImport(t.Context(), created.ID)
	if err != nil || stored.RequestedWindow != "start_now" {
		t.Fatalf("stored history = %+v, %v", stored, err)
	}

	bad := `{"name":"Bad History","domain":"bad.example","microsoftTenantId":"bad-directory","historyWindow":"thirty_days"}`
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants", admin, bad, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid history window = %d, want 400", rec.Code)
	}
}

// consentDeniedGraph simulates a tenant whose app registration authenticates
// fine but lacks admin-consented application permissions (Graph 403).
type consentDeniedGraph struct {
	graph.Provider
}

func (consentDeniedGraph) TestConnection(context.Context, string) error {
	return &graph.APIError{
		Status: http.StatusForbidden, Code: "Authorization_RequestDenied",
		Message: "Insufficient privileges to complete the operation.", Path: "/organization",
	}
}

func TestTenantConnectionFailureSurfaced(t *testing.T) {
	gp := consentDeniedGraph{graph.NewProvider(graph.Config{}, discardLogger(), nil)}
	h, st := newTestAPIWithGraph(t, gp)
	admin := adminToken(t, h)

	// Create: saved, but the response says why the connection failed.
	rec := call(t, h, http.MethodPost, "/api/v1/tenants", admin,
		`{"name":"Consent Missing","domain":"cm.onmicrosoft.com","microsoftTenantId":"guid-cm"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		model.Tenant
		ConnectionError string `json:"connectionError"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.Status != "Disconnected" {
		t.Fatalf("status = %q, want Disconnected", created.Status)
	}
	if !strings.Contains(created.ConnectionError, "admin consent") ||
		!strings.Contains(created.ConnectionError, "Authorization_RequestDenied") {
		t.Fatalf("connectionError = %q", created.ConnectionError)
	}

	// The test endpoint reports the same reason and persists the status.
	var res map[string]string
	rec = call(t, h, http.MethodPost, "/api/v1/tenants/"+created.ID+"/test", admin, "", &res)
	if rec.Code != http.StatusOK || res["status"] != "Disconnected" {
		t.Fatalf("test = %d %v", rec.Code, res)
	}
	if !strings.Contains(res["error"], "Authorization_RequestDenied") {
		t.Fatalf("test error = %q", res["error"])
	}
	got, _ := st.Tenant(t.Context(), created.ID)
	if got.Status != "Disconnected" || got.LastGraphTest != "just now" {
		t.Fatalf("persisted tenant = %+v", got)
	}

	// The failed test is audited.
	entries, _ := st.Audit(t.Context())
	if entries[0].Action != "tenant.test" || entries[0].Result != "Failed" {
		t.Fatalf("latest audit = %+v", entries[0])
	}

	// Graph errors on normal reads use the Microsoft envelope codes.
	// (Users still comes from the embedded sample provider here, so use a
	// permission-denied stub only for TestConnection — reads stay 200.)
	if rec := call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/users", admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("sample users = %d", rec.Code)
	}
}

func TestSuccessfulTestConnectionPersists(t *testing.T) {
	h, st := newTestAPI(t)
	admin := adminToken(t, h)

	var res map[string]string
	rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/test", admin, "", &res)
	if rec.Code != http.StatusOK || res["status"] != "Connected" || res["error"] != "" {
		t.Fatalf("test = %d %v", rec.Code, res)
	}
	got, _ := st.Tenant(t.Context(), "ten_1")
	if got.LastGraphTest != "just now" {
		t.Fatalf("lastGraphTest = %q, want refreshed", got.LastGraphTest)
	}
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_none/test", admin, "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant test = %d, want 404", rec.Code)
	}
}

func TestCorrelationIDEcho(t *testing.T) {
	h, _ := newTestAPI(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set("X-Correlation-ID", "cor_e2e42")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Correlation-ID"); got != "cor_e2e42" {
		t.Fatalf("echoed correlation id = %q", got)
	}
	// The 401 envelope carries the same id.
	var env httpx.ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decoding envelope: %v", err)
	}
	if env.Error.CorrelationID != "cor_e2e42" {
		t.Fatalf("envelope correlation id = %q", env.Error.CorrelationID)
	}
}
