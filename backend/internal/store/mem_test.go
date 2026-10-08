package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/seed"
)

func TestMemTenants(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	ts, err := m.Tenants(ctx)
	if err != nil || len(ts) != len(seed.Tenants) {
		t.Fatalf("Tenants = %d entries, err %v; want %d", len(ts), err, len(seed.Tenants))
	}

	got, err := m.Tenant(ctx, "ten_1")
	if err != nil || got.Name != "Contoso Ltd" {
		t.Fatalf("Tenant(ten_1) = %+v, %v", got, err)
	}
	if _, err := m.Tenant(ctx, "ten_none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tenant err = %v, want ErrNotFound", err)
	}
}

func TestMemTenantPreflightLifecycle(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	if _, err := m.TenantPreflight(ctx, "ten_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("initial preflight err = %v, want ErrNotFound", err)
	}
	want := model.Preflight{
		Mode: "sample", RanAt: "2026-08-26T04:00:00Z",
		Checks: []model.PreflightCheck{{
			Category: "Security Operations", Area: "Fast identity monitoring",
			Resource: "Microsoft Graph", Permission: "AuditLog.Read.All", Status: "sample",
		}},
	}
	if err := m.UpsertTenantPreflight(ctx, "ten_1", want); err != nil {
		t.Fatalf("UpsertTenantPreflight: %v", err)
	}
	got, err := m.TenantPreflight(ctx, "ten_1")
	if err != nil || got.RanAt != want.RanAt || len(got.Checks) != 1 || got.Checks[0].Category != "Security Operations" {
		t.Fatalf("TenantPreflight = %+v, %v", got, err)
	}
	got.Checks[0].Category = "mutated"
	again, _ := m.TenantPreflight(ctx, "ten_1")
	if again.Checks[0].Category != "Security Operations" {
		t.Fatalf("stored preflight was mutated through returned slice: %+v", again)
	}
	if err := m.UpsertTenantPreflight(ctx, "missing", want); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tenant err = %v, want ErrNotFound", err)
	}
}

func TestMemCreateWorkingSet(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	before, _ := m.WorkingSets(ctx)
	ws, err := m.CreateWorkingSet(ctx, NewWorkingSet{
		Name: "Test Set", Description: "Saved users", TenantID: "ten_1", Tenant: "Contoso Ltd",
		UserIDs: []string{"u1", "u2", "u3"}, CreatedBy: "T. Tester",
	})
	if err != nil {
		t.Fatalf("CreateWorkingSet: %v", err)
	}
	if ws.ID == "" || ws.Items != 3 || ws.CreatedBy != "T. Tester" || ws.TenantID != "ten_1" || ws.Description != "Saved users" {
		t.Fatalf("created = %+v", ws)
	}
	ws.UserIDs[0] = "mutated"

	after, _ := m.WorkingSets(ctx)
	if len(after) != len(before)+1 {
		t.Fatalf("working sets = %d, want %d", len(after), len(before)+1)
	}
	// Newest first, matching the UI's ordering expectation.
	if after[0].ID != ws.ID {
		t.Fatalf("first entry = %s, want %s", after[0].ID, ws.ID)
	}
	if got := after[0].UserIDs; len(got) != 3 || got[0] != "u1" {
		t.Fatalf("persisted user IDs = %v, want independent [u1 u2 u3]", got)
	}
	fetched, err := m.WorkingSet(ctx, ws.ID)
	if err != nil || fetched.Name != "Test Set" {
		t.Fatalf("WorkingSet = %+v, %v", fetched, err)
	}
	updated, err := m.UpdateWorkingSet(ctx, ws.ID, WorkingSetUpdate{
		Name: "Updated Set", Description: "Updated users", UserIDs: []string{"u2", "u4"},
	})
	if err != nil || updated.Name != "Updated Set" || updated.Items != 2 || len(updated.UserIDs) != 2 {
		t.Fatalf("UpdateWorkingSet = %+v, %v", updated, err)
	}
	updated.UserIDs[0] = "mutated"
	fetched, _ = m.WorkingSet(ctx, ws.ID)
	if fetched.UserIDs[0] != "u2" {
		t.Fatalf("stored update mutated through result: %+v", fetched)
	}
	if _, err := m.UpdateWorkingSet(ctx, "missing", WorkingSetUpdate{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing update err = %v, want ErrNotFound", err)
	}
}

func TestMemStorylineUpsertPreservesAnalystStateAndCopiesEvidence(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	storyline := model.SecurityStoryline{
		ID: "story_1", CorrelationKey: "account_takeover|ten_1|aaron@example.com",
		PackID: "account_takeover_bec", Title: "Account takeover progression",
		Status: model.SecurityTriageNew, RiskScore: 82, FirstSeen: now.Add(-time.Hour), LastSeen: now,
		TenantIDs: []string{"ten_1"}, DetectionIDs: []string{"det_1", "det_2"},
		EventIDs: []string{"evt_1", "evt_2"}, Reasons: []string{"Two independent stages"},
		Entities: []model.SecurityStorylineEntity{{Type: "account", Key: "ten_1|account|aaron@example.com", Label: "aaron@example.com"}},
	}
	if err := m.UpsertSecurityStorylines(ctx, []model.SecurityStoryline{storyline}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpdateSecurityStorylineState(ctx, storyline.ID, model.SecurityTriageInProgress, "Aisha Rivera", "Aisha Rivera"); err != nil {
		t.Fatal(err)
	}

	storyline.RiskScore = 91
	storyline.Status = model.SecurityTriageNew
	storyline.Owner = ""
	storyline.EventIDs = append(storyline.EventIDs, "evt_late")
	if err := m.UpsertSecurityStorylines(ctx, []model.SecurityStoryline{storyline}); err != nil {
		t.Fatal(err)
	}
	got, err := m.SecurityStoryline(ctx, storyline.ID)
	if err != nil || got.Status != model.SecurityTriageInProgress || got.Owner != "Aisha Rivera" || got.RiskScore != 91 || len(got.EventIDs) != 3 {
		t.Fatalf("storyline = %+v, err=%v", got, err)
	}
	got.EventIDs[0] = "mutated"
	again, _ := m.SecurityStoryline(ctx, storyline.ID)
	if again.EventIDs[0] != "evt_1" {
		t.Fatalf("stored evidence mutated through returned value: %+v", again.EventIDs)
	}
}

func TestMemJobs(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	j, err := m.CreateJob(ctx, model.Job{Type: "Test Job", Status: "Queued"})
	if err != nil || j.ID == "" {
		t.Fatalf("CreateJob = %+v, %v", j, err)
	}

	if err := m.UpdateJobStatus(ctx, j.ID, "Completed", 100); err != nil {
		t.Fatalf("UpdateJobStatus: %v", err)
	}
	if err := m.AcknowledgeJob(ctx, j.ID); err != nil {
		t.Fatalf("AcknowledgeJob: %v", err)
	}
	jobs, _ := m.Jobs(ctx)
	for _, got := range jobs {
		if got.ID == j.ID {
			if got.Status != "Completed" || got.Progress != 100 || !got.Acknowledged {
				t.Fatalf("updated job = %+v", got)
			}
			return
		}
	}
	t.Fatal("created job not listed")
}

func TestMemUpdateJobStatusMissing(t *testing.T) {
	m := NewMem()
	if err := m.UpdateJobStatus(context.Background(), "job_none", "Running", 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestMemThreatLockerCleanupOperationLifecycle(t *testing.T) {
	ctx := context.Background()
	m := NewMem()
	started := model.TLAppCleanupOperation{
		ID:          "tlop_1",
		TenantID:    "ten_1",
		Status:      model.TLCleanupSubmitted,
		RequestedBy: "Admin User",
		Fingerprint: "cleanup:abc123",
		CreatedAt:   time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC),
	}
	if _, err := m.CreateTLAppCleanupOperation(ctx, started); err != nil {
		t.Fatalf("CreateTLAppCleanupOperation: %v", err)
	}
	if _, err := m.CreateTLAppCleanupOperation(ctx, started); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate active operation = %v, want ErrConflict", err)
	}
	active, err := m.ActiveTLAppCleanupOperation(ctx, started.Fingerprint)
	if err != nil || active.ID != started.ID {
		t.Fatalf("ActiveTLAppCleanupOperation = %+v, %v", active, err)
	}

	result := model.TLAppCleanupResult{Status: "Completed", RetainedAppID: "app_parent"}
	if err := m.UpdateTLAppCleanupOperation(ctx, started.ID, model.TLCleanupVerified, result, ""); err != nil {
		t.Fatalf("UpdateTLAppCleanupOperation: %v", err)
	}
	if _, err := m.ActiveTLAppCleanupOperation(ctx, started.Fingerprint); !errors.Is(err, ErrNotFound) {
		t.Fatalf("verified operation remained active: %v", err)
	}
	operations, err := m.TLAppCleanupOperations(ctx, "ten_1")
	if err != nil || len(operations) != 1 {
		t.Fatalf("TLAppCleanupOperations = %+v, %v", operations, err)
	}
	if operations[0].Status != model.TLCleanupVerified || operations[0].Result.RetainedAppID != "app_parent" {
		t.Fatalf("updated operation = %+v", operations[0])
	}
}

func TestMemAppendAuditDefaults(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	if err := m.AppendAudit(ctx, model.AuditEntry{Actor: "T. Tester", Action: "test.action"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	entries, _ := m.Audit(ctx)
	got := entries[0] // newest first
	if got.Action != "test.action" {
		t.Fatalf("first audit entry = %+v", got)
	}
	if got.ID == "" || got.Timestamp == "" {
		t.Fatalf("id/timestamp not defaulted: %+v", got)
	}
}

func TestMemSecurityIncidentStateLifecycle(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	receivedAt := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	observed, err := m.ObserveSecurityIncident(ctx, model.SecurityIncidentState{
		TenantID: "ten_1", IncidentID: "incident_observed", Status: model.SecurityTriageNew,
		ReceivedAt: receivedAt, UpdatedBy: "RTM monitoring",
	})
	if err != nil || !observed.ReceivedAt.Equal(receivedAt) {
		t.Fatalf("ObserveSecurityIncident = %+v, %v", observed, err)
	}
	observedAgain, err := m.ObserveSecurityIncident(ctx, model.SecurityIncidentState{
		TenantID: "ten_1", IncidentID: "incident_observed", Status: model.SecurityTriageResolved,
		ReceivedAt: receivedAt.Add(time.Hour), UpdatedBy: "RTM monitoring",
	})
	if err != nil || !observedAgain.ReceivedAt.Equal(receivedAt) || observedAgain.Status != model.SecurityTriageNew {
		t.Fatalf("second observation changed first receipt/state = %+v, %v", observedAgain, err)
	}

	state, err := m.UpsertSecurityIncidentState(ctx, model.SecurityIncidentState{
		TenantID: "ten_1", IncidentID: "incident_42", Status: model.SecurityTriageInProgress,
		Owner: "Aisha Rivera", UpdatedBy: "Aisha Rivera",
	})
	if err != nil {
		t.Fatalf("UpsertSecurityIncidentState: %v", err)
	}
	if state.UpdatedAt.IsZero() || state.ReceivedAt.IsZero() {
		t.Fatal("updatedAt/receivedAt were not defaulted")
	}

	state.Status = model.SecurityTriageResolved
	if _, err := m.UpsertSecurityIncidentState(ctx, state); err != nil {
		t.Fatalf("update SecurityIncidentState: %v", err)
	}
	states, err := m.SecurityIncidentStates(ctx)
	if err != nil || len(states) != 2 {
		t.Fatalf("SecurityIncidentStates = %+v, %v", states, err)
	}
	triagedFound := false
	for _, item := range states {
		if item.IncidentID == "incident_42" && item.Status == model.SecurityTriageResolved {
			triagedFound = true
		}
	}
	if !triagedFound {
		t.Fatalf("resolved triage state not retained: %+v", states)
	}
	if _, err := m.UpsertSecurityIncidentState(ctx, model.SecurityIncidentState{
		TenantID: "ten_missing", IncidentID: "incident_42", Status: model.SecurityTriageNew,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown tenant err = %v, want ErrNotFound", err)
	}
}

func TestMemChangeLifecycle(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	// Nothing is seeded: change history only holds real actions.
	if cs, _ := m.Changes(ctx); len(cs) != 0 {
		t.Fatalf("seeded changes = %d, want 0", len(cs))
	}

	err := m.AppendChange(ctx, model.ChangeDetail{
		Change: model.Change{
			Timestamp: "2026-07-02 10:00", Technician: "T. Tester", Tenant: "Contoso Ltd",
			Action: "Added 2 members", Target: "Sales", Status: "Completed", Revert: "Available",
		},
		RevertEligible: true, RevertPayload: `{"action":"remove_from_group"}`,
		Before: []string{"members: 4"}, After: []string{"members: 6"},
		ExecutionLog: []string{"ok"},
	})
	if err != nil {
		t.Fatalf("AppendChange: %v", err)
	}
	cs, _ := m.Changes(ctx)
	if len(cs) != 1 || cs[0].ID == "" {
		t.Fatalf("changes = %+v", cs)
	}
	d, err := m.Change(ctx, cs[0].ID)
	if err != nil || !d.RevertEligible || d.RevertPayload == "" || d.Before[0] != "members: 4" {
		t.Fatalf("detail = %+v, %v", d, err)
	}

	if err := m.UpdateChangeRevert(ctx, cs[0].ID, "Reverted"); err != nil {
		t.Fatalf("UpdateChangeRevert: %v", err)
	}
	d, _ = m.Change(ctx, cs[0].ID)
	if d.Revert != "Reverted" {
		t.Fatalf("revert = %q", d.Revert)
	}

	if _, err := m.Change(ctx, "chg_none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing change err = %v, want ErrNotFound", err)
	}
}

func TestMemAccounts(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	acct, err := m.AccountByEmail(ctx, "aisha.rivera@rarity.io")
	if err != nil || acct.ID != "tech_2" || acct.IsAdmin {
		t.Fatalf("AccountByEmail = %+v, %v", acct, err)
	}
	if _, err := m.AccountByEmail(ctx, "nobody@rarity.io"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing account err = %v, want ErrNotFound", err)
	}
}

func TestMemAppSettingValue(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	if err := m.UpdateAppSettingValue(ctx, "session_timeout", "480"); err != nil {
		t.Fatalf("UpdateAppSettingValue: %v", err)
	}
	settings, err := m.AppSettings(ctx)
	if err != nil {
		t.Fatalf("AppSettings: %v", err)
	}
	for _, setting := range settings {
		if setting.Key == "session_timeout" {
			if setting.Value != "480" {
				t.Fatalf("session timeout = %q, want 480", setting.Value)
			}
			return
		}
	}
	t.Fatal("session_timeout setting not found")
}

func TestMemRefreshTokenLifecycle(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	if jti, _ := m.CurrentRefreshToken(ctx, "tech_1"); jti != "" {
		t.Fatalf("initial jti = %q, want empty", jti)
	}
	if err := m.SetRefreshToken(ctx, "tech_1", "jti_abc"); err != nil {
		t.Fatalf("SetRefreshToken: %v", err)
	}
	if jti, _ := m.CurrentRefreshToken(ctx, "tech_1"); jti != "jti_abc" {
		t.Fatalf("jti = %q, want jti_abc", jti)
	}
	if err := m.ClearRefreshToken(ctx, "tech_1"); err != nil {
		t.Fatalf("ClearRefreshToken: %v", err)
	}
	if jti, _ := m.CurrentRefreshToken(ctx, "tech_1"); jti != "" {
		t.Fatalf("cleared jti = %q, want empty", jti)
	}
}

func TestMemTenantLifecycle(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	created, err := m.CreateTenant(ctx, NewTenant{
		Name: "Fabrikam, Inc.", Domain: "fabrikam.com", MicrosoftTenantID: "guid-1",
		ClientID: "app-1", ClientSecret: "secret-1",
	})
	if err != nil || created.ID == "" || created.Status != "Disconnected" {
		t.Fatalf("CreateTenant = %+v, %v", created, err)
	}

	// Credentials round-trip for the Graph layer.
	creds, err := m.TenantCreds(ctx, created.ID)
	if err != nil || creds.ClientID != "app-1" || creds.ClientSecret != "secret-1" || creds.MicrosoftTenantID != "guid-1" {
		t.Fatalf("TenantCreds = %+v, %v", creds, err)
	}
	// Seeded tenants fall back to their record (authority only, no app creds).
	seeded, err := m.TenantCreds(ctx, "ten_1")
	if err != nil || seeded.MicrosoftTenantID == "" || seeded.ClientID != "" {
		t.Fatalf("seeded TenantCreds = %+v, %v", seeded, err)
	}

	if err := m.UpdateTenantStatus(ctx, created.ID, "Connected", "just now"); err != nil {
		t.Fatalf("UpdateTenantStatus: %v", err)
	}
	got, _ := m.Tenant(ctx, created.ID)
	if got.Status != "Connected" || got.LastGraphTest != "just now" {
		t.Fatalf("updated tenant = %+v", got)
	}
	if _, err := m.CreateSecurityDetectionRule(ctx, model.SecurityDetectionRule{ID: "tenant-rule", RuleID: "custom_tenant", Name: "Tenant rule", DetectionType: "direct", Severity: "Low", Confidence: "medium", Scope: "tenant", TenantID: "ten_1", UpdatedBy: "Admin"}); err != nil {
		t.Fatalf("CreateSecurityDetectionRule: %v", err)
	}

	if err := m.DeleteTenant(ctx, "ten_1"); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if _, err := m.Tenant(ctx, "ten_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted tenant err = %v, want ErrNotFound", err)
	}
	if _, err := m.SecurityDetectionRule(ctx, "tenant-rule"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant rule survived tenant deletion: %v", err)
	}
	if err := m.DeleteTenant(ctx, "ten_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete err = %v, want ErrNotFound", err)
	}
}

func TestMemUpdateTenantPreservesBlankSecretsAndClearsExplicitly(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	created, err := m.CreateTenant(ctx, NewTenant{
		Name: "Fabrikam", Domain: "fabrikam.com", MicrosoftTenantID: "dir-1",
		ClientID: "graph-app", ClientSecret: "graph-secret",
		ExchangeClientID: "exo-app", ExchangeClientSecret: "exo-secret",
		SharePointAdminURL: "https://fabrikam-admin.sharepoint.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := m.UpdateTenant(ctx, created.ID, TenantUpdate{
		Name: strPtr("Fabrikam Updated"), SharePointAdminURL: strPtr("https://new-admin.sharepoint.com"),
	})
	if err != nil {
		t.Fatalf("UpdateTenant: %v", err)
	}
	creds, _ := m.TenantCreds(ctx, created.ID)
	if renamed.Name != "Fabrikam Updated" || creds.ClientSecret != "graph-secret" ||
		creds.ExchangeClientSecret != "exo-secret" {
		t.Fatalf("metadata update lost credentials: tenant=%+v creds=%+v", renamed, creds)
	}
	_, err = m.UpdateTenant(ctx, created.ID, TenantUpdate{ClearGraph: true, ClearExchange: true})
	if err != nil {
		t.Fatalf("clear credentials: %v", err)
	}
	creds, _ = m.TenantCreds(ctx, created.ID)
	if creds.ClientID != "" || creds.ClientSecret != "" || creds.ExchangeClientID != "" ||
		creds.ExchangeClientSecret != "" {
		t.Fatalf("explicit clear retained credentials: %+v", creds)
	}
}

func strPtr(value string) *string { return &value }

func TestMemSetPassword(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	acct, err := m.AccountByID(ctx, "admin_1")
	if err != nil || !acct.MustChange {
		t.Fatalf("AccountByID(admin_1) = %+v, %v", acct, err)
	}

	if err := m.SetPassword(ctx, "admin_1", "new-hash"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	rotated, _ := m.AccountByID(ctx, "admin_1")
	if rotated.PasswordHash != "new-hash" || rotated.MustChange || rotated.CredentialVersion != acct.CredentialVersion+1 {
		t.Fatalf("rotated account = %+v", rotated)
	}
	if err := m.SetRefreshToken(ctx, "admin_1", "refresh-before-reset"); err != nil {
		t.Fatalf("SetRefreshToken: %v", err)
	}
	if err := m.ResetPassword(ctx, "admin_1", "temporary-hash"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	reset, _ := m.AccountByID(ctx, "admin_1")
	if reset.PasswordHash != "temporary-hash" || !reset.MustChange || reset.CredentialVersion != rotated.CredentialVersion+1 {
		t.Fatalf("reset account = %+v", reset)
	}
	if refresh, err := m.CurrentRefreshToken(ctx, "admin_1"); err != nil || refresh != "" {
		t.Fatalf("refresh after reset = %q, %v", refresh, err)
	}

	if err := m.SetPassword(ctx, "acct_none", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing account err = %v, want ErrNotFound", err)
	}
	if err := m.ResetPassword(ctx, "acct_none", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing reset account err = %v, want ErrNotFound", err)
	}
}

// Listing methods must return copies: mutating a returned slice must not
// corrupt the store.
func TestMemReturnsCopies(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	ts, _ := m.Tenants(ctx)
	ts[0].Name = "MUTATED"
	fresh, _ := m.Tenants(ctx)
	if fresh[0].Name == "MUTATED" {
		t.Fatal("Tenants returned a shared slice")
	}
}

func TestMemSharePointSnapshotLifecycle(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	scan, err := m.CreateSharePointScan(ctx, model.SharePointScan{
		TenantID: "ten_1", Scope: "sites", Status: "queued", Trigger: "manual",
		StartedBy: "A. Admin",
	})
	if err != nil || scan.ID == "" {
		t.Fatalf("CreateSharePointScan = %+v, %v", scan, err)
	}

	nodes := []model.SharePointInventoryNode{
		{
			ID: "site_1", TenantID: "ten_1", ScanID: scan.ID, Kind: "site",
			Name: "Operations", Path: "/", SizeBytes: 300, FileCount: 2,
		},
		{
			ID: "folder_1", TenantID: "ten_1", ScanID: scan.ID, Kind: "folder",
			ParentID: "site_1", SiteID: "site_1", Name: "Runbooks",
			Path: "/Shared Documents/Runbooks", SizeBytes: 300, FileCount: 2,
			HasUniquePermissions: true,
		},
	}
	completed := scan
	completed.Status = "completed"
	completed.CompletedAt = "2026-07-31T12:00:00Z"
	completed.SiteCount = 1
	completed.FolderCount = 1
	completed.FileCount = 2
	completed.TotalBytes = 300
	completed.UniquePermissionCount = 1
	completed.Coverage = "complete"
	if err := m.CompleteSharePointScan(ctx, completed, nodes); err != nil {
		t.Fatalf("CompleteSharePointScan: %v", err)
	}

	got, err := m.SharePointInventory(ctx, "ten_1", "sites")
	if err != nil {
		t.Fatalf("SharePointInventory: %v", err)
	}
	if got.Scan.ID != scan.ID || got.Scan.Status != "completed" || len(got.Nodes) != 2 {
		t.Fatalf("inventory = %+v", got)
	}
	if !got.Nodes[1].HasUniquePermissions || got.Nodes[1].SizeBytes != 300 {
		t.Fatalf("folder = %+v", got.Nodes[1])
	}

	history, err := m.SharePointScans(ctx, "ten_1")
	if err != nil || len(history) != 1 || history[0].ID != scan.ID {
		t.Fatalf("SharePointScans = %+v, %v", history, err)
	}

	// Returned snapshots are copies; callers cannot mutate persisted history.
	got.Nodes[0].Name = "MUTATED"
	fresh, _ := m.SharePointInventory(ctx, "ten_1", "sites")
	if fresh.Nodes[0].Name == "MUTATED" {
		t.Fatal("SharePointInventory returned shared node state")
	}
}

func TestMemSecurityEventSearchAndRuleRevisions(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	now := time.Now().UTC()
	events := []model.SecurityAuditEvent{
		{ID: "evt-new", TenantID: "ten_1", ProviderRecordID: "provider-new", Workload: "Exchange", Operation: "Set-Mailbox", Actor: "admin@example.com", ClientIP: "203.0.113.9", ObjectID: "finance@example.com", ResultStatus: "Succeeded", OccurredAt: now, IngestedAt: now, Raw: json.RawMessage(`{"safe":true}`)},
		{ID: "evt-old", TenantID: "ten_1", ProviderRecordID: "provider-old", Workload: "SharePoint", Operation: "FileDownloaded", Actor: "user@example.com", OccurredAt: now.Add(-time.Hour), IngestedAt: now, Raw: json.RawMessage(`{}`)},
	}
	if _, err := m.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: "Audit.General"}, events, nil); err != nil {
		t.Fatal(err)
	}
	got, more, err := m.SearchSecurityAuditEvents(ctx, model.SecurityAuditEventSearch{Query: "finance", From: now.Add(-2 * time.Hour), To: now.Add(time.Hour), Limit: 1})
	if err != nil || more || len(got) != 1 || got[0].ID != "evt-new" {
		t.Fatalf("search = %+v more=%v err=%v", got, more, err)
	}
	got[0].Raw[0] = 'x'
	detail, _ := m.SecurityAuditEvent(ctx, "ten_1", "evt-new")
	if detail.Raw[0] == 'x' {
		t.Fatal("search returned shared raw evidence")
	}
	batch, err := m.SecurityAuditEventsByIDs(ctx, []string{"evt-old", "missing"})
	if err != nil || len(batch) != 1 || batch[0].ID != "evt-old" {
		t.Fatalf("event batch = %+v, %v", batch, err)
	}

	rule := model.SecurityDetectionRule{ID: "rule-1", RuleID: "custom_test", Name: "Custom test", DetectionType: "direct", Severity: "Medium", Confidence: "medium", Scope: "global", Definition: model.SecurityRuleDefinition{Operations: []string{"Set-Mailbox"}}, UpdatedBy: "Admin"}
	created, err := m.CreateSecurityDetectionRule(ctx, rule)
	if err != nil || created.Revision != 1 {
		t.Fatalf("create rule = %+v, %v", created, err)
	}
	created.Enabled, created.UpdatedBy = true, "Second Admin"
	updated, err := m.UpdateSecurityDetectionRule(ctx, created, created.Revision)
	if err != nil || updated.Revision != 2 || !updated.Enabled {
		t.Fatalf("update rule = %+v, %v", updated, err)
	}
	if _, err := m.UpdateSecurityDetectionRule(ctx, created, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update err = %v", err)
	}
	revisions, _ := m.SecurityDetectionRuleRevisions(ctx, rule.ID)
	if len(revisions) != 2 || revisions[0].Revision != 2 || revisions[1].Snapshot.Enabled {
		t.Fatalf("revisions = %+v", revisions)
	}
}

func TestMemSecurityEventDeduplicatesAcrossSources(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	now := time.Now().UTC()
	fast := model.SecurityAuditEvent{ID: "evt-shared", TenantID: "ten_1", ProviderRecordID: "microsoft-record", OccurredAt: now.Add(-time.Minute), AvailableAt: now.Add(-30 * time.Second), IngestedAt: now.Add(-30 * time.Second), Sources: []string{"entra_graph"}, Raw: json.RawMessage(`{"source":"graph"}`)}
	backfill := fast
	backfill.AvailableAt, backfill.IngestedAt, backfill.Sources = now, now, []string{"m365_audit"}
	if inserted, err := m.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: "Graph.SignIn"}, []model.SecurityAuditEvent{fast}, nil); err != nil || inserted != 1 {
		t.Fatalf("fast insert=%d err=%v", inserted, err)
	}
	if inserted, err := m.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: "Audit.AzureActiveDirectory"}, []model.SecurityAuditEvent{backfill}, nil); err != nil || inserted != 0 {
		t.Fatalf("backfill insert=%d err=%v", inserted, err)
	}
	got, err := m.SecurityAuditEvent(ctx, "ten_1", "evt-shared")
	if err != nil || len(got.Sources) != 2 || !got.AvailableAt.Equal(fast.AvailableAt) {
		t.Fatalf("event=%+v err=%v", got, err)
	}
}

func TestMemSecurityEventSemanticDeduplication(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	now := time.Now().UTC()
	fast := model.SecurityAuditEvent{
		ID: "evt-fast", TenantID: "ten_1", ProviderRecordID: "graph-record",
		ContentType: "Graph.SignIn", Workload: "EntraID", Operation: "UserLoggedIn",
		Actor: "analyst@example.com", ClientIP: "203.0.113.10", ObjectID: "app-1",
		ResultStatus: "Succeeded", OccurredAt: now, AvailableAt: now.Add(time.Second),
		IngestedAt: now.Add(2 * time.Second), Sources: []string{"entra_graph"},
		Raw: json.RawMessage(`{"source":"graph"}`),
	}
	backfill := fast
	backfill.ID, backfill.ProviderRecordID = "evt-audit", "audit-record"
	backfill.ContentType, backfill.Workload = "Audit.AzureActiveDirectory", "AzureActiveDirectory"
	backfill.OccurredAt = now.Add(3 * time.Second)
	backfill.AvailableAt, backfill.IngestedAt = now.Add(time.Minute), now.Add(time.Minute)
	backfill.Sources, backfill.Raw = []string{"m365_audit"}, json.RawMessage(`{"source":"audit","detail":"authoritative"}`)
	fastDetection := model.SecurityNativeDetection{ID: "det-fast", TenantID: "ten_1", EventID: fast.ID, EventIDs: []string{fast.ID}, RuleID: "successful_sign_in", RuleVersion: 1, OccurredAt: fast.OccurredAt}
	backfillDetection := fastDetection
	backfillDetection.ID, backfillDetection.EventID, backfillDetection.EventIDs = "det-audit", backfill.ID, []string{backfill.ID}

	if inserted, err := m.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: fast.ContentType}, []model.SecurityAuditEvent{fast}, []model.SecurityNativeDetection{fastDetection}); err != nil || inserted != 1 {
		t.Fatalf("fast insert=%d err=%v", inserted, err)
	}
	if inserted, err := m.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: backfill.ContentType}, []model.SecurityAuditEvent{backfill}, nil); err != nil || inserted != 0 {
		t.Fatalf("backfill insert=%d err=%v", inserted, err)
	}
	if inserted, err := m.StoreSecurityNativeDetections(ctx, []model.SecurityNativeDetection{backfillDetection}); err != nil || inserted != 0 {
		t.Fatalf("backfill detection insert=%d err=%v", inserted, err)
	}
	events, more, err := m.SearchSecurityAuditEvents(ctx, model.SecurityAuditEventSearch{From: now.Add(-time.Minute), To: now.Add(2 * time.Minute), Limit: 10})
	if err != nil || more || len(events) != 1 {
		t.Fatalf("events=%+v more=%v err=%v", events, more, err)
	}
	if events[0].ID != fast.ID || len(events[0].Sources) != 2 || string(events[0].Raw) != string(backfill.Raw) || !events[0].AvailableAt.Equal(fast.AvailableAt) {
		t.Fatalf("canonical event=%+v", events[0])
	}
	evidence, err := m.SecurityAuditEventEvidence(ctx, "ten_1", fast.ID)
	if err != nil || len(evidence) != 2 || string(evidence[0].Raw) != string(fast.Raw) || string(evidence[1].Raw) != string(backfill.Raw) {
		t.Fatalf("source evidence=%+v err=%v", evidence, err)
	}
	repolled := fast
	repolled.AvailableAt, repolled.IngestedAt = now.Add(2*time.Hour), now.Add(2*time.Hour)
	repolled.Raw = json.RawMessage(`{"source":"graph-repolled"}`)
	if inserted, err := m.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: fast.ContentType}, []model.SecurityAuditEvent{repolled}, nil); err != nil || inserted != 0 {
		t.Fatalf("repolled fast insert=%d err=%v", inserted, err)
	}
	evidence, err = m.SecurityAuditEventEvidence(ctx, "ten_1", fast.ID)
	if err != nil || !evidence[0].AvailableAt.Equal(fast.AvailableAt) || string(evidence[0].Raw) != string(repolled.Raw) {
		t.Fatalf("refreshed source evidence=%+v err=%v", evidence, err)
	}
	detections, err := m.SecurityNativeDetections(ctx)
	if err != nil || len(detections) != 1 || detections[0].EventID != fast.ID {
		t.Fatalf("detections=%+v err=%v", detections, err)
	}

	repeated := fast
	repeated.ID, repeated.ProviderRecordID = "evt-later", "graph-later"
	repeated.OccurredAt = now.Add(11 * time.Second)
	if inserted, err := m.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: repeated.ContentType}, []model.SecurityAuditEvent{repeated}, nil); err != nil || inserted != 1 {
		t.Fatalf("later insert=%d err=%v", inserted, err)
	}
}
