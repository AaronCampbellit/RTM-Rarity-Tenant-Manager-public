package securityops

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
)

type scriptedProvider struct {
	graph.Provider
	feeds   map[string]model.SecurityIncidentFeed
	details map[string]model.SecurityIncidentDetail
	errs    map[string]error
}

func (p *scriptedProvider) SecurityIncidents(_ context.Context, tenantID string) (model.SecurityIncidentFeed, error) {
	if err := p.errs[tenantID]; err != nil {
		return model.SecurityIncidentFeed{}, err
	}
	return p.feeds[tenantID], nil
}

func (p *scriptedProvider) SecurityIncident(_ context.Context, tenantID, incidentID string) (model.SecurityIncidentDetail, error) {
	if err := p.errs[tenantID]; err != nil {
		return model.SecurityIncidentDetail{}, err
	}
	return p.details[tenantID+"|"+incidentID], nil
}

func securityTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSnapshotKeepsHealthyTenantsWhenOneFails(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	second, err := st.CreateTenant(ctx, store.NewTenant{Name: "Fabrikam", Domain: "fabrikam.example", MicrosoftTenantID: "directory-2"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	base := graph.NewProvider(graph.Config{}, securityTestLogger(), nil)
	provider := &scriptedProvider{
		Provider: base,
		feeds: map[string]model.SecurityIncidentFeed{
			"ten_1": {Mode: "live", Incidents: []model.SecurityIncident{{
				ID: "42", Title: "High impact incident", Severity: "Critical",
				Status: model.SecurityTriageNew, ProviderStatus: "active",
				UpdatedAt: "2026-08-23T10:00:00Z",
			}}},
		},
		errs: map[string]error{
			second.ID: &graph.APIError{Status: http.StatusForbidden, Path: "/security/incidents"},
		},
	}
	service := New(st, provider, securityTestLogger())

	snapshot, err := service.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Summary.TenantsCovered != 1 || snapshot.Summary.TenantsTotal != 2 || snapshot.Summary.IngestionHealth != 50 {
		t.Fatalf("summary = %+v", snapshot.Summary)
	}
	if snapshot.Summary.Open != 1 || snapshot.Summary.Critical != 1 || len(snapshot.Incidents) != 1 {
		t.Fatalf("incident summary = %+v incidents=%+v", snapshot.Summary, snapshot.Incidents)
	}
	firstReceipt := snapshot.Incidents[0].RTMReceivedAt
	if firstReceipt == "" {
		t.Fatal("RTM receipt time was not recorded")
	}
	refreshed, err := service.Snapshot(ctx)
	if err != nil || refreshed.Incidents[0].RTMReceivedAt != firstReceipt {
		t.Fatalf("RTM receipt time changed across refresh: first=%q refreshed=%q err=%v", firstReceipt, refreshed.Incidents[0].RTMReceivedAt, err)
	}
	if snapshot.Connectors[0].Status != "degraded" || snapshot.Connectors[0].AttentionTenants != 1 {
		t.Fatalf("connector = %+v", snapshot.Connectors[0])
	}
	foundMissing := false
	for _, coverage := range snapshot.Coverage {
		if coverage.TenantID == second.ID && coverage.ConnectorKey == defenderConnectorKey && coverage.Status == "missing_permission" {
			foundMissing = true
		}
	}
	if !foundMissing || len(snapshot.Warnings) != 1 {
		t.Fatalf("coverage = %+v warnings=%v", snapshot.Coverage, snapshot.Warnings)
	}
}

func TestSnapshotAndDetailIncludeRTMNativeDetection(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	now := time.Date(2026, 8, 24, 20, 0, 0, 0, time.UTC)
	event := model.SecurityAuditEvent{
		ID: "sae_native", TenantID: "ten_1", ProviderRecordID: "record-native",
		ContentType: "Audit.Exchange", Workload: "Exchange", Operation: "Set-Mailbox",
		Actor: "admin@contoso.com", ObjectID: "finance@contoso.com", OccurredAt: now, IngestedAt: now,
		Raw: []byte(`{"Id":"record-native"}`),
	}
	detection := model.SecurityNativeDetection{
		ID: "rta_native", TenantID: "ten_1", EventID: event.ID, RuleID: "suspicious_mail_forwarding",
		RuleVersion: 1, Title: "Mailbox forwarding changed", Description: "Review it.", Severity: "High",
		OccurredAt: now, CreatedAt: now, Entities: []model.SecurityEntity{{Type: "account", Label: event.Actor}},
	}
	if _, err := st.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{
		TenantID: "ten_1", ContentType: "Audit.Exchange", Status: "sample", Mode: "sample",
		CursorEnd: now, LastPolledAt: now,
	}, []model.SecurityAuditEvent{event}, []model.SecurityNativeDetection{detection}); err != nil {
		t.Fatal(err)
	}
	provider := &scriptedProvider{Provider: graph.NewProvider(graph.Config{}, securityTestLogger(), nil), feeds: map[string]model.SecurityIncidentFeed{
		"ten_1": {Mode: "sample", Incidents: []model.SecurityIncident{}},
	}, errs: map[string]error{}}
	service := New(st, provider, securityTestLogger())
	snapshot, err := service.Snapshot(ctx)
	if err != nil || len(snapshot.Incidents) != 1 || snapshot.Incidents[0].Source != "RTM M365 Audit" {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	detail, err := service.Incident(ctx, "ten_1", "rta_native")
	if err != nil || len(detail.Alerts) != 1 || len(detail.Timeline) != 1 || detail.Timeline[0].ID != event.ID || detail.Evidence == nil || detail.Evidence.Actor != event.Actor || detail.Evidence.Operation != event.Operation || detail.Remediation.Category != "Mailbox persistence or mail-flow change" {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}
	if snapshot.Incidents[0].Evidence == nil || snapshot.Incidents[0].Evidence.Target != event.ObjectID {
		t.Fatalf("snapshot evidence=%+v", snapshot.Incidents[0].Evidence)
	}
	if snapshot.Incidents[0].RTMReceivedAt != detection.CreatedAt.Format(time.RFC3339) || detail.RTMReceivedAt != detection.CreatedAt.Format(time.RFC3339) {
		t.Fatalf("native RTM receipt snapshot=%q detail=%q", snapshot.Incidents[0].RTMReceivedAt, detail.RTMReceivedAt)
	}
}

func TestStorylineDetailReturnsCompleteOrderedEvidenceAndTriage(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	now := time.Date(2026, 8, 26, 16, 0, 0, 0, time.UTC)
	events := []model.SecurityAuditEvent{
		{ID: "evt_signin", TenantID: "ten_1", ProviderRecordID: "record-signin", ContentType: "Audit.AzureActiveDirectory", Workload: "Entra ID", Operation: "UserLoggedIn", Actor: "aaron@contoso.com", ClientIP: "203.0.113.10", ResultStatus: "Succeeded", OccurredAt: now.Add(-10 * time.Minute), IngestedAt: now, Raw: []byte(`{"Id":"record-signin"}`)},
		{ID: "evt_rule", TenantID: "ten_1", ProviderRecordID: "record-rule", ContentType: "Audit.Exchange", Workload: "Exchange", Operation: "New-InboxRule", Actor: "aaron@contoso.com", ObjectID: "aaron@contoso.com", ResultStatus: "Succeeded", OccurredAt: now, IngestedAt: now, Raw: []byte(`{"Id":"record-rule"}`)},
	}
	detections := []model.SecurityNativeDetection{
		{ID: "det_signin", TenantID: "ten_1", EventID: events[0].ID, EventIDs: []string{events[0].ID}, RuleID: "failed_logins_then_success", RuleVersion: 1, Title: "Failed attempts followed by success", Severity: "High", Confidence: "high", OccurredAt: events[0].OccurredAt, CreatedAt: now},
		{ID: "det_rule", TenantID: "ten_1", EventID: events[1].ID, EventIDs: []string{events[1].ID}, RuleID: "inbox_rule_change", RuleVersion: 1, Title: "Suspicious inbox rule", Severity: "High", Confidence: "high", OccurredAt: events[1].OccurredAt, CreatedAt: now},
	}
	if _, err := st.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: "Audit.Exchange", Status: "healthy", Mode: "live", CursorEnd: now}, events, detections); err != nil {
		t.Fatal(err)
	}
	storyline := model.SecurityStoryline{
		ID: "story_ato", CorrelationKey: "account_takeover|ten_1|aaron@contoso.com", PackID: "account_takeover_bec",
		Title: "Account takeover progression", Status: model.SecurityTriageNew, RiskScore: 88,
		FirstSeen: events[0].OccurredAt, LastSeen: events[1].OccurredAt, UpdatedAt: now,
		TenantIDs: []string{"ten_1"}, DetectionIDs: []string{"det_signin", "det_rule"}, EventIDs: []string{"evt_signin", "evt_rule"},
	}
	if err := st.UpsertSecurityStorylines(ctx, []model.SecurityStoryline{storyline}); err != nil {
		t.Fatal(err)
	}
	service := New(st, graph.NewProvider(graph.Config{}, securityTestLogger(), nil), securityTestLogger())
	detail, err := service.Storyline(ctx, storyline.ID)
	if err != nil || len(detail.Evidence) != 2 || len(detail.Evidence[0].Events) != 1 || len(detail.Evidence[1].Events) != 1 {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}
	if detail.Evidence[0].DetectionID != "det_signin" || detail.Evidence[0].Stage == "" || detail.Evidence[1].DetectionID != "det_rule" || detail.Evidence[1].Stage == "" {
		t.Fatalf("ordered evidence = %+v", detail.Evidence)
	}
	updated, err := service.TriageStoryline(ctx, storyline.ID, model.SecurityTriageInProgress, "Aisha Rivera", "Aisha Rivera")
	if err != nil || updated.Status != model.SecurityTriageInProgress || updated.Owner != "Aisha Rivera" {
		t.Fatalf("triage=%+v err=%v", updated, err)
	}
	if _, err := service.TriageStoryline(ctx, storyline.ID, "Closed", "", "Aisha Rivera"); err != ErrInvalidTriageStatus {
		t.Fatalf("invalid status err=%v", err)
	}
}

func TestSnapshotAppliesLocalTriageState(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	if _, err := st.UpsertSecurityIncidentState(ctx, model.SecurityIncidentState{
		TenantID: "ten_1", IncidentID: "42", Status: model.SecurityTriageResolved,
		Owner: "Aisha Rivera", UpdatedBy: "Aisha Rivera",
	}); err != nil {
		t.Fatalf("state: %v", err)
	}
	base := graph.NewProvider(graph.Config{}, securityTestLogger(), nil)
	provider := &scriptedProvider{Provider: base, feeds: map[string]model.SecurityIncidentFeed{
		"ten_1": {Mode: "live", Incidents: []model.SecurityIncident{{
			ID: "42", Title: "Incident", Severity: "High", Status: model.SecurityTriageNew,
			ProviderStatus: "active", UpdatedAt: "2026-08-23T10:00:00Z",
		}}},
	}, errs: map[string]error{}}

	snapshot, err := New(st, provider, securityTestLogger()).Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Summary.Open != 0 || snapshot.Incidents[0].Status != model.SecurityTriageResolved || snapshot.Incidents[0].Owner != "Aisha Rivera" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if snapshot.Warnings == nil {
		t.Fatal("warnings must serialize as an empty array, not null")
	}
}

func TestTriagePersistsLocalWorkflowWithoutChangingProvider(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	base := graph.NewProvider(graph.Config{}, securityTestLogger(), nil)
	detail := model.SecurityIncidentDetail{SecurityIncident: model.SecurityIncident{
		ID: "42", Title: "Incident", Severity: "High", Status: model.SecurityTriageNew,
		ProviderStatus: "active",
	}}
	provider := &scriptedProvider{
		Provider: base, feeds: map[string]model.SecurityIncidentFeed{}, errs: map[string]error{},
		details: map[string]model.SecurityIncidentDetail{"ten_1|42": detail},
	}
	service := New(st, provider, securityTestLogger())
	status, owner := model.SecurityTriageInProgress, "Aisha Rivera"

	got, err := service.Triage(ctx, "ten_1", "42", &status, &owner, "Aisha Rivera")
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if got.Status != status || got.Owner != owner || got.ProviderStatus != "active" {
		t.Fatalf("detail = %+v", got)
	}
	states, _ := st.SecurityIncidentStates(ctx)
	if len(states) != 1 || states[0].Status != status || states[0].UpdatedBy != "Aisha Rivera" {
		t.Fatalf("states = %+v", states)
	}

	invalid := "Closed"
	if _, err := service.Triage(ctx, "ten_1", "42", &invalid, nil, "Aisha Rivera"); err != ErrInvalidTriageStatus {
		t.Fatalf("invalid status err = %v", err)
	}
}

func TestConnectorStatusDoesNotPresentMixedSampleCoverageAsHealthy(t *testing.T) {
	status := connectorStatus(model.SecurityConnectorSummary{
		HealthyTenants: 3,
		SampleTenants:  1,
	})
	if status != "sample" {
		t.Fatalf("connector status = %q, want sample", status)
	}
}

func TestProviderCoverageErrorDistinguishesDefenderProvisioning(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		wantStatus string
		wantDetail string
	}{
		{
			name:       "tenant is not provisioned",
			message:    "Unauthorized request - Account is not provisioned.",
			wantStatus: "not_provisioned",
			wantDetail: "not provisioned",
		},
		{
			name:       "application role is missing",
			message:    "Missing application roles. API required roles: SecurityIncident.Read.All",
			wantStatus: "missing_permission",
			wantDetail: defenderPermission,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, detail := providerCoverageError(&graph.APIError{
				Status:  http.StatusForbidden,
				Path:    "/security/incidents",
				Message: tt.message,
			})
			if status != tt.wantStatus || !strings.Contains(detail, tt.wantDetail) {
				t.Fatalf("providerCoverageError() = %q, %q", status, detail)
			}
		})
	}
}

func TestAuditCoverageRequiresAllWorkloadsAndPrioritizesPermissionErrors(t *testing.T) {
	tenant := model.Tenant{ID: "ten_1", Name: "Contoso"}
	now := time.Now().UTC()
	partial := auditCoverageForTenant(tenant, []model.SecurityAuditCheckpoint{{
		TenantID: tenant.ID, ContentType: "Audit.Exchange", Status: "healthy", Mode: "live",
	}}, now.Format(time.RFC3339))
	if partial.Status != "degraded" || !strings.Contains(partial.Detail, "1 of 4") {
		t.Fatalf("partial coverage = %+v", partial)
	}
	missing := auditCoverageForTenant(tenant, []model.SecurityAuditCheckpoint{{
		TenantID: tenant.ID, ContentType: "Audit.Exchange", Status: "missing_permission",
		Detail: "grant ActivityFeed.Read",
	}}, now.Format(time.RFC3339))
	if missing.Status != "missing_permission" || !strings.Contains(missing.Detail, "ActivityFeed.Read") {
		t.Fatalf("missing coverage = %+v", missing)
	}
}
