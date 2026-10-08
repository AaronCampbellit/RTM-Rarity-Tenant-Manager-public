package server_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/seed"
)

func TestSecurityOperationsSnapshotIsCrossTenantAndAudited(t *testing.T) {
	h, st := newTestAPI(t)
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken

	var snapshot model.SecurityOperationsSnapshot
	rec := call(t, h, http.MethodGet, "/api/v1/security/operations", token, "", &snapshot)
	if rec.Code != http.StatusOK {
		t.Fatalf("snapshot = %d %s", rec.Code, rec.Body.String())
	}
	if len(snapshot.Incidents) != 7 || snapshot.Summary.TenantsCovered != 1 || snapshot.Summary.SampleTenants != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	defenderSample, auditInitializing := false, false
	for _, coverage := range snapshot.Coverage {
		if coverage.ConnectorKey == "defender_xdr" && coverage.Status == "sample" {
			defenderSample = true
		}
		if coverage.ConnectorKey == "m365_audit" && coverage.Status == "degraded" {
			auditInitializing = true
		}
	}
	if snapshot.Connectors[0].Status != "sample" || !defenderSample || !auditInitializing {
		t.Fatalf("connector coverage = %+v %+v", snapshot.Connectors, snapshot.Coverage)
	}
	entries, _ := st.Audit(t.Context())
	if entries[0].Action != "security.operations.view" || entries[0].Result != "Success" {
		t.Fatalf("audit = %+v", entries[0])
	}
}

func TestSecurityIncidentDetailAndLocalTriage(t *testing.T) {
	h, st := newTestAPI(t)
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken

	var detail model.SecurityIncidentDetail
	rec := call(t, h, http.MethodGet, "/api/v1/security/incidents/ten_1/sec_1001", token, "", &detail)
	if rec.Code != http.StatusOK || detail.Title != "Suspicious inbox forwarding rule" || detail.RTMReceivedAt == "" || len(detail.Timeline) == 0 || len(detail.Remediation.Steps) == 0 {
		t.Fatalf("detail = %d %+v", rec.Code, detail)
	}

	rec = call(t, h, http.MethodPatch, "/api/v1/security/incidents/ten_1/sec_1001", token,
		`{"status":"In Progress","assignment":"me"}`, &detail)
	if rec.Code != http.StatusOK || detail.Status != model.SecurityTriageInProgress || detail.Owner != "Aisha Rivera" {
		t.Fatalf("triage = %d %+v", rec.Code, detail)
	}
	states, _ := st.SecurityIncidentStates(t.Context())
	if len(states) != 1 || states[0].UpdatedBy != "Aisha Rivera" {
		t.Fatalf("states = %+v", states)
	}
	entries, _ := st.Audit(t.Context())
	if entries[0].Action != "security.incident.triage" {
		t.Fatalf("latest audit = %+v", entries[0])
	}
}

func TestSecurityIncidentTriageValidatesStatus(t *testing.T) {
	h, _ := newTestAPI(t)
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken
	rec := call(t, h, http.MethodPatch, "/api/v1/security/incidents/ten_1/sec_1001", token,
		`{"status":"Closed"}`, nil)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != httpx.CodeValidationFailed {
		t.Fatalf("invalid triage = %d %s", rec.Code, rec.Body.String())
	}
}

func TestSecurityStorylineDetailAndLocalTriage(t *testing.T) {
	h, st := newTestAPI(t)
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken
	now := time.Date(2026, 8, 26, 16, 0, 0, 0, time.UTC)
	event := model.SecurityAuditEvent{
		ID: "evt_story_api", TenantID: "ten_1", ProviderRecordID: "record-story-api",
		ContentType: "Audit.Exchange", Workload: "Exchange", Operation: "New-InboxRule",
		Actor: "aaron@contoso.com", ObjectID: "aaron@contoso.com", ResultStatus: "Succeeded",
		OccurredAt: now, IngestedAt: now, Raw: []byte(`{"Id":"record-story-api"}`),
	}
	detection := model.SecurityNativeDetection{
		ID: "det_story_api", TenantID: "ten_1", EventID: event.ID, EventIDs: []string{event.ID},
		RuleID: "inbox_rule_change", RuleVersion: 1, Title: "Suspicious inbox rule",
		Severity: "High", Confidence: "high", OccurredAt: now, CreatedAt: now,
	}
	if _, err := st.StoreSecurityAuditBatch(t.Context(), model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: "Audit.Exchange", Status: "healthy", Mode: "live", CursorEnd: now}, []model.SecurityAuditEvent{event}, []model.SecurityNativeDetection{detection}); err != nil {
		t.Fatal(err)
	}
	storyline := model.SecurityStoryline{
		ID: "story_api", CorrelationKey: "account_takeover|ten_1|aaron@contoso.com", PackID: "account_takeover_bec",
		Title: "Account takeover progression", Status: model.SecurityTriageNew, RiskScore: 86,
		FirstSeen: now, LastSeen: now, UpdatedAt: now, TenantIDs: []string{"ten_1"},
		DetectionIDs: []string{detection.ID}, EventIDs: []string{event.ID},
	}
	if err := st.UpsertSecurityStorylines(t.Context(), []model.SecurityStoryline{storyline}); err != nil {
		t.Fatal(err)
	}

	var detail model.SecurityStorylineDetail
	rec := call(t, h, http.MethodGet, "/api/v1/security/storylines/story_api", token, "", &detail)
	if rec.Code != http.StatusOK || detail.ID != storyline.ID || len(detail.Evidence) != 1 || len(detail.Evidence[0].Events) != 1 {
		t.Fatalf("detail = %d %+v", rec.Code, detail)
	}
	var updated model.SecurityStoryline
	rec = call(t, h, http.MethodPatch, "/api/v1/security/storylines/story_api", token, `{"status":"In Progress","assignment":"me"}`, &updated)
	if rec.Code != http.StatusOK || updated.Status != model.SecurityTriageInProgress || updated.Owner != "Aisha Rivera" {
		t.Fatalf("triage = %d %+v", rec.Code, updated)
	}
	rec = call(t, h, http.MethodPatch, "/api/v1/security/storylines/story_api", token, `{"status":"Closed"}`, nil)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != httpx.CodeValidationFailed {
		t.Fatalf("invalid triage = %d %s", rec.Code, rec.Body.String())
	}
	entries, _ := st.Audit(t.Context())
	if entries[0].Action != "security.storyline.triage" {
		t.Fatalf("latest audit = %+v", entries[0])
	}
}

func TestBulkSecurityIncidentTriageAcceptsAndMovesStages(t *testing.T) {
	h, st := newTestAPI(t)
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken
	type bulkResponse struct {
		Requested int `json:"requested"`
		Updated   int `json:"updated"`
		Failed    int `json:"failed"`
		Incidents []struct {
			TenantID   string `json:"tenantId"`
			IncidentID string `json:"incidentId"`
			Status     string `json:"status"`
			Owner      string `json:"owner"`
		} `json:"incidents"`
		Failures []struct {
			TenantID   string `json:"tenantId"`
			IncidentID string `json:"incidentId"`
			Message    string `json:"message"`
		} `json:"failures"`
	}

	var accepted bulkResponse
	rec := call(t, h, http.MethodPatch, "/api/v1/security/incidents", token, `{
		"action":"accept",
		"incidents":[
			{"tenantId":"ten_1","incidentId":"sec_1001"},
			{"tenantId":"ten_1","incidentId":"sec_1002"}
		]
	}`, &accepted)
	if rec.Code != http.StatusOK || accepted.Updated != 2 || accepted.Failed != 0 {
		t.Fatalf("accept = %d %+v", rec.Code, accepted)
	}
	for _, incident := range accepted.Incidents {
		if incident.Owner != "Aisha Rivera" || incident.Status != model.SecurityTriageInProgress {
			t.Fatalf("accepted incident = %+v", incident)
		}
	}

	var moved bulkResponse
	rec = call(t, h, http.MethodPatch, "/api/v1/security/incidents", token, `{
		"action":"set_status",
		"status":"Resolved",
		"incidents":[
			{"tenantId":"ten_1","incidentId":"sec_1001"},
			{"tenantId":"ten_1","incidentId":"sec_1002"}
		]
	}`, &moved)
	if rec.Code != http.StatusOK || moved.Updated != 2 || moved.Failed != 0 {
		t.Fatalf("move stage = %d %+v", rec.Code, moved)
	}
	for _, incident := range moved.Incidents {
		if incident.Owner != "Aisha Rivera" || incident.Status != model.SecurityTriageResolved {
			t.Fatalf("moved incident = %+v", incident)
		}
	}
	entries, _ := st.Audit(t.Context())
	if entries[0].Action != "security.incident.bulk_triage" || entries[0].Resource != "2 security incidents" {
		t.Fatalf("latest audit = %+v", entries[0])
	}
}

func TestBulkSecurityIncidentTriageReportsStaleRowsWithoutHidingSuccess(t *testing.T) {
	h, _ := newTestAPI(t)
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken
	var result struct {
		Updated  int `json:"updated"`
		Failed   int `json:"failed"`
		Failures []struct {
			IncidentID string `json:"incidentId"`
			Message    string `json:"message"`
		} `json:"failures"`
	}
	rec := call(t, h, http.MethodPatch, "/api/v1/security/incidents", token, `{
		"action":"accept",
		"incidents":[
			{"tenantId":"ten_1","incidentId":"sec_1001"},
			{"tenantId":"ten_1","incidentId":"no-longer-present"}
		]
	}`, &result)
	if rec.Code != http.StatusOK || result.Updated != 1 || result.Failed != 1 || len(result.Failures) != 1 {
		t.Fatalf("partial bulk triage = %d %+v", rec.Code, result)
	}
	if result.Failures[0].IncidentID != "no-longer-present" || result.Failures[0].Message == "" {
		t.Fatalf("failure = %+v", result.Failures[0])
	}
}

func TestBulkSecurityIncidentTriageValidatesRequest(t *testing.T) {
	h, _ := newTestAPI(t)
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken
	requests := []string{
		`{"action":"accept","incidents":[]}`,
		`{"action":"set_status","incidents":[{"tenantId":"ten_1","incidentId":"sec_1001"}]}`,
		`{"action":"set_status","status":"Closed","incidents":[{"tenantId":"ten_1","incidentId":"sec_1001"}]}`,
		`{"action":"accept","incidents":[{"tenantId":"ten_1","incidentId":"sec_1001"},{"tenantId":"ten_1","incidentId":"sec_1001"}]}`,
	}
	for _, body := range requests {
		rec := call(t, h, http.MethodPatch, "/api/v1/security/incidents", token, body, nil)
		if rec.Code != http.StatusBadRequest || errCode(t, rec) != httpx.CodeValidationFailed {
			t.Fatalf("invalid bulk triage = %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestSecurityOperationsRequireAuthentication(t *testing.T) {
	h, _ := newTestAPI(t)
	for _, path := range []string{
		"/api/v1/security/operations",
		"/api/v1/security/incidents/ten_1/sec_1001",
	} {
		if rec := call(t, h, http.MethodGet, path, "", "", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s = %d, want 401", path, rec.Code)
		}
	}
	if rec := call(t, h, http.MethodPatch, "/api/v1/security/incidents", "", `{
		"action":"accept","incidents":[{"tenantId":"ten_1","incidentId":"sec_1001"}]
	}`, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bulk triage = %d, want 401", rec.Code)
	}
}
