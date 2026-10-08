package server_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/seed"
)

func TestSecurityEventExplorerSearchDetailAndRedaction(t *testing.T) {
	h, st := newTestAPI(t)
	now := time.Now().UTC()
	raw := json.RawMessage(`{"Operation":"Set-Mailbox","Password":"do-not-return","AccessToken":"secret-token","Parameters":[{"Name":"ClientSecret","Value":"nested-secret"},{"Name":"ForwardingSmtpAddress","Value":"outside@example.net"}]}`)
	event := model.SecurityAuditEvent{ID: "evt-raw-1", TenantID: "ten_1", ProviderRecordID: "provider-raw-1", ContentType: "Audit.Exchange", Workload: "Exchange", Operation: "Set-Mailbox", Actor: "admin@contoso.com", ClientIP: "203.0.113.8", ObjectID: "finance@contoso.com", ResultStatus: "Succeeded", OccurredAt: now.Add(-time.Minute), IngestedAt: now, Raw: raw}
	detection := model.SecurityNativeDetection{ID: "det-raw-1", TenantID: "ten_1", EventID: event.ID, RuleID: "suspicious_mail_forwarding", RuleVersion: 1, Title: "Forwarding changed", Severity: "High", DetectionType: "direct", Confidence: "high", OccurredAt: event.OccurredAt, CreatedAt: now}
	if _, err := st.StoreSecurityAuditBatch(t.Context(), model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: "Audit.Exchange"}, []model.SecurityAuditEvent{event}, []model.SecurityNativeDetection{detection}); err != nil {
		t.Fatal(err)
	}
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken
	from, to := now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)
	var page model.SecurityAuditEventPage
	rec := call(t, h, http.MethodGet, "/api/v1/security/events?workload=Exchange&query=finance&from="+from+"&to="+to, token, "", &page)
	if rec.Code != http.StatusOK || len(page.Events) != 1 || page.Events[0].TenantName != "Contoso Ltd" {
		t.Fatalf("event page = %d %+v", rec.Code, page)
	}
	var detail model.SecurityAuditEventDetail
	rec = call(t, h, http.MethodGet, "/api/v1/security/events/ten_1/evt-raw-1", token, "", &detail)
	if rec.Code != http.StatusOK || len(detail.RelatedDetections) != 1 || len(detail.SourceEvidence) != 1 {
		t.Fatalf("event detail = %d %+v", rec.Code, detail)
	}
	evidence := string(detail.Raw)
	if strings.Contains(evidence, "do-not-return") || strings.Contains(evidence, "secret-token") || strings.Contains(evidence, "nested-secret") || !strings.Contains(evidence, "outside@example.net") || strings.Count(evidence, "[REDACTED]") < 3 {
		t.Fatalf("redacted evidence = %s", evidence)
	}
	sourceEvidence := string(detail.SourceEvidence[0].Raw)
	if strings.Contains(sourceEvidence, "do-not-return") || strings.Contains(sourceEvidence, "secret-token") || strings.Contains(sourceEvidence, "nested-secret") || !strings.Contains(sourceEvidence, "outside@example.net") {
		t.Fatalf("redacted source evidence = %s", sourceEvidence)
	}
	entries, _ := st.Audit(t.Context())
	if entries[0].Action != "security.event.raw_view" {
		t.Fatalf("latest audit = %+v", entries[0])
	}
}

func TestSecurityRuleConditionOptionsUseNormalizedEvidenceOnly(t *testing.T) {
	h, st := newTestAPI(t)
	now := time.Now().UTC()
	event := model.SecurityAuditEvent{
		ID: "evt-options-1", TenantID: "ten_1", ProviderRecordID: "provider-options-1",
		ContentType: "Audit.Exchange", Workload: "Exchange", Operation: "Set-Mailbox",
		Actor: "admin@contoso.com", ClientIP: "203.0.113.8", ObjectID: "finance@contoso.com",
		ResultStatus: "Succeeded", OccurredAt: now.Add(-time.Minute), IngestedAt: now,
		Raw: json.RawMessage(`{"ForwardingSmtpAddress":"outside@example.net","AccessToken":"do-not-return"}`),
	}
	if _, err := st.StoreSecurityAuditBatch(t.Context(), model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: "Audit.Exchange"}, []model.SecurityAuditEvent{event}, nil); err != nil {
		t.Fatal(err)
	}
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken
	var options model.SecurityRuleConditionOptions
	rec := call(t, h, http.MethodGet, "/api/v1/security/detection-rules/options?tenantId=ten_1", token, "", &options)
	if rec.Code != http.StatusOK || options.EventsScanned != 1 || !slices.Contains(options.Workloads, "Exchange") || !slices.Contains(options.Operations, "Set-Mailbox") || !slices.Contains(options.Actors, "admin@contoso.com") || !slices.Contains(options.ClientIPs, "203.0.113.8") || !slices.Contains(options.Results, "Succeeded") || !slices.Contains(options.Objects, "finance@contoso.com") || !slices.Contains(options.RawEvidenceTerms, "ForwardingSmtpAddress") || !slices.Contains(options.RawEvidenceTerms, "AuthenticationRequirement") {
		t.Fatalf("condition options = %d %+v", rec.Code, options)
	}
	encoded, _ := json.Marshal(options)
	if strings.Contains(string(encoded), "outside@example.net") || strings.Contains(string(encoded), "do-not-return") || strings.Contains(string(encoded), "AccessToken") {
		t.Fatalf("raw evidence leaked into condition options: %s", encoded)
	}
	entries, _ := st.Audit(t.Context())
	if entries[0].Action != "security.rule_options.view" {
		t.Fatalf("latest audit = %+v", entries[0])
	}
}

func TestSecurityRuleCatalogAndAdminMutations(t *testing.T) {
	h, _ := newTestAPI(t)
	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken
	var catalog []model.SecurityDetectionRule
	rec := call(t, h, http.MethodGet, "/api/v1/security/detection-rules", tech, "", &catalog)
	if rec.Code != http.StatusOK || len(catalog) != 54 {
		t.Fatalf("catalog = %d rules=%d", rec.Code, len(catalog))
	}
	createBody := `{"rule":{"name":"Custom mailbox detector","description":"Detect a selected mailbox operation.","builtIn":false,"override":false,"locked":false,"detectionType":"direct","severity":"High","confidence":"high","enabled":false,"scope":"global","definition":{"workloads":["Exchange"],"operations":["Set-Mailbox"],"operationMatch":"exact"},"revision":0}}`
	if denied := call(t, h, http.MethodPost, "/api/v1/security/detection-rules", tech, createBody, nil); denied.Code != http.StatusForbidden {
		t.Fatalf("technician create = %d", denied.Code)
	}
	admin := adminToken(t, h)
	var created model.SecurityDetectionRule
	rec = call(t, h, http.MethodPost, "/api/v1/security/detection-rules", admin, createBody, &created)
	if rec.Code != http.StatusCreated || created.ID == "" || created.Enabled || created.Revision != 1 {
		t.Fatalf("created = %d %+v", rec.Code, created)
	}
	created.Enabled = true
	previewBody, _ := json.Marshal(map[string]any{"rule": created})
	var preview model.SecurityRulePreview
	rec = call(t, h, http.MethodPost, "/api/v1/security/detection-rules/preview", admin, string(previewBody), &preview)
	if rec.Code != http.StatusOK || preview.ApprovalToken == "" {
		t.Fatalf("preview = %d %+v", rec.Code, preview)
	}
	updateBody, _ := json.Marshal(map[string]any{"rule": created, "approvalToken": preview.ApprovalToken})
	var updated model.SecurityDetectionRule
	rec = call(t, h, http.MethodPut, "/api/v1/security/detection-rules/"+created.ID, admin, string(updateBody), &updated)
	if rec.Code != http.StatusOK || !updated.Enabled || updated.Revision != 2 {
		t.Fatalf("updated = %d %+v body=%s", rec.Code, updated, rec.Body.String())
	}
	var revisions []model.SecurityDetectionRuleRevision
	rec = call(t, h, http.MethodGet, "/api/v1/security/detection-rules/"+created.ID+"/revisions", tech, "", &revisions)
	if rec.Code != http.StatusOK || len(revisions) != 2 || revisions[0].Revision != 2 {
		t.Fatalf("revisions = %d %+v", rec.Code, revisions)
	}
}

func TestSecurityRuleBuiltInRequiresStoredOverride(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)
	body := `{"rule":{"id":"builtin:password_reset","ruleId":"password_reset","name":"User password reset or changed","description":"built-in","builtIn":true,"locked":true,"detectionType":"direct","severity":"Critical","confidence":"high","enabled":true,"scope":"global","definition":{},"revision":1}}`
	var preview model.SecurityRulePreview
	rec := call(t, h, http.MethodPost, "/api/v1/security/detection-rules/preview", admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	var mutation map[string]any
	_ = json.Unmarshal([]byte(body), &mutation)
	mutation["approvalToken"] = preview.ApprovalToken
	encoded, _ := json.Marshal(mutation)
	var override model.SecurityDetectionRule
	rec = call(t, h, http.MethodPost, "/api/v1/security/detection-rules", admin, string(encoded), &override)
	if rec.Code != http.StatusCreated || override.BaseRuleID != "password_reset" || !override.Override || !override.Locked || override.ID == "builtin:password_reset" {
		t.Fatalf("override = %d %+v body=%s", rec.Code, override, rec.Body.String())
	}
}

func TestSecurityRuleBuiltInOverrideApprovalMatchesCreateInProduction(t *testing.T) {
	h, _ := newTestAPIWithEnv(t, nil, "production")
	admin := adminToken(t, h)
	body := `{"rule":{"id":"","ruleId":"password_reset","baseRuleId":"password_reset","name":"User password reset or changed","description":"built-in","builtIn":true,"override":true,"locked":true,"detectionType":"direct","severity":"Critical","confidence":"high","enabled":true,"scope":"global","definition":{"triggerMode":"builtIn","exclusions":[]},"revision":1}}`
	var preview model.SecurityRulePreview
	rec := call(t, h, http.MethodPost, "/api/v1/security/detection-rules/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || preview.ApprovalToken == "" {
		t.Fatalf("preview = %d %+v body=%s", rec.Code, preview, rec.Body.String())
	}
	var mutation map[string]any
	_ = json.Unmarshal([]byte(body), &mutation)
	mutation["approvalToken"] = preview.ApprovalToken
	encoded, _ := json.Marshal(mutation)
	var override model.SecurityDetectionRule
	rec = call(t, h, http.MethodPost, "/api/v1/security/detection-rules", admin, string(encoded), &override)
	if rec.Code != http.StatusCreated || override.BaseRuleID != "password_reset" || !override.Override {
		t.Fatalf("override = %d %+v body=%s", rec.Code, override, rec.Body.String())
	}
}

func TestSecurityRuleBuiltInAcceptsEditableTriggerAndAlertText(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)
	body := `{"rule":{"id":"builtin:password_reset","ruleId":"password_reset","name":"Priority mailbox change","description":"Escalate mailbox changes from the selected workload.","builtIn":true,"locked":true,"detectionType":"direct","severity":"Critical","confidence":"high","enabled":true,"scope":"global","definition":{"triggerMode":"custom","workloads":["Exchange"],"operations":["Set-Mailbox"],"operationMatch":"exact"},"revision":1}}`
	var preview model.SecurityRulePreview
	rec := call(t, h, http.MethodPost, "/api/v1/security/detection-rules/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || preview.ApprovalToken == "" {
		t.Fatalf("preview = %d %+v body=%s", rec.Code, preview, rec.Body.String())
	}
	var mutation map[string]any
	_ = json.Unmarshal([]byte(body), &mutation)
	mutation["approvalToken"] = preview.ApprovalToken
	encoded, _ := json.Marshal(mutation)
	var override model.SecurityDetectionRule
	rec = call(t, h, http.MethodPost, "/api/v1/security/detection-rules", admin, string(encoded), &override)
	if rec.Code != http.StatusCreated || override.Name != "Priority mailbox change" || override.Description != "Escalate mailbox changes from the selected workload." || override.Definition.TriggerMode != "custom" || len(override.Definition.Operations) != 1 || override.Definition.Operations[0] != "Set-Mailbox" {
		t.Fatalf("editable override = %d %+v body=%s", rec.Code, override, rec.Body.String())
	}
}
