package m365audit

import (
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func TestBuiltInRuleCatalogIsCompleteAndUnique(t *testing.T) {
	rules := BuiltInRules()
	if len(rules) != 54 {
		t.Fatalf("BuiltInRules count = %d, want 54", len(rules))
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if seen[rule.RuleID] || !rule.BuiltIn || !rule.Locked || rule.Scope != "global" || !rule.Enabled {
			t.Fatalf("invalid built-in rule: %+v", rule)
		}
		seen[rule.RuleID] = true
	}
}

func TestBuiltInSeverityCalibration(t *testing.T) {
	expected := map[string]string{
		"authentication_method_change":       "High",
		"guest_invitation":                   "Low",
		"guest_privilege_escalation":         "High",
		"high_risk_app_permission":           "High",
		"application_secret_expiring":        "Low",
		"audit_configuration_change":         "High",
		"legacy_authentication":              "Medium",
		"single_factor_authentication":       "High",
		"large_group_membership_change":      "Medium",
		"repeated_administrative_failures":   "Medium",
		"cross_tenant_administrator_burst":   "High",
		"unusual_administrator_country":      "Medium",
		"unusual_administrator_time":         "Low",
		"possible_session_token_reuse":       "High",
		"domain_federation_change":           "Critical",
		"tenant_domain_change":               "High",
		"application_configuration_change":   "Medium",
		"mailbox_auditing_disabled":          "Critical",
		"suspicious_authentication_reported": "High",
		"cross_tenant_access_policy_change":  "High",
		"privileged_role_policy_change":      "High",
	}
	for _, rule := range BuiltInRules() {
		if want, ok := expected[rule.RuleID]; ok && rule.Severity != want {
			t.Fatalf("%s severity = %s, want %s", rule.RuleID, rule.Severity, want)
		}
		if rule.Severity == "Critical" && rule.Confidence != ConfidenceHigh {
			t.Fatalf("critical rule must use high-confidence evidence: %+v", rule)
		}
	}
}

func TestCustomDirectRuleMatchesConfiguredFieldsAndExclusions(t *testing.T) {
	event := testEvent("custom-1", "Set-Mailbox", detectionTestNow, map[string]any{"ForwardingSmtpAddress": "outside@example.net"})
	event.Workload = "Exchange"
	rule := model.SecurityDetectionRule{
		ID: "rule-1", RuleID: "custom_forwarding", Name: "External forwarding", Description: "External forwarding was configured.",
		DetectionType: DetectionDirect, Severity: "High", Confidence: ConfidenceHigh, Enabled: true, Scope: "global", Revision: 3,
		Definition: model.SecurityRuleDefinition{Workloads: []string{"Exchange"}, Operations: []string{"Set-Mailbox"}, OperationMatch: "exact", RawContains: []string{"example.net"}},
	}
	detections := DetectCustom([]model.SecurityAuditEvent{event}, detectionTestNow, []model.SecurityDetectionRule{rule})
	if len(detections) != 1 || detections[0].RuleID != rule.RuleID || detections[0].RuleVersion != 3 {
		t.Fatalf("custom detections = %+v", detections)
	}
	rule.Definition.Exclusions = []model.SecurityRuleExclusion{{Field: "actor", Match: "exact", Value: event.Actor}}
	if got := DetectCustom([]model.SecurityAuditEvent{event}, detectionTestNow, []model.SecurityDetectionRule{rule}); len(got) != 0 {
		t.Fatalf("excluded event detected: %+v", got)
	}
}

func TestCustomThresholdAndBuiltInOverride(t *testing.T) {
	var events []model.SecurityAuditEvent
	for i := 0; i < 3; i++ {
		event := testEvent(string(rune('a'+i)), "FileDownloaded", detectionTestNow.Add(time.Duration(i)*time.Minute), nil)
		event.Workload = "SharePoint"
		events = append(events, event)
	}
	custom := model.SecurityDetectionRule{
		ID: "rule-2", RuleID: "custom_download", Name: "Three downloads", Description: "Download activity", DetectionType: DetectionThreshold,
		Severity: "Medium", Confidence: ConfidenceMedium, Enabled: true, Scope: "global", Revision: 2,
		Definition: model.SecurityRuleDefinition{Workloads: []string{"SharePoint"}, Operations: []string{"download"}, OperationMatch: "contains", Threshold: 3, WindowMinutes: 5, GroupBy: "actor"},
	}
	if got := CorrelateConfigured(events, detectionTestNow, []model.SecurityDetectionRule{custom}); len(got) != 1 || got[0].RuleID != custom.RuleID {
		t.Fatalf("custom threshold detections = %+v", got)
	}
	override := model.SecurityDetectionRule{BaseRuleID: "bulk_file_download", RuleID: "bulk_file_download", BuiltIn: true, Enabled: false, Scope: "global", Severity: "High", Confidence: ConfidenceMedium, Revision: 2}
	if got := CorrelateConfigured(events, detectionTestNow, []model.SecurityDetectionRule{override}); len(got) != 0 {
		t.Fatalf("disabled built-in produced detections: %+v", got)
	}
}

func TestPreviewRuleForBuiltInUsesOverrideSettings(t *testing.T) {
	event := testEvent("preview-1", "Reset user password", detectionTestNow, nil)
	rule := model.SecurityDetectionRule{RuleID: "password_reset", BaseRuleID: "password_reset", BuiltIn: true, Enabled: false, Scope: "global", Severity: "Critical", Confidence: ConfidenceHigh, Revision: 4}
	got := PreviewRule([]model.SecurityAuditEvent{event}, rule, detectionTestNow)
	if len(got) != 1 || got[0].Severity != "Critical" || got[0].RuleVersion != 4 {
		t.Fatalf("preview = %+v", got)
	}
}

func TestBuiltInOverrideCanReplaceSpecializedTrigger(t *testing.T) {
	passwordReset := testEvent("reset-1", "Reset user password", detectionTestNow, nil)
	mailboxChange := testEvent("mailbox-1", "Set-Mailbox", detectionTestNow.Add(time.Minute), nil)
	mailboxChange.Workload = "Exchange"
	rule := model.SecurityDetectionRule{
		ID: "override-1", RuleID: "password_reset", BaseRuleID: "password_reset", Name: "Mailbox alert",
		Description: "The customized built-in alert.", BuiltIn: true, Override: true, Locked: true,
		DetectionType: DetectionDirect, Severity: "Critical", Confidence: ConfidenceHigh, Enabled: true,
		Scope: "global", Revision: 3,
		Definition: model.SecurityRuleDefinition{
			TriggerMode: "custom", Workloads: []string{"Exchange"}, Operations: []string{"Set-Mailbox"}, OperationMatch: "exact",
		},
	}

	got := DetectConfigured([]model.SecurityAuditEvent{passwordReset, mailboxChange}, detectionTestNow, []model.SecurityDetectionRule{rule})
	if len(got) != 1 || got[0].EventID != mailboxChange.ID || got[0].RuleID != "password_reset" || got[0].Title != "Mailbox alert" || got[0].RuleVersion != 3 {
		t.Fatalf("customized built-in detections = %+v", got)
	}
}

func TestTenantBuiltInOverrideWinsOverGlobalCustomTrigger(t *testing.T) {
	event := testEvent("reset-tenant", "Reset user password", detectionTestNow, nil)
	global := model.SecurityDetectionRule{
		ID: "override-global", RuleID: "password_reset", BaseRuleID: "password_reset", Name: "Global replacement",
		Description: "Global replacement.", BuiltIn: true, Override: true, Locked: true, DetectionType: DetectionDirect,
		Severity: "High", Confidence: ConfidenceHigh, Enabled: true, Scope: "global", Revision: 2,
		Definition: model.SecurityRuleDefinition{TriggerMode: "custom", Operations: []string{"Set-Mailbox"}, OperationMatch: "exact"},
	}
	tenant := model.SecurityDetectionRule{
		ID: "override-tenant", RuleID: "password_reset", BaseRuleID: "password_reset", Name: "Tenant baseline",
		Description: "Tenant baseline.", BuiltIn: true, Override: true, Locked: true, DetectionType: DetectionDirect,
		Severity: "Medium", Confidence: ConfidenceHigh, Enabled: true, Scope: "tenant", TenantID: event.TenantID, Revision: 4,
		Definition: model.SecurityRuleDefinition{TriggerMode: "builtIn"},
	}

	got := DetectConfigured([]model.SecurityAuditEvent{event}, detectionTestNow, []model.SecurityDetectionRule{global, tenant})
	if len(got) != 1 || got[0].EventID != event.ID || got[0].RuleVersion != 4 {
		t.Fatalf("tenant precedence detections = %+v", got)
	}
}
