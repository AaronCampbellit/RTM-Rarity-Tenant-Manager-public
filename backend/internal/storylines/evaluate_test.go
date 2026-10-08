package storylines

import (
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func TestEvaluateAccountTakeoverExplainsProgression(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	events := []model.SecurityAuditEvent{
		event("evt_login", "ten_1", "aaron@contoso.com", "1.2.3.4", "Entra", "UserLoggedIn", now.Add(-22*time.Minute)),
		event("evt_mfa", "ten_1", "aaron@contoso.com", "1.2.3.4", "Entra", "Update authentication method", now.Add(-12*time.Minute)),
		event("evt_forward", "ten_1", "aaron@contoso.com", "1.2.3.4", "Exchange", "Set-Mailbox", now.Add(-2*time.Minute)),
	}
	detections := []model.SecurityNativeDetection{
		detection("det_login", "ten_1", "evt_login", "possible_session_token_reuse", "High", "medium", events[0].OccurredAt),
		detection("det_mfa", "ten_1", "evt_mfa", "authentication_method_change", "High", "high", events[1].OccurredAt),
		detection("det_forward", "ten_1", "evt_forward", "suspicious_mail_forwarding", "High", "high", events[2].OccurredAt),
	}

	result := Evaluate(detections, events, map[string]string{"ten_1": "Contoso"}, now)
	storyline := findPack(t, result, "account_takeover_bec")
	if storyline.Severity != "Critical" || storyline.RiskScore < 80 || storyline.Confidence != "high" {
		t.Fatalf("storyline risk = %s %d %s", storyline.Severity, storyline.RiskScore, storyline.Confidence)
	}
	if len(storyline.Stages) != 3 || storyline.SignalCount != 3 || len(storyline.Reasons) < 3 {
		t.Fatalf("storyline explanation incomplete: %+v", storyline)
	}
	if storyline.ID == "" || storyline.CorrelationKey == "" || len(storyline.EventIDs) != 3 {
		t.Fatalf("storyline identity/evidence incomplete: %+v", storyline)
	}

	replayed := Evaluate(detections, events, map[string]string{"ten_1": "Contoso"}, now.Add(time.Minute))
	if findPack(t, replayed, "account_takeover_bec").ID != storyline.ID {
		t.Fatal("overlapping replay changed storyline identity")
	}
}

func TestEvaluateMSPStorylineRequiresSameActorNotSharedIP(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	events := []model.SecurityAuditEvent{
		event("evt_1", "ten_1", "admin-one@rarity.io", "1.2.3.4", "Entra", "Add application", now.Add(-10*time.Minute)),
		event("evt_2", "ten_2", "admin-two@rarity.io", "1.2.3.4", "Entra", "Add member to role", now.Add(-5*time.Minute)),
	}
	detections := []model.SecurityNativeDetection{
		detection("det_1", "ten_1", "evt_1", "application_registration", "Medium", "high", events[0].OccurredAt),
		detection("det_2", "ten_2", "evt_2", "privileged_role_change", "High", "high", events[1].OccurredAt),
	}
	if result := Evaluate(detections, events, nil, now); hasPack(result, "msp_admin_compromise") {
		t.Fatal("different actors were correlated from a shared IP")
	}

	events[1].Actor = events[0].Actor
	result := Evaluate(detections, events, map[string]string{"ten_1": "One", "ten_2": "Two"}, now)
	storyline := findPack(t, result, "msp_admin_compromise")
	if len(storyline.TenantIDs) != 2 || storyline.Severity == "Low" {
		t.Fatalf("cross-tenant storyline = %+v", storyline)
	}
}

func event(id, tenant, actor, ip, workload, operation string, occurred time.Time) model.SecurityAuditEvent {
	return model.SecurityAuditEvent{ID: id, TenantID: tenant, Actor: actor, ClientIP: ip, Workload: workload, Operation: operation, OccurredAt: occurred}
}

func detection(id, tenant, eventID, rule, severity, confidence string, occurred time.Time) model.SecurityNativeDetection {
	return model.SecurityNativeDetection{ID: id, TenantID: tenant, EventID: eventID, EventIDs: []string{eventID}, RuleID: rule, Severity: severity, Confidence: confidence, OccurredAt: occurred}
}

func findPack(t *testing.T, storylines []model.SecurityStoryline, packID string) model.SecurityStoryline {
	t.Helper()
	for _, storyline := range storylines {
		if storyline.PackID == packID {
			return storyline
		}
	}
	t.Fatalf("storyline pack %s not found in %+v", packID, storylines)
	return model.SecurityStoryline{}
}

func hasPack(storylines []model.SecurityStoryline, packID string) bool {
	for _, storyline := range storylines {
		if storyline.PackID == packID {
			return true
		}
	}
	return false
}
