package securityops

import (
	"testing"

	"github.com/rarity/rtm/internal/model"
)

func TestRemediationPlanSelectsIncidentSpecificPlaybooks(t *testing.T) {
	tests := []struct {
		name     string
		incident model.SecurityIncidentDetail
		category string
		action   string
	}{
		{
			name: "identity compromise",
			incident: model.SecurityIncidentDetail{SecurityIncident: model.SecurityIncident{
				Title: "Multiple failed sign-ins followed by success", RuleID: "failed_logins_then_success",
			}},
			category: "Identity compromise", action: "Users → Revoke user access (What-If)",
		},
		{
			name: "mailbox persistence",
			incident: model.SecurityIncidentDetail{SecurityIncident: model.SecurityIncident{
				Title: "Mailbox forwarding changed", RuleID: "suspicious_mail_forwarding",
			}},
			category: "Mailbox persistence or mail-flow change", action: "Exchange → run the matching What-If action",
		},
		{
			name: "application consent",
			incident: model.SecurityIncidentDetail{SecurityIncident: model.SecurityIncident{
				Title: "High-risk application permission granted", RuleID: "high_risk_app_permission",
			}},
			category: "Application or consent risk", action: "Entra admin center → Enterprise applications",
		},
		{
			name: "provider alert participates in classification",
			incident: model.SecurityIncidentDetail{SecurityIncident: model.SecurityIncident{Title: "Provider incident"}, Alerts: []model.SecurityAlert{
				{Title: "Unexpected external SharePoint access"},
			}},
			category: "SharePoint or OneDrive data access", action: "SharePoint → investigate access and run What-If",
		},
		{
			name: "audit search",
			incident: model.SecurityIncidentDetail{SecurityIncident: model.SecurityIncident{
				Title: "Audit log search executed", RuleID: "audit_log_search",
			}},
			category: "Audit and investigation activity", action: "Audit Logs → verify the RTM operator trail",
		},
		{
			name: "domain federation control",
			incident: model.SecurityIncidentDetail{SecurityIncident: model.SecurityIncident{
				Title: "Domain federation or authentication changed", RuleID: "domain_federation_change",
			}},
			category: "Security control change", action: "Tenant detail → review control state",
		},
		{
			name: "application owner",
			incident: model.SecurityIncidentDetail{SecurityIncident: model.SecurityIncident{
				Title: "Application or service principal owner changed", RuleID: "application_owner_change",
			}},
			category: "Application or consent risk", action: "Entra admin center → Enterprise applications",
		},
		{
			name: "reported authentication fraud",
			incident: model.SecurityIncidentDetail{SecurityIncident: model.SecurityIncident{
				Title: "Suspicious authentication activity reported", RuleID: "suspicious_authentication_reported",
			}},
			category: "Identity compromise", action: "Users → Revoke user access (What-If)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := remediationPlan(test.incident)
			if plan.Category != test.category {
				t.Fatalf("category = %q, want %q", plan.Category, test.category)
			}
			if len(plan.Steps) < 4 || len(plan.CompletionCriteria) < 4 {
				t.Fatalf("plan is incomplete: %+v", plan)
			}
			if plan.Steps[0].RTMAction != test.action {
				t.Fatalf("first action = %q, want %q", plan.Steps[0].RTMAction, test.action)
			}
		})
	}
}

func TestRemediationPlanFallsBackWithoutClaimingCompromise(t *testing.T) {
	plan := remediationPlan(model.SecurityIncidentDetail{SecurityIncident: model.SecurityIncident{Title: "Unknown provider alert"}})
	if plan.Category != "General Microsoft 365 investigation" || len(plan.Steps) == 0 {
		t.Fatalf("fallback = %+v", plan)
	}
	if plan.Steps[0].Phase != "Investigate" {
		t.Fatalf("fallback should verify evidence before containment: %+v", plan.Steps[0])
	}
}
