package securityops

import (
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func TestSummarizeSecurityEventPromotesHumanEvidenceAndDropsResourceBlob(t *testing.T) {
	event := model.SecurityAuditEvent{
		ID: "sae-1", Operation: "Add app role assignment to service principal.",
		Actor: "admin@example.com", Workload: "AzureActiveDirectory", ResultStatus: "Success",
		ObjectID:   "00000002/outlook.office365.com;https://outlook.office.com;https://outlook.com;https://mail.office365.com",
		OccurredAt: time.Date(2026, 8, 25, 20, 38, 37, 0, time.UTC),
		Raw: []byte(`{
			"Target":[{"ID":"Office 365 Exchange Online","Type":1},{"ID":"00000002/outlook.office365.com;https://outlook.office.com","Type":4}],
			"ModifiedProperties":[
				{"Name":"AppRole.Id","NewValue":"role-guid","OldValue":""},
				{"Name":"AppRole.Value","NewValue":"Exchange.ManageAsAppV2","OldValue":""},
				{"Name":"AppRole.DisplayName","NewValue":"Manage Exchange as application v2","OldValue":""},
				{"Name":"ServicePrincipal.DisplayName","NewValue":"Rarity Tenant Manager","OldValue":""},
				{"Name":"ServicePrincipal.Name","NewValue":"api://application-guid,application-guid","OldValue":""},
				{"Name":"TargetId.ServicePrincipalNames","NewValue":"one;two;three;four","OldValue":""}
			]
		}`),
	}

	got := summarizeSecurityEvent(event)
	if got.Target != "Rarity Tenant Manager" || got.RelatedResource != "Office 365 Exchange Online" {
		t.Fatalf("target summary = %+v", got)
	}
	if got.Actor != event.Actor || got.Operation != event.Operation || got.ResultStatus != "Success" {
		t.Fatalf("normalized evidence = %+v", got)
	}
	if len(got.Changes) != 3 || got.Changes[0].Field != "Application permission" || got.Changes[0].After != "Exchange.ManageAsAppV2" {
		t.Fatalf("changes = %+v", got.Changes)
	}
	for _, change := range got.Changes {
		if change.After == event.ObjectID {
			t.Fatal("opaque resource blob leaked into human evidence")
		}
	}
}

func TestSummarizeSecurityEventUsesFastIdentityTarget(t *testing.T) {
	event := model.SecurityAuditEvent{
		ID: "sae-fast", Operation: "Add member to role", Actor: "admin@example.com",
		ObjectID: "Global Administrator", ResultStatus: "success", OccurredAt: time.Now().UTC(),
		Raw: []byte(`{"targetResources":[{"displayName":"Global Administrator"}]}`),
	}
	got := summarizeSecurityEvent(event)
	if got.Target != "Global Administrator" || len(got.Changes) != 0 {
		t.Fatalf("fast identity summary = %+v", got)
	}
}
