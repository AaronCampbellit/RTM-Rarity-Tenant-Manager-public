package server

import (
	"encoding/json"
	"testing"

	"github.com/rarity/rtm/internal/model"
)

func TestOfflineTimelineFactsExposeOnlyInvestigatorContext(t *testing.T) {
	facts := offlineTimelineFacts(json.RawMessage(`{
		"ApplicationDisplayName":"Outlook",
		"AuthType":"OAuth",
		"ExternalAccess":true,
		"OperationCount":14,
		"GeoLocation":"US",
		"DeviceDisplayName":"Analyst laptop",
		"SessionId":"must-not-be-projected"
	}`))
	values := map[string]string{}
	for _, fact := range facts {
		values[fact.Label] = fact.Value
	}
	for label, want := range map[string]string{
		"Application": "Outlook", "Authentication": "OAuth", "Access": "External",
		"Affected": "14 items", "Location": "US", "Device": "Analyst laptop",
	} {
		if values[label] != want {
			t.Fatalf("%s = %q, want %q (facts=%+v)", label, values[label], want, facts)
		}
	}
	if _, exposed := values["SessionId"]; exposed {
		t.Fatalf("non-allowlisted field was exposed: %+v", facts)
	}
}

func TestTimelineSignalsDeduplicateRuleMatches(t *testing.T) {
	signal := model.OfflineTimelineSignal{RuleID: "rule-1", Title: "Risky activity", Severity: "High"}
	if containsTimelineSignal(nil, signal) {
		t.Fatal("empty signal list reported a match")
	}
	if !containsTimelineSignal([]model.OfflineTimelineSignal{signal}, signal) {
		t.Fatal("equivalent signal was not deduplicated")
	}
}

func TestOfflineTimelineRawStringBackfillsExistingAnalysisFields(t *testing.T) {
	raw := json.RawMessage(`{"ClientIPAddress":"203.0.113.4","MailboxOwnerUPN":"user@example.com"}`)
	if got := offlineTimelineRawString(raw, "ClientIPAddress", "ActorIpAddress"); got != "203.0.113.4" {
		t.Fatalf("client IP = %q", got)
	}
	if got := offlineTimelineRawString(raw, "MailboxOwnerUPN", "SourceFileName"); got != "user@example.com" {
		t.Fatalf("target = %q", got)
	}
}
