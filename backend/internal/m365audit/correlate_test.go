package m365audit

import (
	"fmt"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func eventsFor(count int, operation string, interval time.Duration, raw func(int) map[string]any) []model.SecurityAuditEvent {
	out := make([]model.SecurityAuditEvent, 0, count)
	for i := 0; i < count; i++ {
		var body map[string]any
		if raw != nil {
			body = raw(i)
		}
		event := testEvent(fmt.Sprintf("evt-%s-%d", operation, i), operation, detectionTestNow.Add(time.Duration(i)*interval), body)
		event.ObjectID = fmt.Sprintf("object-%d", i)
		out = append(out, event)
	}
	return out
}

func requireCorrelatedRule(t *testing.T, events []model.SecurityAuditEvent, ruleID, detectionType string) model.SecurityNativeDetection {
	t.Helper()
	detection, ok := detectionRuleIDs(Correlate(events, detectionTestNow.Add(24*time.Hour)))[ruleID]
	if !ok {
		t.Fatalf("rule %s missing from %+v", ruleID, detectionRuleIDs(Correlate(events, detectionTestNow.Add(24*time.Hour))))
	}
	if detection.DetectionType != detectionType || detection.Confidence == "" {
		t.Fatalf("detection classification = %+v", detection)
	}
	return detection
}

func TestCorrelateVolumeRules(t *testing.T) {
	forwarding := eventsFor(5, "Set-Mailbox", time.Minute, func(i int) map[string]any {
		return map[string]any{"ForwardingSmtpAddress": fmt.Sprintf("user%d@external.example", i)}
	})
	requireCorrelatedRule(t, forwarding, "mass_mailbox_forwarding", DetectionThreshold)

	group := eventsFor(20, "Add member to group", 20*time.Second, nil)
	groupDetection := requireCorrelatedRule(t, group, "large_group_membership_change", DetectionThreshold)
	if len(groupDetection.EventIDs) != len(group) {
		t.Fatalf("supporting event relationship = %d ids, want %d", len(groupDetection.EventIDs), len(group))
	}

	downloads := eventsFor(50, "FileDownloaded", 10*time.Second, nil)
	markSharePointEvents(downloads)
	requireCorrelatedRule(t, downloads, "bulk_file_download", DetectionThreshold)

	deletions := eventsFor(20, "FileDeleted", 10*time.Second, nil)
	markSharePointEvents(deletions)
	requireCorrelatedRule(t, deletions, "bulk_file_deletion", DetectionThreshold)

	sharing := eventsFor(10, "SharingInvitationCreated", 10*time.Second, nil)
	markSharePointEvents(sharing)
	requireCorrelatedRule(t, sharing, "bulk_external_sharing", DetectionThreshold)
}

func markSharePointEvents(events []model.SecurityAuditEvent) {
	for i := range events {
		events[i].Workload = "SharePoint"
		events[i].ContentType = "Audit.SharePoint"
	}
}

func TestBulkFileDetectionRequiresSharePointOrOneDriveSource(t *testing.T) {
	events := eventsFor(50, "FileDownloaded", 10*time.Second, nil)
	if _, ok := detectionRuleIDs(Correlate(events, detectionTestNow.Add(time.Hour)))["bulk_file_download"]; ok {
		t.Fatal("generic audit events must not be labeled as SharePoint bulk downloads")
	}
}

func TestCorrelateAdministrativeBursts(t *testing.T) {
	failures := eventsFor(5, "Set-ConditionalAccessPolicy", time.Minute, nil)
	for i := range failures {
		failures[i].ResultStatus = "Failed"
	}
	requireCorrelatedRule(t, failures, "repeated_administrative_failures", DetectionThreshold)

	objects := eventsFor(15, "Update user", 20*time.Second, mapAccountEnabled)
	requireCorrelatedRule(t, objects, "administrator_object_burst", DetectionThreshold)

	crossTenant := eventsFor(15, "Update user", 20*time.Second, mapAccountEnabled)
	for i := range crossTenant {
		if i%2 == 1 {
			crossTenant[i].TenantID = "ten_2"
		}
	}
	requireCorrelatedRule(t, crossTenant, "cross_tenant_administrator_burst", DetectionCorrelation)
}

func mapAccountEnabled(_ int) map[string]any { return map[string]any{"AccountEnabled": false} }

func TestCorrelateLoginSignals(t *testing.T) {
	var events []model.SecurityAuditEvent
	for i := 0; i < 5; i++ {
		event := testEvent(fmt.Sprintf("fail-%d", i), "UserLoginFailed", detectionTestNow.Add(time.Duration(i)*time.Minute), map[string]any{"Country": "US"})
		event.ResultStatus = "Failed"
		events = append(events, event)
	}
	first := testEvent("success-1", "UserLoggedIn", detectionTestNow.Add(6*time.Minute), map[string]any{"Country": "US", "SessionId": "session-1", "UserAgent": "Browser A"})
	first.ResultStatus, first.ClientIP = "Success", "203.0.113.10"
	second := testEvent("success-2", "UserLoggedIn", detectionTestNow.Add(35*time.Minute), map[string]any{"Country": "CA", "SessionId": "session-1", "UserAgent": "Browser B"})
	second.ResultStatus, second.ClientIP = "Success", "198.51.100.20"
	events = append(events, first, second)
	rules := detectionRuleIDs(Correlate(events, detectionTestNow.Add(time.Hour)))
	for _, ruleID := range []string{"failed_logins_then_success", "possible_impossible_travel", "possible_session_token_reuse"} {
		if _, ok := rules[ruleID]; !ok {
			t.Fatalf("%s missing from %+v", ruleID, rules)
		}
	}
	if rules["possible_impossible_travel"].Confidence != ConfidenceMedium || rules["possible_session_token_reuse"].DetectionType != DetectionCorrelation {
		t.Fatalf("login signal metadata = %+v", rules)
	}
}

func TestCorrelateNewForwardingDomainNeedsBaseline(t *testing.T) {
	events := eventsFor(4, "Set-Mailbox", 24*time.Hour, func(i int) map[string]any {
		return map[string]any{"ForwardingSmtpAddress": fmt.Sprintf("user%d@known.example", i)}
	})
	newDomain := testEvent("new-domain", "Set-Mailbox", detectionTestNow.Add(5*24*time.Hour), map[string]any{"ForwardingSmtpAddress": "user@new.example"})
	events = append(events, newDomain)
	requireCorrelatedRule(t, events, "new_forwarding_domain", DetectionHeuristic)
}

func TestCorrelateUnusualAdministratorContextRequiresSevenDayBaseline(t *testing.T) {
	events := eventsFor(21, "Update user", 12*time.Hour, mapAccountEnabled)
	for i := range events {
		events[i].ClientIP = "203.0.113.10"
		events[i].Raw = []byte(`{"Country":"US","AccountEnabled":false}`)
	}
	anomaly := testEvent("admin-anomaly", "Update user", events[len(events)-1].OccurredAt.Add(12*time.Hour), map[string]any{"Country": "CA", "AccountEnabled": false})
	anomaly.ClientIP = "198.51.100.20"
	events = append(events, anomaly)
	rules := detectionRuleIDs(Correlate(events, anomaly.OccurredAt.Add(time.Hour)))
	for _, ruleID := range []string{"unusual_administrator_ip", "unusual_administrator_country"} {
		if _, ok := rules[ruleID]; !ok {
			t.Fatalf("%s missing from %+v", ruleID, rules)
		}
	}
}

func TestCorrelationIDsAreStableAcrossReplay(t *testing.T) {
	events := eventsFor(20, "Add member to group", 20*time.Second, nil)
	first := requireCorrelatedRule(t, events, "large_group_membership_change", DetectionThreshold)
	second := detectionRuleIDs(Correlate(events, detectionTestNow.Add(48*time.Hour)))["large_group_membership_change"]
	if first.ID != second.ID {
		t.Fatalf("correlation ID changed: %s != %s", first.ID, second.ID)
	}
}

func TestNoImpossibleTravelWithoutCountryEvidence(t *testing.T) {
	first := testEvent("login-1", "UserLoggedIn", detectionTestNow, map[string]any{"SessionId": "a"})
	second := testEvent("login-2", "UserLoggedIn", detectionTestNow.Add(time.Hour), map[string]any{"SessionId": "b"})
	first.ResultStatus, second.ResultStatus = "Success", "Success"
	if _, ok := detectionRuleIDs(Correlate([]model.SecurityAuditEvent{first, second}, detectionTestNow))["possible_impossible_travel"]; ok {
		t.Fatal("impossible travel must not fire without country evidence")
	}
}
