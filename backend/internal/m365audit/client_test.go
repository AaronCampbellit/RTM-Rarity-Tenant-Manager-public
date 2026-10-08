package m365audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestClientCollectStartsSubscriptionAndNormalizesEvents(t *testing.T) {
	var started bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = r.ParseForm()
			if r.Form.Get("scope") != "https://manage.office.com/.default" {
				t.Fatalf("token scope = %q", r.Form.Get("scope"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 3600})
		case strings.HasSuffix(r.URL.Path, "/subscriptions/list"):
			_ = json.NewEncoder(w).Encode([]any{})
		case strings.HasSuffix(r.URL.Path, "/subscriptions/start"):
			started = true
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/subscriptions/content"):
			_ = json.NewEncoder(w).Encode([]map[string]string{{"contentUri": serverURL(r) + "/content/blob-1"}})
		case r.URL.Path == "/content/blob-1":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"Id": "record-1", "CreationTime": "2026-08-24T20:00:00Z",
				"Operation": "Set-Mailbox", "Workload": "Exchange",
				"UserId": "admin@example.com", "ClientIP": "203.0.113.9",
				"ObjectId": "finance@example.com", "ResultStatus": "Succeeded",
			}})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	c := newClient(Config{ClientID: "client", ClientSecret: "secret", TenantID: "directory"}, testLogger(), nil)
	c.base, c.loginBase = server.URL, server.URL
	events, err := c.Collect(context.Background(), "ten_1", "Audit.Exchange", time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !started || len(events) != 1 {
		t.Fatalf("started=%v events=%+v", started, events)
	}
	event := events[0]
	if event.ProviderRecordID != "record-1" || event.Operation != "Set-Mailbox" || event.Actor != "admin@example.com" || event.Raw == nil {
		t.Fatalf("normalized event = %+v", event)
	}
}

func TestNormalizeEventAcceptsMicrosoftTimestampWithoutZone(t *testing.T) {
	raw := json.RawMessage(`{"Id":"record-no-zone","CreationTime":"2026-08-25T16:23:10","Operation":"Add user","Workload":"AzureActiveDirectory","UserId":"admin@example.com","ResultStatus":"Success"}`)
	event, err := normalizeEvent("ten_1", "Audit.AzureActiveDirectory", raw, time.Now().UTC())
	if err != nil {
		t.Fatalf("normalizeEvent: %v", err)
	}
	want := time.Date(2026, 8, 25, 16, 23, 10, 0, time.UTC)
	if !event.OccurredAt.Equal(want) {
		t.Fatalf("OccurredAt = %s, want %s", event.OccurredAt, want)
	}
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host
}

func TestValidateContentURLRejectsSSRF(t *testing.T) {
	c := newClient(Config{}, testLogger(), nil)
	tests := []string{
		"http://169.254.169.254/latest/meta-data",
		"https://manage.office.com.evil.example/content",
		"file:///etc/passwd",
	}
	for _, raw := range tests {
		if err := c.validateContentURL(raw); err == nil {
			t.Fatalf("validateContentURL(%q) unexpectedly succeeded", raw)
		}
	}
	for _, raw := range []string{"https://manage.office.com/content", "https://content.manage.microsoft.com/blob"} {
		if err := c.validateContentURL(raw); err != nil {
			t.Fatalf("validateContentURL(%q): %v", raw, err)
		}
	}
}

func TestTokenRequestEscapesAuthority(t *testing.T) {
	c := newClient(Config{}, testLogger(), nil)
	u, _ := url.Parse(c.loginBase + "/" + url.PathEscape("tenant.example") + "/oauth2/v2.0/token")
	if u.Path != "/tenant.example/oauth2/v2.0/token" {
		t.Fatalf("path = %q", u.Path)
	}
}

func TestPreflightReportsSampleAndMissingPermission(t *testing.T) {
	sample := newClient(Config{}, testLogger(), nil).Preflight(context.Background(), "ten_1")
	if sample.Status != "sample" || sample.Permission != Permission {
		t.Fatalf("sample preflight = %+v", sample)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 3600})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "AF20023", "message": "ActivityFeed.Read permission is required"}})
	}))
	defer server.Close()
	c := newClient(Config{ClientID: "client", ClientSecret: "secret", TenantID: "directory"}, testLogger(), nil)
	c.base, c.loginBase = server.URL, server.URL
	missing := c.Preflight(context.Background(), "ten_1")
	if missing.Status != "missing" || !strings.Contains(missing.Detail, Permission) {
		t.Fatalf("missing preflight = %+v", missing)
	}
}

func TestClientCollectFastIdentityNormalizesSignIns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = r.ParseForm()
			if r.Form.Get("scope") != "https://graph.microsoft.com/.default" {
				t.Fatalf("token scope = %q", r.Form.Get("scope"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "graph-token", "expires_in": 3600})
		case r.URL.Path == "/auditLogs/signIns":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{
				{"id": "signin-ok", "createdDateTime": "2026-08-25T15:00:00.123Z", "userPrincipalName": "user@example.com", "ipAddress": "203.0.113.5", "resourceDisplayName": "Microsoft 365", "status": map[string]any{"errorCode": 0}, "location": map[string]any{"countryOrRegion": "US"}},
				{"id": "signin-fail", "createdDateTime": "2026-08-25T15:00:30Z", "userPrincipalName": "user@example.com", "ipAddress": "203.0.113.5", "status": map[string]any{"errorCode": 50126}},
			}})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	c := newClient(Config{ClientID: "client", ClientSecret: "secret", TenantID: "directory"}, testLogger(), nil)
	c.graphBase, c.loginBase = server.URL, server.URL
	at := time.Date(2026, 8, 25, 15, 1, 0, 0, time.UTC)
	events, err := c.CollectFastIdentity(context.Background(), "ten_1", ContentTypeEntraSignIn, at.Add(-time.Minute), at)
	if err != nil || len(events) != 2 {
		t.Fatalf("CollectFastIdentity events=%+v err=%v", events, err)
	}
	if events[0].Operation != "UserLoggedIn" || events[0].ResultStatus != "Succeeded" || events[1].Operation != "UserLoginFailed" || events[1].ResultStatus != "Failed" {
		t.Fatalf("normalized sign-ins = %+v", events)
	}
	if len(events[0].Sources) != 1 || events[0].Sources[0] != "entra_graph" || !events[0].AvailableAt.Equal(at) {
		t.Fatalf("source lifecycle = %+v", events[0])
	}
}

func TestNormalizeFastDirectoryAudit(t *testing.T) {
	raw := json.RawMessage(`{"id":"audit-1","activityDateTime":"2026-08-25T15:00:00Z","activityDisplayName":"Add member to role","result":"success","initiatedBy":{"user":{"userPrincipalName":"admin@example.com","ipAddress":"192.0.2.4"}},"targetResources":[{"displayName":"Global Administrator"}]}`)
	event, err := normalizeFastIdentityEvent("ten_1", ContentTypeEntraDirectoryAudit, raw, time.Now().UTC())
	if err != nil || event.Operation != "Add member to role" || event.Actor != "admin@example.com" || event.ClientIP != "192.0.2.4" || event.ObjectID != "Global Administrator" {
		t.Fatalf("event=%+v err=%v", event, err)
	}
	if detections := Detect([]model.SecurityAuditEvent{event}, time.Now().UTC()); len(detections) != 1 || detections[0].RuleID != "privileged_role_change" {
		t.Fatalf("detections=%+v", detections)
	}
}

func TestFastDirectoryAuditCoversPriorityChangeFamilies(t *testing.T) {
	tests := []struct {
		operation string
		rule      string
	}{
		{"Add user", "account_lifecycle_change"},
		{"Add member to group", "group_membership_change"},
		{"Add member to role", "privileged_role_change"},
		{"Add application", "application_registration"},
	}
	for index, test := range tests {
		t.Run(test.rule, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{
				"id": fmt.Sprintf("audit-%d", index), "activityDateTime": "2026-08-25T15:00:00Z",
				"activityDisplayName": test.operation, "result": "success",
				"initiatedBy":     map[string]any{"user": map[string]any{"userPrincipalName": "admin@example.com"}},
				"targetResources": []any{map[string]any{"displayName": "target"}},
			})
			event, err := normalizeFastIdentityEvent("ten_1", ContentTypeEntraDirectoryAudit, raw, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := detectionRuleIDs(Detect([]model.SecurityAuditEvent{event}, time.Now().UTC()))[test.rule]; !ok {
				t.Fatalf("operation %q did not produce %s", test.operation, test.rule)
			}
		})
	}
}
