package m365audit

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

var detectionTestNow = time.Date(2026, 8, 25, 6, 0, 0, 0, time.UTC)

func testEvent(id, operation string, at time.Time, raw map[string]any) model.SecurityAuditEvent {
	body, _ := json.Marshal(raw)
	return model.SecurityAuditEvent{
		ID: id, ProviderRecordID: id, TenantID: "ten_1", ContentType: "Audit.General",
		Workload: "General", Operation: operation, Actor: "admin@example.com",
		ClientIP: "203.0.113.10", ObjectID: "object-" + id,
		ResultStatus: "Succeeded", OccurredAt: at, IngestedAt: at, Raw: body,
	}
}

func detectionRuleIDs(detections []model.SecurityNativeDetection) map[string]model.SecurityNativeDetection {
	out := make(map[string]model.SecurityNativeDetection, len(detections))
	for _, detection := range detections {
		out[detection.RuleID] = detection
	}
	return out
}

func TestDetectDirectRulePack(t *testing.T) {
	tests := []struct {
		name, operation, want string
		raw                   map[string]any
	}{
		{"forwarding", "Set-Mailbox", "suspicious_mail_forwarding", map[string]any{"ForwardingSmtpAddress": "external@example.net"}},
		{"delegation", "Add-MailboxPermission", "mailbox_delegation_change", nil},
		{"transport", "New-TransportRule", "transport_rule_change", nil},
		{"inbox", "New-InboxRule", "inbox_rule_change", map[string]any{"MoveToFolder": "Archive"}},
		{"role", "Add member to role.", "privileged_role_change", nil},
		{"purview role", "Add-RoleGroupMember", "privileged_role_change", nil},
		{"role policy", "Update role management policy", "privileged_role_policy_change", nil},
		{"guest", "Invite external user", "guest_invitation", nil},
		{"guest role", "Add member to role.", "guest_privilege_escalation", map[string]any{"UserType": "Guest"}},
		{"group owner", "Add owner to group", "group_owner_change", nil},
		{"group member", "Add member to group", "group_membership_change", nil},
		{"account", "Disable account", "account_lifecycle_change", nil},
		{"password", "Reset user password", "password_reset", nil},
		{"mfa", "Delete user authentication method", "authentication_method_change", nil},
		{"reported fraud", "Suspicious activity reported", "suspicious_authentication_reported", nil},
		{"ca", "Update conditional access policy", "conditional_access_change", nil},
		{"named location", "Update named location", "named_location_change", nil},
		{"security defaults", "Update security defaults", "security_defaults_change", nil},
		{"authorization policy", "Update authorization policy", "authorization_policy_change", nil},
		{"cross-tenant policy", "Update a partner to cross-tenant access setting", "cross_tenant_access_policy_change", nil},
		{"federation", "Set federation settings on domain", "domain_federation_change", nil},
		{"tenant domain", "Verify domain", "tenant_domain_change", nil},
		{"hybrid authentication", "Disable passthrough authentication", "hybrid_authentication_change", nil},
		{"app", "Add application", "application_registration", nil},
		{"app config", "Update service principal", "application_configuration_change", nil},
		{"app owner", "Add owner to application", "application_owner_change", nil},
		{"oauth", "Consent to application", "oauth_consent", nil},
		{"risky consent", "Consent to application", "high_risk_app_permission", map[string]any{"Scope": "Directory.ReadWrite.All Mail.Send"}},
		{"secret", "Update application - Certificates and secrets", "application_secret_change", nil},
		{"expiring secret", "Update application - Certificates and secrets", "application_secret_expiring", map[string]any{"EndDateTime": detectionTestNow.Add(7 * 24 * time.Hour).Format(time.RFC3339)}},
		{"site permission", "SiteCollectionAdminAdded", "sharepoint_permission_change", nil},
		{"external sharing", "AnonymousLinkCreated", "external_sharing_change", nil},
		{"connector", "New-InboundConnector", "outlook_connector_change", nil},
		{"mail protection", "Set-AntiPhishPolicy", "mail_protection_policy_change", nil},
		{"mailbox audit bypass", "Set-MailboxAuditBypassAssociation", "mailbox_audit_bypass_change", map[string]any{"AuditBypassEnabled": true}},
		{"mailbox auditing disabled", "Set-OrganizationConfig", "mailbox_auditing_disabled", map[string]any{"AuditDisabled": true}},
		{"audit search", "Search-UnifiedAuditLog", "audit_log_search", nil},
		{"audit search event", "SearchQueryInitiatedExchange", "audit_log_search", nil},
		{"audit disabled", "Set-UnifiedAuditLogIngestionEnabled", "audit_configuration_change", nil},
		{"single-factor login", "UserLoggedIn", "single_factor_authentication", map[string]any{"authenticationRequirement": "singleFactorAuthentication"}},
		{"legacy login", "UserLoggedIn", "legacy_authentication", map[string]any{"ClientAppUsed": "IMAP"}},
	}
	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := testEvent(fmt.Sprintf("evt-%d", index), tt.operation, detectionTestNow, tt.raw)
			first := detectionRuleIDs(Detect([]model.SecurityAuditEvent{event}, detectionTestNow))
			second := detectionRuleIDs(Detect([]model.SecurityAuditEvent{event}, detectionTestNow.Add(time.Hour)))
			detection, ok := first[tt.want]
			if !ok {
				t.Fatalf("%s missing from %+v", tt.want, first)
			}
			if detection.ID != second[tt.want].ID || detection.DetectionType != DetectionDirect || detection.Confidence == "" || detection.RuleVersion != 1 {
				t.Fatalf("unstable or unclassified detection: %+v / %+v", detection, second[tt.want])
			}
		})
	}
}

func TestDetectIgnoresUnrelatedMailboxChanges(t *testing.T) {
	event := testEvent("sae-1", "Set-Mailbox", detectionTestNow, map[string]any{"AuditEnabled": true})
	if detections := Detect([]model.SecurityAuditEvent{event}, detectionTestNow); len(detections) != 0 {
		t.Fatalf("unrelated mailbox change detected: %+v", detections)
	}
}

func TestMailboxAuditingDisabledRequiresExplicitTrueValue(t *testing.T) {
	event := testEvent("audit-enabled", "Set-OrganizationConfig", detectionTestNow, map[string]any{"AuditDisabled": false})
	if _, exists := detectionRuleIDs(Detect([]model.SecurityAuditEvent{event}, detectionTestNow))["mailbox_auditing_disabled"]; exists {
		t.Fatal("re-enabling mailbox auditing must not produce the disabled detection")
	}
}

func TestApplicationCredentialChangeDoesNotDuplicateConfigurationChange(t *testing.T) {
	event := testEvent("secret-only", "Update application - Certificates and secrets", detectionTestNow, nil)
	rules := detectionRuleIDs(Detect([]model.SecurityAuditEvent{event}, detectionTestNow))
	if _, exists := rules["application_secret_change"]; !exists {
		t.Fatal("credential update must produce the application-secret detection")
	}
	if _, exists := rules["application_configuration_change"]; exists {
		t.Fatal("credential-only update must not duplicate the general application-configuration detection")
	}
}

func TestAppRoleAssignmentIsNotDirectoryRoleMembership(t *testing.T) {
	event := testEvent("sae-app-role", "Add app role assignment to service principal.", detectionTestNow, map[string]any{
		"ModifiedProperties": []map[string]string{{"Name": "AppRole.Value", "NewValue": "Exchange.ManageAsAppV2"}},
	})
	detections := detectionRuleIDs(Detect([]model.SecurityAuditEvent{event}, detectionTestNow))
	if _, exists := detections["privileged_role_change"]; exists {
		t.Fatalf("app permission was misclassified as directory role membership: %+v", detections)
	}
	if _, exists := detections["oauth_consent"]; !exists {
		t.Fatalf("app permission did not produce OAuth/app-role detection: %+v", detections)
	}
}

func TestRawStringReadsManagementActivityParameters(t *testing.T) {
	event := testEvent("sae-1", "Set-Mailbox", detectionTestNow, map[string]any{
		"Parameters": []map[string]any{{"Name": "ForwardingSmtpAddress", "Value": "smtp:user@new.example"}},
	})
	if got := rawString(event, "ForwardingSmtpAddress"); got != "smtp:user@new.example" {
		t.Fatalf("rawString = %q", got)
	}
	if got := forwardingDomain(event); got != "new.example" {
		t.Fatalf("forwardingDomain = %q", got)
	}
}

func TestSharePointGroupChangeRequiresSharePointSource(t *testing.T) {
	event := testEvent("group-event", "AddedToGroup", detectionTestNow, nil)
	if _, ok := detectionRuleIDs(Detect([]model.SecurityAuditEvent{event}, detectionTestNow))["sharepoint_permission_change"]; ok {
		t.Fatal("generic group operation must not be labeled as a SharePoint permission change")
	}
	event.Workload, event.ContentType = "SharePoint", "Audit.SharePoint"
	if _, ok := detectionRuleIDs(Detect([]model.SecurityAuditEvent{event}, detectionTestNow))["sharepoint_permission_change"]; !ok {
		t.Fatal("SharePoint group operation was not detected")
	}
}

func TestExpiringCredentialParsesManagementActivityTimestamp(t *testing.T) {
	event := testEvent("secret-expiry", "Update application - Certificates and secrets", detectionTestNow, map[string]any{
		"Parameters": []map[string]any{{"Name": "EndDateTime", "Value": "2026-09-01T06:00:00"}},
	})
	if _, ok := detectionRuleIDs(Detect([]model.SecurityAuditEvent{event}, detectionTestNow))["application_secret_expiring"]; !ok {
		t.Fatal("timestamp without a timezone was not parsed")
	}
}
