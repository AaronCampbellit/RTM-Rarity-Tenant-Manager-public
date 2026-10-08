package m365audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/model"
)

const (
	DetectionDirect      = "direct"
	DetectionThreshold   = "threshold"
	DetectionCorrelation = "correlation"
	DetectionHeuristic   = "heuristic"
	ConfidenceHigh       = "high"
	ConfidenceMedium     = "medium"
	ConfidenceLow        = "low"
)

type rule struct {
	id, title, description, severity, confidence string
	match                                        func(model.SecurityAuditEvent, time.Time) bool
}

var directRules = []rule{
	{"suspicious_mail_forwarding", "Mailbox forwarding or redirect changed", "A mailbox forwarding or inbox-rule redirect setting changed. Verify the destination and administrator intent.", "High", ConfidenceHigh, func(e model.SecurityAuditEvent, _ time.Time) bool { return matchesForwarding(e) }},
	{"mailbox_delegation_change", "Mailbox delegation or permission changed", "A mailbox, recipient, or mailbox-folder delegation changed. Confirm the delegate and approved access request.", "High", ConfidenceHigh, simpleMatch("mailboxpermission", "recipientpermission", "mailboxfolderpermission", "send on behalf")},
	{"transport_rule_change", "Exchange transport rule changed", "A mail-flow transport rule was created, modified, enabled, disabled, or removed. Review conditions, redirects, and bypass actions.", "High", ConfidenceHigh, simpleMatch("transport rule", "transportrule")},
	{"inbox_rule_change", "Inbox rule changed", "An inbox rule was created, modified, enabled, disabled, or deleted. Review unexpected delete, move, mark-read, and concealment behavior.", "Medium", ConfidenceHigh, matchesNonForwardingInboxRule},
	{"privileged_role_change", "Privileged administrative role membership changed", "Membership, eligibility, or an administrative role assignment changed in Entra, Exchange, or Purview. Confirm the actor and approved change record.", "High", ConfidenceHigh, matchesPrivilegedRoleChange},
	{"privileged_role_policy_change", "Privileged role or PIM policy changed", "A directory role-management or PIM policy changed. Review activation requirements, approval, duration, and authentication context.", "High", ConfidenceHigh, simpleMatch("role management policy", "role management setting", "role setting", "pim policy")},
	{"guest_invitation", "Guest user invited or created", "An external guest was invited or created. Confirm the sponsor, target organization, and intended access.", "Low", ConfidenceHigh, simpleMatch("invite external user", "invited user", "guest user", "redeem external user invite")},
	{"guest_privilege_escalation", "Guest account received privileged access", "A guest or external identity was added to a role or privileged assignment. Treat this as high-impact until approved.", "High", ConfidenceMedium, matchesGuestPrivilege},
	{"group_owner_change", "Group ownership changed", "An owner was added to or removed from a group. Validate the new ownership and group sensitivity.", "Medium", ConfidenceHigh, simpleMatch("owner to group", "owner from group", "add group owner", "remove group owner")},
	{"group_membership_change", "Group membership changed", "A group member was added or removed. RTM also correlates unusually large membership changes separately.", "Low", ConfidenceHigh, simpleMatch("member to group", "member from group", "add group member", "remove group member")},
	{"account_lifecycle_change", "User account lifecycle changed", "A user account was created, deleted, enabled, or disabled. Confirm the identity lifecycle request and source of authority.", "Medium", ConfidenceHigh, matchesAccountLifecycle},
	{"password_reset", "User password reset or changed", "A password reset or forced password change was recorded. Validate the actor and help-desk request.", "Medium", ConfidenceHigh, simpleMatch("reset password", "reset user password", "change user password", "change password", "force change password")},
	{"authentication_method_change", "User authentication method changed", "A user's authentication/security information changed. Validate this against the user's recent help-desk activity because an attacker can register a new sign-in method for persistence.", "High", ConfidenceHigh, simpleMatch("security info", "authentication method")},
	{"suspicious_authentication_reported", "Suspicious authentication activity reported", "A user reported suspicious authentication activity or MFA fraud. Treat the account as potentially compromised until validated.", "High", ConfidenceHigh, simpleMatch("suspicious activity reported", "fraud reported - user is blocked for mfa", "fraud reported - no action taken")},
	{"conditional_access_change", "Conditional Access policy changed", "A Conditional Access policy was added, changed, disabled, or deleted. Review exclusions and enforcement state.", "High", ConfidenceHigh, simpleMatch("conditional access policy")},
	{"named_location_change", "Conditional Access named location changed", "A named location used by Conditional Access was added, updated, or deleted. Review trusted-location status and included IP ranges or countries.", "High", ConfidenceHigh, simpleMatch("add named location", "update named location", "delete named location")},
	{"security_defaults_change", "Entra security defaults changed", "Microsoft Entra security defaults were changed. Confirm whether baseline identity protections were enabled or disabled and whether Conditional Access replaces them.", "High", ConfidenceHigh, simpleMatch("update security defaults")},
	{"authorization_policy_change", "Tenant authorization policy changed", "The tenant authorization policy changed. Review guest permissions, default user permissions, and user-consent behavior.", "High", ConfidenceHigh, simpleMatch("update authorization policy")},
	{"cross_tenant_access_policy_change", "Cross-tenant access policy changed", "A default or partner-specific cross-tenant access setting changed. Review inbound/outbound trust, MFA trust, and tenant restrictions.", "High", ConfidenceHigh, simpleMatch("cross-tenant access setting", "cross tenant access setting")},
	{"domain_federation_change", "Domain federation or authentication changed", "A domain authentication mode or federation trust changed. Validate issuer, endpoints, signing certificates, and the approved identity-provider change.", "Critical", ConfidenceHigh, simpleMatch("set domain authentication", "set federation settings on domain", "set federation settings")},
	{"tenant_domain_change", "Tenant domain added, removed, or verified", "A tenant domain was added, removed, updated, or verified. Confirm ownership, DNS validation, and the approved domain-lifecycle request.", "High", ConfidenceHigh, matchesTenantDomainChange},
	{"hybrid_authentication_change", "Hybrid authentication configuration changed", "A directory synchronization, desktop SSO, or pass-through authentication setting changed. Confirm the hybrid identity maintenance window and resulting sign-in path.", "High", ConfidenceHigh, simpleMatch("set dirsyncenabled flag", "set dirsync feature", "desktop sso", "passthrough authentication", "pass-through authentication")},
	{"application_registration", "Application or service principal registered", "An application or service principal was created. Confirm ownership, publisher, and required permissions.", "Medium", ConfidenceHigh, matchesApplicationRegistration},
	{"application_configuration_change", "Application or service-principal configuration changed", "An existing application or service principal changed. Review redirect URIs, identifier URIs, sign-in audience, account state, and other authentication settings.", "Medium", ConfidenceHigh, matchesApplicationConfigurationChange},
	{"application_owner_change", "Application or service-principal owner changed", "An owner was added to or removed from an application or service principal. Owners can manage credentials and application configuration.", "High", ConfidenceHigh, simpleMatch("owner to application", "owner from application", "owner to service principal", "owner from service principal")},
	{"oauth_consent", "OAuth consent or app-role assignment changed", "An OAuth consent or app-role assignment changed. Review scopes, consent type, and service-principal ownership.", "High", ConfidenceHigh, simpleMatch("consent to application", "oauth2permissiongrant", "app role assignment")},
	{"high_risk_app_permission", "High-risk application permission granted", "An application consent or role assignment references a high-impact directory, mail, site, or identity permission.", "High", ConfidenceMedium, matchesHighRiskPermission},
	{"application_secret_change", "Application credential created or changed", "A service-principal or application secret/certificate was created, updated, or removed. Confirm the owner and credential rotation request.", "High", ConfidenceHigh, simpleMatch("service principal credentials", "certificates and secrets", "application credential")},
	{"application_secret_expiring", "New application credential expires soon", "A credential-change event contains an expiration within 30 days. This only evaluates expiration values present in the audit event.", "Low", ConfidenceMedium, matchesExpiringCredential},
	{"sharepoint_permission_change", "SharePoint permission or administrator changed", "A SharePoint permission, group membership, site administrator, or sharing permission changed.", "Medium", ConfidenceHigh, matchesSharePointPermission},
	{"external_sharing_change", "External or anonymous sharing changed", "A sharing invitation, anonymous link, or external-sharing configuration was created or modified.", "Medium", ConfidenceHigh, simpleMatch("anonymouslinkcreated", "sharinginvitationcreated", "sharingset", "anonymous link", "external sharing")},
	{"outlook_connector_change", "Exchange Online connector changed", "An inbound or outbound Exchange Online connector was created, modified, enabled, disabled, or removed. Validate routing and TLS restrictions.", "High", ConfidenceHigh, simpleMatch("inboundconnector", "outboundconnector", "inbound connector", "outbound connector")},
	{"mail_protection_policy_change", "Exchange mail-protection policy changed", "An anti-phishing, anti-spam, malware, Safe Links, Safe Attachments, or quarantine policy/rule changed. Review protection actions, exceptions, scope, and enabled state.", "High", ConfidenceHigh, matchesMailProtectionPolicyChange},
	{"mailbox_audit_bypass_change", "Mailbox audit bypass changed", "A mailbox audit bypass association changed. Confirm whether bypass was enabled and whether the account is approved to perform unaudited mailbox actions.", "High", ConfidenceHigh, simpleMatch("mailboxauditbypassassociation", "mailbox audit bypass")},
	{"mailbox_auditing_disabled", "Organization-wide mailbox auditing disabled", "Exchange organization configuration disabled mailbox auditing. Restore auditing immediately unless this is an explicitly approved emergency change.", "Critical", ConfidenceHigh, matchesMailboxAuditingDisabled},
	{"audit_log_search", "Audit log search executed or changed", "An audit-log search, export, or search configuration was executed or modified. Confirm the investigation and evidence-handling request.", "Low", ConfidenceHigh, simpleMatch("search-unifiedauditlog", "auditlogsearch", "audit log search", "compliancesearch", "searchqueryinitiated", "searchqueryperformed")},
	{"audit_configuration_change", "Audit configuration changed", "A Microsoft 365 audit configuration changed. Verify unified audit ingestion remains enabled and retention still meets policy.", "High", ConfidenceHigh, simpleMatch("adminauditlogconfig", "unifiedauditlogingestion", "audit disabled", "disable audit")},
	{"single_factor_authentication", "Single-factor authentication sign-in observed", "A successful Entra sign-in explicitly reports a single-factor authentication requirement. Validate the account's MFA registration and Conditional Access coverage.", "High", ConfidenceHigh, matchesSingleFactorAuthentication},
	{"legacy_authentication", "Legacy authentication activity observed", "A login audit event references a legacy client protocol that may bypass modern authentication controls.", "Medium", ConfidenceMedium, matchesLegacyAuthentication},
}

func simpleMatch(parts ...string) func(model.SecurityAuditEvent, time.Time) bool {
	return func(event model.SecurityAuditEvent, _ time.Time) bool { return operationContains(event, parts...) }
}

func operationContains(event model.SecurityAuditEvent, parts ...string) bool {
	operation := strings.ToLower(event.Operation)
	for _, part := range parts {
		if strings.Contains(operation, part) {
			return true
		}
	}
	return false
}

func matchesForwarding(event model.SecurityAuditEvent) bool {
	if !operationContains(event, "set-mailbox", "new-inboxrule", "set-inboxrule", "updateinboxrules", "inbox rule") {
		return false
	}
	raw := strings.ToLower(string(event.Raw))
	return strings.Contains(raw, "forward") || strings.Contains(raw, "redirect")
}

func matchesNonForwardingInboxRule(event model.SecurityAuditEvent, _ time.Time) bool {
	return operationContains(event, "new-inboxrule", "set-inboxrule", "remove-inboxrule", "updateinboxrules", "inbox rule") && !matchesForwarding(event)
}

func matchesGuestPrivilege(event model.SecurityAuditEvent, _ time.Time) bool {
	if !operationContains(event, "member to role", "eligible member to role", "role assignment") {
		return false
	}
	raw := strings.ToLower(string(event.Raw))
	return (strings.Contains(raw, "usertype") && strings.Contains(raw, "guest")) || strings.Contains(raw, "#ext#") || strings.Contains(raw, "external user")
}

func matchesPrivilegedRoleChange(event model.SecurityAuditEvent, _ time.Time) bool {
	// Entra uses "app role assignment" for application permissions. Those are
	// OAuth/app-consent evidence, not directory administrator membership.
	if operationContains(event, "app role assignment") {
		return false
	}
	return operationContains(event,
		"member to role", "member from role", "eligible member to role", "role assignment",
		"rolegroupmember", "role group member", "managementroleassignment", "management role assignment",
		"rbac role group", "grantpermissionsasync", "deletepermissionasync")
}

func matchesSharePointPermission(event model.SecurityAuditEvent, _ time.Time) bool {
	if operationContains(event, "sitecollectionadmin", "site collection admin", "permissionlevel", "permission level", "sharingpermission", "securelinkcreated") {
		return true
	}
	return isSharePointEvent(event) && operationContains(event, "added to group", "removed from group", "addedtogroup", "removedfromgroup")
}

func matchesAccountLifecycle(event model.SecurityAuditEvent, _ time.Time) bool {
	if operationContains(event, "add user", "create user", "delete user", "disable account", "enable account", "account enabled", "account disabled") {
		return true
	}
	if operationContains(event, "update user") {
		raw := strings.ToLower(string(event.Raw))
		return strings.Contains(raw, "accountenabled")
	}
	return false
}

func matchesApplicationRegistration(event model.SecurityAuditEvent, _ time.Time) bool {
	return operationContains(event, "add application", "create application", "add service principal", "create service principal")
}

func matchesApplicationConfigurationChange(event model.SecurityAuditEvent, _ time.Time) bool {
	if operationContains(event, "certificates and secrets", "application credential", "service principal credentials") {
		return false
	}
	return operationContains(event, "update application", "update service principal", "set service principal")
}

func matchesTenantDomainChange(event model.SecurityAuditEvent, _ time.Time) bool {
	return operationContains(event,
		"add domain to company", "remove domain from company", "update domain",
		"verify domain", "verify email verified domain")
}

var highRiskPermissions = []string{
	"directory.readwrite.all", "rolemanagement.readwrite.directory", "application.readwrite.all",
	"mail.readwrite", "mail.send", "sites.fullcontrol.all", "sites.readwrite.all",
	"user.readwrite.all", "group.readwrite.all", "groupmember.readwrite.all",
	"policy.readwrite.conditionalaccess", "identityriskyevent.readwrite.all",
}

func matchesHighRiskPermission(event model.SecurityAuditEvent, _ time.Time) bool {
	if !operationContains(event, "consent to application", "oauth2permissiongrant", "app role assignment", "permission grant") {
		return false
	}
	raw := strings.ToLower(string(event.Raw))
	for _, permission := range highRiskPermissions {
		if strings.Contains(raw, permission) {
			return true
		}
	}
	return false
}

func matchesExpiringCredential(event model.SecurityAuditEvent, now time.Time) bool {
	if !operationContains(event, "service principal credentials", "certificates and secrets", "application credential") {
		return false
	}
	value := rawString(event, "EndDateTime", "EndDate", "KeyEndDateTime", "ExpirationDate")
	if value == "" {
		return false
	}
	expires, ok := parseAuditTime(value)
	return ok && expires.After(now) && expires.Before(now.Add(30*24*time.Hour))
}

func parseAuditTime(value string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func matchesLegacyAuthentication(event model.SecurityAuditEvent, _ time.Time) bool {
	if !isLoginEvent(event) {
		return false
	}
	raw := strings.ToLower(string(event.Raw))
	for _, marker := range []string{"imap", "pop3", "smtp auth", "authenticated smtp", "exchange activesync", "mapi over http", "other clients", "legacy authentication"} {
		if strings.Contains(raw, marker) {
			return true
		}
	}
	return false
}

func matchesMailProtectionPolicyChange(event model.SecurityAuditEvent, _ time.Time) bool {
	return operationContains(event,
		"antiphishpolicy", "antiphishrule", "anti-phish policy", "anti-phish rule",
		"hostedcontentfilterpolicy", "hostedcontentfilterrule", "spam filter policy", "spam filter rule",
		"malwarefilterpolicy", "malwarefilterrule", "malware filter policy", "malware filter rule",
		"safelinkspolicy", "safelinksrule", "safe links policy", "safe links rule",
		"safeattachmentpolicy", "safeattachmentrule", "safe attachments policy", "safe attachments rule",
		"quarantinepolicy", "quarantine policy")
}

func matchesMailboxAuditingDisabled(event model.SecurityAuditEvent, _ time.Time) bool {
	return operationContains(event, "set-organizationconfig", "set organization config") &&
		strings.EqualFold(rawString(event, "AuditDisabled"), "true")
}

func matchesSingleFactorAuthentication(event model.SecurityAuditEvent, _ time.Time) bool {
	if !isSuccessfulLogin(event) {
		return false
	}
	requirement := strings.ToLower(strings.TrimSpace(rawString(event, "authenticationRequirement")))
	return requirement == "singlefactorauthentication" || requirement == "singlefactor"
}

func Detect(events []model.SecurityAuditEvent, createdAt time.Time) []model.SecurityNativeDetection {
	return DetectConfigured(events, createdAt, nil)
}

func DetectConfigured(events []model.SecurityAuditEvent, createdAt time.Time, configs []model.SecurityDetectionRule) []model.SecurityNativeDetection {
	out := DetectBuiltInsConfigured(events, createdAt, configs)
	rules := newRuleSet(configs)
	for _, rule := range rules.customRules() {
		if rule.DetectionType == DetectionDirect {
			out = append(out, evaluateCustomRule(events, rule, createdAt)...)
		}
	}
	for _, rule := range rules.replacementRules() {
		if rule.DetectionType == DetectionDirect {
			out = append(out, evaluateCustomRule(rules.replacementEvents(events, rule), rule, createdAt)...)
		}
	}
	return out
}

func DetectBuiltInsConfigured(events []model.SecurityAuditEvent, createdAt time.Time, configs []model.SecurityDetectionRule) []model.SecurityNativeDetection {
	rules := newRuleSet(configs)
	var out []model.SecurityNativeDetection
	for _, event := range events {
		for _, candidate := range directRules {
			if !candidate.match(event, createdAt) {
				continue
			}
			effective, allowed := rules.allows(candidate.id, event, candidate.severity, candidate.confidence)
			if !allowed {
				continue
			}
			out = append(out, makeDetection(candidate.id, effective.version, effective.title(candidate.title), effective.detail(candidate.description),
				effective.severity, DetectionDirect, effective.confidence, event, event.ID, createdAt))
		}
	}
	return out
}

func makeDetection(ruleID string, version int, title, description, severity, detectionType, confidence string, event model.SecurityAuditEvent, identity string, createdAt time.Time) model.SecurityNativeDetection {
	digest := sha256.Sum256([]byte(event.TenantID + "|" + ruleID + "|" + fmt.Sprint(version) + "|" + identity))
	return model.SecurityNativeDetection{
		ID: "rta_" + hex.EncodeToString(digest[:12]), TenantID: event.TenantID,
		EventID: event.ID, EventIDs: []string{event.ID}, RuleID: ruleID, RuleVersion: version,
		Title: title, Description: description, Severity: severity,
		DetectionType: detectionType, Confidence: confidence,
		Entities: eventEntities(event), OccurredAt: event.OccurredAt,
		CreatedAt: createdAt.UTC(), Sample: event.Sample,
	}
}

func eventEntities(event model.SecurityAuditEvent) []model.SecurityEntity {
	entities := make([]model.SecurityEntity, 0, 5)
	if event.Actor != "" {
		entities = append(entities, model.SecurityEntity{Type: "account", Label: event.Actor, Key: normalizedEntityKey(event.TenantID, "account", event.Actor)})
	}
	if event.ObjectID != "" {
		entities = append(entities, model.SecurityEntity{Type: "resource", Label: event.ObjectID, Key: normalizedEntityKey(event.TenantID, "resource", event.ObjectID)})
	}
	if event.ClientIP != "" {
		entities = append(entities, model.SecurityEntity{Type: "ip", Label: event.ClientIP, Key: normalizedEntityKey(event.TenantID, "ip", event.ClientIP)})
	}
	if country := eventCountry(event); country != "" {
		entities = append(entities, model.SecurityEntity{Type: "country", Label: country, Key: normalizedEntityKey(event.TenantID, "country", country)})
	}
	return entities
}

func normalizedEntityKey(tenantID, entityType, value string) string {
	return tenantID + "|" + strings.ToLower(strings.TrimSpace(entityType)) + "|" + strings.ToLower(strings.TrimSpace(value))
}

func rawString(event model.SecurityAuditEvent, keys ...string) string {
	var value any
	if json.Unmarshal(event.Raw, &value) != nil {
		return ""
	}
	wanted := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		wanted[strings.ToLower(key)] = struct{}{}
	}
	return findRawString(value, wanted)
}

func findRawString(value any, wanted map[string]struct{}) string {
	switch typed := value.(type) {
	case map[string]any:
		if name, ok := typed["Name"]; ok {
			if _, wantedName := wanted[strings.ToLower(scalarString(name))]; wantedName {
				if text := scalarString(typed["Value"]); text != "" {
					return text
				}
			}
		}
		for key, child := range typed {
			if _, ok := wanted[strings.ToLower(key)]; ok {
				if text := scalarString(child); text != "" {
					return text
				}
			}
		}
		for _, child := range typed {
			if text := findRawString(child, wanted); text != "" {
				return text
			}
		}
	case []any:
		for _, child := range typed {
			if text := findRawString(child, wanted); text != "" {
				return text
			}
		}
	}
	return ""
}

func scalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return fmt.Sprintf("%.0f", typed)
	case bool:
		return fmt.Sprint(typed)
	default:
		return ""
	}
}

func eventCountry(event model.SecurityAuditEvent) string {
	return rawString(event, "Country", "CountryCode", "CountryOrRegion")
}

func eventUserAgent(event model.SecurityAuditEvent) string {
	return rawString(event, "UserAgent", "ClientInfoString", "ClientAppUsed")
}

func eventSessionID(event model.SecurityAuditEvent) string {
	return rawString(event, "SessionId", "SessionID", "UniqueTokenIdentifier", "TokenId")
}

func isLoginEvent(event model.SecurityAuditEvent) bool {
	return operationContains(event, "userloggedin", "userloginfailed", "user login", "sign-in", "signin", "login")
}

func isSuccessfulLogin(event model.SecurityAuditEvent) bool {
	if !isLoginEvent(event) || isFailure(event) {
		return false
	}
	result := strings.ToLower(event.ResultStatus)
	return operationContains(event, "userloggedin", "successful login") || result == "success" || result == "succeeded" || result == "true"
}

func isFailure(event model.SecurityAuditEvent) bool {
	result := strings.ToLower(event.ResultStatus)
	return operationContains(event, "loginfailed") || strings.Contains(result, "fail") || strings.Contains(result, "denied") || strings.Contains(result, "error") || strings.Contains(result, "invalid") || result == "false"
}

func isAdministrativeEvent(event model.SecurityAuditEvent) bool {
	if isLoginEvent(event) || isFileReadEvent(event) {
		return false
	}
	return operationContains(event, "add", "create", "new-", "set-", "update", "remove", "delete", "enable", "disable", "reset", "change", "grant", "revoke", "consent", "invite", "search")
}

func isFileReadEvent(event model.SecurityAuditEvent) bool {
	return operationContains(event, "fileaccessed", "filedownloaded", "filesynced", "filepreviewed", "file accessed", "file downloaded")
}

func isSharePointEvent(event model.SecurityAuditEvent) bool {
	source := strings.ToLower(event.Workload + " " + event.ContentType)
	return strings.Contains(source, "sharepoint") || strings.Contains(source, "onedrive")
}
