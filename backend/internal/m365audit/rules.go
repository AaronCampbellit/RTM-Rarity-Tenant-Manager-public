package m365audit

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/model"
)

type builtInRuleSpec struct {
	id, name, description, detectionType, severity, confidence string
	threshold, windowMinutes                                   int
}

var correlatedRuleCatalog = []builtInRuleSpec{
	{"mass_mailbox_forwarding", "Mass mailbox forwarding changes", "Detects forwarding or redirect changes across many mailboxes.", DetectionThreshold, "Critical", ConfidenceHigh, 5, 30},
	{"new_forwarding_domain", "Forwarding to a newly observed domain", "Detects a destination outside the retained forwarding-domain baseline.", DetectionHeuristic, "High", ConfidenceMedium, 1, 0},
	{"large_group_membership_change", "Large group membership change", "Detects many group membership changes by one actor.", DetectionThreshold, "Medium", ConfidenceHigh, 20, 15},
	{"bulk_file_download", "Bulk SharePoint/OneDrive downloads", "Detects access to many distinct SharePoint or OneDrive objects.", DetectionThreshold, "High", ConfidenceMedium, 50, 15},
	{"bulk_file_deletion", "Bulk SharePoint/OneDrive deletions", "Detects deletion of many distinct SharePoint or OneDrive objects.", DetectionThreshold, "High", ConfidenceMedium, 20, 15},
	{"bulk_external_sharing", "Bulk SharePoint/OneDrive sharing", "Detects sharing changes across many distinct objects.", DetectionThreshold, "High", ConfidenceMedium, 10, 15},
	{"repeated_administrative_failures", "Repeated administrative failures", "Detects repeated failed administrative operations.", DetectionThreshold, "Medium", ConfidenceHigh, 5, 10},
	{"administrator_object_burst", "Administrator changed many objects rapidly", "Detects one administrator changing many distinct objects.", DetectionThreshold, "High", ConfidenceMedium, 15, 10},
	{"cross_tenant_administrator_burst", "Administrator activity burst across tenants", "Detects one administrator rapidly changing objects across managed tenants.", DetectionCorrelation, "High", ConfidenceMedium, 15, 15},
	{"unusual_administrator_ip", "Administrator used a newly observed IP", "Compares administrator IP activity with the retained seven-day baseline.", DetectionHeuristic, "Medium", ConfidenceLow, 10, 10080},
	{"unusual_administrator_country", "Administrator active from a newly observed country", "Compares administrator country activity with the retained seven-day baseline.", DetectionHeuristic, "Medium", ConfidenceLow, 10, 10080},
	{"unusual_administrator_time", "Administrator active at an unusual UTC hour", "Compares UTC activity hour with the retained administrator baseline.", DetectionHeuristic, "Low", ConfidenceLow, 20, 10080},
	{"failed_logins_then_success", "Repeated failed logins followed by success", "Detects repeated login failures immediately followed by a success.", DetectionCorrelation, "High", ConfidenceHigh, 5, 15},
	{"possible_impossible_travel", "Possible impossible-travel login", "Compares countries on consecutive successful audit login records.", DetectionHeuristic, "High", ConfidenceMedium, 2, 120},
	{"possible_session_token_reuse", "Possible stolen-session or token reuse", "Detects one session identifier from different IPs in a short interval.", DetectionCorrelation, "High", ConfidenceMedium, 2, 30},
}

// BuiltInRules is the immutable rule catalog shown in Admin. A stored override
// may retain the specialized detector or replace it with an editable event
// match; the catalog itself is never mutated.
func BuiltInRules() []model.SecurityDetectionRule {
	now := time.Time{}
	out := make([]model.SecurityDetectionRule, 0, len(directRules)+len(correlatedRuleCatalog))
	for _, candidate := range directRules {
		out = append(out, model.SecurityDetectionRule{
			ID: "builtin:" + candidate.id, RuleID: candidate.id,
			Name: candidate.title, Description: candidate.description,
			BuiltIn: true, Locked: true, DetectionType: DetectionDirect,
			Severity: candidate.severity, Confidence: candidate.confidence,
			Enabled: true, Scope: "global", Revision: 1, UpdatedBy: "System",
			Definition: model.SecurityRuleDefinition{TriggerMode: "builtIn"},
			CreatedAt:  now, UpdatedAt: now,
		})
	}
	for _, candidate := range correlatedRuleCatalog {
		out = append(out, model.SecurityDetectionRule{
			ID: "builtin:" + candidate.id, RuleID: candidate.id,
			Name: candidate.name, Description: candidate.description,
			BuiltIn: true, Locked: true, DetectionType: candidate.detectionType,
			Severity: candidate.severity, Confidence: candidate.confidence,
			Enabled: true, Scope: "global", Revision: 1, UpdatedBy: "System",
			Definition: model.SecurityRuleDefinition{TriggerMode: "builtIn", Threshold: candidate.threshold, WindowMinutes: candidate.windowMinutes},
			CreatedAt:  now, UpdatedAt: now,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type effectiveRule struct {
	enabled              bool
	severity, confidence string
	name, description    string
	threshold            int
	window               time.Duration
	version              int
	exclusions           []model.SecurityRuleExclusion
}

type ruleSet struct {
	configs []model.SecurityDetectionRule
}

func newRuleSet(configs []model.SecurityDetectionRule) ruleSet {
	return ruleSet{configs: append([]model.SecurityDetectionRule(nil), configs...)}
}

func (r ruleSet) selected(ruleID, tenantID string) *model.SecurityDetectionRule {
	var global, tenant *model.SecurityDetectionRule
	for i := range r.configs {
		config := &r.configs[i]
		if config.BaseRuleID != ruleID {
			continue
		}
		if config.Scope == "tenant" && config.TenantID == tenantID {
			tenant = config
		} else if config.Scope == "global" {
			global = config
		}
	}
	if tenant != nil {
		return tenant
	}
	return global
}

func (r ruleSet) effective(ruleID, tenantID, severity, confidence string, threshold, windowMinutes int) effectiveRule {
	effective := effectiveRule{
		enabled: true, severity: severity, confidence: confidence,
		threshold: threshold, window: time.Duration(windowMinutes) * time.Minute, version: 1,
	}
	selected := r.selected(ruleID, tenantID)
	if selected == nil {
		return effective
	}
	if selected.Definition.TriggerMode == "custom" {
		// The editable replacement is evaluated through the generic rule engine,
		// so the specialized built-in must not also emit a duplicate detection.
		effective.enabled = false
		return effective
	}
	effective.enabled = selected.Enabled
	effective.severity, effective.confidence = selected.Severity, selected.Confidence
	baseName, baseDescription := builtInRuleText(ruleID)
	if selected.Name != baseName {
		effective.name = selected.Name
	}
	if selected.Description != baseDescription {
		effective.description = selected.Description
	}
	effective.version = selected.Revision
	if selected.Definition.Threshold > 0 {
		effective.threshold = selected.Definition.Threshold
	}
	if selected.Definition.WindowMinutes > 0 {
		effective.window = time.Duration(selected.Definition.WindowMinutes) * time.Minute
	}
	effective.exclusions = selected.Definition.Exclusions
	return effective
}

func builtInRuleText(ruleID string) (string, string) {
	for _, candidate := range directRules {
		if candidate.id == ruleID {
			return candidate.title, candidate.description
		}
	}
	for _, candidate := range correlatedRuleCatalog {
		if candidate.id == ruleID {
			return candidate.name, candidate.description
		}
	}
	return "", ""
}

func (r effectiveRule) title(fallback string) string {
	if r.name != "" {
		return r.name
	}
	return fallback
}

func (r effectiveRule) detail(fallback string) string {
	if r.description != "" {
		return r.description
	}
	return fallback
}

func (r ruleSet) allows(ruleID string, event model.SecurityAuditEvent, severity, confidence string) (effectiveRule, bool) {
	effective := r.effective(ruleID, event.TenantID, severity, confidence, 0, 0)
	return effective, effective.enabled && !eventExcluded(event, effective.exclusions)
}

func eventExcluded(event model.SecurityAuditEvent, exclusions []model.SecurityRuleExclusion) bool {
	for _, exclusion := range exclusions {
		var actual string
		switch exclusion.Field {
		case "actor":
			actual = event.Actor
		case "clientIp":
			actual = event.ClientIP
		case "objectId":
			actual = event.ObjectID
		case "tenantId":
			actual = event.TenantID
		default:
			continue
		}
		if exclusion.Match == "contains" && strings.Contains(strings.ToLower(actual), strings.ToLower(exclusion.Value)) ||
			exclusion.Match != "contains" && strings.EqualFold(actual, exclusion.Value) {
			return true
		}
	}
	return false
}

func (r ruleSet) customRules() []model.SecurityDetectionRule {
	var out []model.SecurityDetectionRule
	for _, config := range r.configs {
		if config.BaseRuleID == "" && !config.BuiltIn && config.Enabled {
			out = append(out, config)
		}
	}
	return out
}

func (r ruleSet) replacementRules() []model.SecurityDetectionRule {
	var out []model.SecurityDetectionRule
	for _, config := range r.configs {
		if config.BaseRuleID != "" && config.Definition.TriggerMode == "custom" && config.Enabled {
			out = append(out, config)
		}
	}
	return out
}

func (r ruleSet) replacementEvents(events []model.SecurityAuditEvent, rule model.SecurityDetectionRule) []model.SecurityAuditEvent {
	out := make([]model.SecurityAuditEvent, 0, len(events))
	for _, event := range events {
		selected := r.selected(rule.BaseRuleID, event.TenantID)
		if selected != nil && selected.ID == rule.ID {
			out = append(out, event)
		}
	}
	return out
}

func matchCustomEvent(rule model.SecurityDetectionRule, event model.SecurityAuditEvent) bool {
	if rule.Scope == "tenant" && rule.TenantID != event.TenantID || eventExcluded(event, rule.Definition.Exclusions) {
		return false
	}
	definition := rule.Definition
	if len(definition.Workloads) > 0 && !containsFold(definition.Workloads, event.Workload, true) {
		return false
	}
	if len(definition.Operations) > 0 && !containsFold(definition.Operations, event.Operation, definition.OperationMatch == "exact") {
		return false
	}
	if len(definition.Actors) > 0 && !containsFold(definition.Actors, event.Actor, false) {
		return false
	}
	if len(definition.ClientIPs) > 0 && !containsFold(definition.ClientIPs, event.ClientIP, true) {
		return false
	}
	if len(definition.Results) > 0 && !containsFold(definition.Results, event.ResultStatus, true) {
		return false
	}
	if len(definition.ObjectContains) > 0 && !containsFold(definition.ObjectContains, event.ObjectID, false) {
		return false
	}
	raw := strings.ToLower(string(event.Raw))
	for _, required := range definition.RawContains {
		if !strings.Contains(raw, strings.ToLower(required)) {
			return false
		}
	}
	return len(definition.Operations)+len(definition.Workloads)+len(definition.Actors)+len(definition.ClientIPs)+len(definition.Results)+len(definition.ObjectContains)+len(definition.RawContains) > 0
}

func containsFold(expected []string, actual string, exact bool) bool {
	actual = strings.ToLower(actual)
	for _, value := range expected {
		value = strings.ToLower(strings.TrimSpace(value))
		if exact && actual == value || !exact && strings.Contains(actual, value) {
			return true
		}
	}
	return false
}

func evaluateCustomRule(events []model.SecurityAuditEvent, rule model.SecurityDetectionRule, createdAt time.Time) []model.SecurityNativeDetection {
	var matched []model.SecurityAuditEvent
	for _, event := range events {
		if matchCustomEvent(rule, event) {
			matched = append(matched, event)
		}
	}
	if rule.DetectionType == DetectionDirect {
		out := make([]model.SecurityNativeDetection, 0, len(matched))
		for _, event := range matched {
			out = append(out, makeDetection(rule.RuleID, max(1, rule.Revision), rule.Name, rule.Description,
				rule.Severity, DetectionDirect, rule.Confidence, event, event.ID, createdAt))
		}
		return out
	}
	threshold := rule.Definition.Threshold
	window := time.Duration(rule.Definition.WindowMinutes) * time.Minute
	if threshold < 2 || window <= 0 {
		return nil
	}
	groups := map[string][]model.SecurityAuditEvent{}
	for _, event := range matched {
		key := event.TenantID + "|"
		switch rule.Definition.GroupBy {
		case "clientIp":
			key += strings.ToLower(event.ClientIP)
		case "objectId":
			key += strings.ToLower(event.ObjectID)
		case "tenant":
		default:
			key += strings.ToLower(event.Actor)
		}
		groups[key] = append(groups[key], event)
	}
	var out []model.SecurityNativeDetection
	for _, group := range groups {
		out = append(out, thresholdWindows(group, window, threshold, func(events []model.SecurityAuditEvent) (model.SecurityAuditEvent, string, string, bool) {
			anchor := events[len(events)-1]
			return anchor, rule.Name, fmt.Sprintf("%s matched %d events within %d minutes.", rule.Description, len(events), rule.Definition.WindowMinutes), true
		}, rule.RuleID, max(1, rule.Revision), rule.Severity, DetectionThreshold, rule.Confidence, createdAt)...)
	}
	return out
}

func DetectCustom(events []model.SecurityAuditEvent, createdAt time.Time, configs []model.SecurityDetectionRule) []model.SecurityNativeDetection {
	var out []model.SecurityNativeDetection
	for _, rule := range newRuleSet(configs).customRules() {
		if rule.DetectionType == DetectionDirect {
			out = append(out, evaluateCustomRule(events, rule, createdAt)...)
		}
	}
	return out
}

func PreviewRule(events []model.SecurityAuditEvent, rule model.SecurityDetectionRule, createdAt time.Time) []model.SecurityNativeDetection {
	rule.Enabled = true
	if rule.BuiltIn || rule.BaseRuleID != "" {
		if rule.BaseRuleID == "" {
			rule.BaseRuleID = rule.RuleID
		}
		rule.BuiltIn = true
		rules := []model.SecurityDetectionRule{rule}
		all := append(DetectConfigured(events, createdAt, rules), CorrelateConfigured(events, createdAt, rules)...)
		var out []model.SecurityNativeDetection
		for _, detection := range all {
			if detection.RuleID == rule.BaseRuleID {
				out = append(out, detection)
			}
		}
		return out
	}
	return evaluateCustomRule(events, rule, createdAt)
}
