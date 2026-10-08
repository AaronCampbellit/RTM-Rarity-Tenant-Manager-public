// Package storylines deterministically correlates RTM-native detections into
// analyst-facing attack narratives. It is intentionally rules based: every
// score contribution and grouping reason is retained for explanation.
package storylines

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/model"
)

const Lookback = 30 * 24 * time.Hour

type pack struct {
	id, title, summary string
	actions            []string
	rules              map[string]string
	eligible           func(map[string]struct{}, map[string]struct{}, int) bool
}

var packs = []pack{
	{
		id: "account_takeover_bec", title: "Probable account takeover and mailbox persistence",
		summary: "Suspicious identity activity progressed into credential or mailbox persistence and may indicate account takeover or business email compromise.",
		actions: []string{"Revoke active sessions through RTM What-If", "Inspect and remove unapproved authentication methods", "Review mailbox forwarding, delegates, inbox rules, and transport rules", "Reset the password and validate recent sign-ins", "Review external sharing and downloaded resources"},
		rules: mergeRules(
			stageRules("Initial Access", "failed_logins_then_success", "possible_impossible_travel", "possible_session_token_reuse", "suspicious_authentication_reported", "single_factor_authentication", "legacy_authentication"),
			stageRules("Credential Access", "password_reset", "authentication_method_change"),
			stageRules("Persistence", "suspicious_mail_forwarding", "mass_mailbox_forwarding", "new_forwarding_domain", "mailbox_delegation_change", "inbox_rule_change", "transport_rule_change", "outlook_connector_change"),
			stageRules("Collection", "bulk_file_download", "bulk_file_deletion", "bulk_external_sharing", "external_sharing_change", "sharepoint_permission_change"),
		),
		eligible: func(stages, _ map[string]struct{}, signals int) bool {
			return signals >= 2 && has(stages, "Initial Access") && (has(stages, "Credential Access") || has(stages, "Persistence") || has(stages, "Collection"))
		},
	},
	{
		id: "privilege_persistence", title: "Privilege escalation and durable persistence",
		summary: "Connected identity, application, consent, and role changes suggest an attempt to establish or expand durable administrative access.",
		actions: []string{"Validate the initiating administrator sign-in", "Review newly created applications and service principals", "Remove unapproved secrets, OAuth grants, and app-role assignments", "Review directory role and Conditional Access changes", "Revoke sessions for affected identities after preserving evidence"},
		rules: mergeRules(
			stageRules("Initial Access", "possible_impossible_travel", "possible_session_token_reuse", "failed_logins_then_success", "unusual_administrator_ip", "unusual_administrator_country", "unusual_administrator_time"),
			stageRules("Persistence", "application_registration", "application_configuration_change", "application_secret_change", "application_owner_change", "guest_invitation", "domain_federation_change", "hybrid_authentication_change"),
			stageRules("Privilege Escalation", "oauth_consent", "high_risk_app_permission", "privileged_role_change", "privileged_role_policy_change", "guest_privilege_escalation"),
			stageRules("Defense Evasion", "conditional_access_change", "named_location_change", "security_defaults_change", "authorization_policy_change", "cross_tenant_access_policy_change", "audit_configuration_change", "mailbox_auditing_disabled"),
		),
		eligible: func(stages, rules map[string]struct{}, signals int) bool {
			return signals >= 2 && (has(stages, "Privilege Escalation") || len(rules) >= 3) && (has(stages, "Initial Access") || has(stages, "Persistence") || has(stages, "Defense Evasion"))
		},
	},
	{
		id: "data_theft", title: "Possible data theft across Microsoft 365",
		summary: "Suspicious identity or persistence signals were followed by collection or external-sharing activity against Microsoft 365 data.",
		actions: []string{"Contain the affected account and revoke sessions", "Identify downloaded, deleted, and externally shared resources", "Remove unapproved sharing links and mailbox delegates", "Preserve source audit evidence before cleanup", "Notify the tenant incident owner and begin data-impact review"},
		rules: mergeRules(
			stageRules("Initial Access", "failed_logins_then_success", "possible_impossible_travel", "possible_session_token_reuse", "suspicious_authentication_reported"),
			stageRules("Persistence", "suspicious_mail_forwarding", "mailbox_delegation_change", "authentication_method_change"),
			stageRules("Collection", "bulk_file_download", "bulk_file_deletion", "bulk_external_sharing", "external_sharing_change", "sharepoint_permission_change"),
		),
		eligible: func(stages, _ map[string]struct{}, signals int) bool {
			return signals >= 2 && has(stages, "Collection") && (has(stages, "Initial Access") || has(stages, "Persistence"))
		},
	},
	{
		id: "defense_evasion", title: "Possible defense evasion",
		summary: "Privileged activity was connected to changes that may weaken, bypass, or conceal Microsoft 365 security controls. Analyst validation is required.",
		actions: []string{"Confirm whether the change is covered by an approved maintenance record", "Review Conditional Access, auditing, and security-defaults state", "Inspect inbox and transport rules for concealment behavior", "Restore weakened controls through the normal RTM What-If gate", "Review all actions by the same administrator during the storyline window"},
		rules: mergeRules(
			stageRules("Initial Access", "unusual_administrator_ip", "unusual_administrator_country", "unusual_administrator_time", "possible_session_token_reuse", "failed_logins_then_success"),
			stageRules("Privileged Action", "privileged_role_change", "administrator_object_burst", "repeated_administrative_failures"),
			stageRules("Defense Evasion", "conditional_access_change", "named_location_change", "security_defaults_change", "authorization_policy_change", "cross_tenant_access_policy_change", "domain_federation_change", "tenant_domain_change", "hybrid_authentication_change", "audit_configuration_change", "audit_log_search", "mailbox_auditing_disabled", "mailbox_audit_bypass_change", "inbox_rule_change", "transport_rule_change", "outlook_connector_change", "mail_protection_policy_change"),
		),
		eligible: func(stages, _ map[string]struct{}, signals int) bool {
			return signals >= 2 && has(stages, "Defense Evasion") && (has(stages, "Initial Access") || has(stages, "Privileged Action"))
		},
	},
	{
		id: "msp_admin_compromise", title: "Possible MSP administrator compromise across tenants",
		summary: "The same administrator or service principal performed connected suspicious or high-impact activity across multiple managed tenants.",
		actions: []string{"Protect the global storyline and assign an incident commander", "Revoke the MSP identity's active sessions and rotate its credentials", "Review the per-tenant blast radius before making changes", "Validate all recent role, consent, application, forwarding, and account changes", "Notify each affected tenant using the verified impact list"},
		rules: mergeRules(
			stageRules("Initial Access", "unusual_administrator_ip", "unusual_administrator_country", "unusual_administrator_time", "possible_session_token_reuse", "failed_logins_then_success"),
			stageRules("Cross-tenant Activity", "cross_tenant_administrator_burst", "administrator_object_burst", "application_registration", "application_configuration_change", "application_secret_change", "high_risk_app_permission", "privileged_role_change", "suspicious_mail_forwarding", "account_lifecycle_change", "group_owner_change", "conditional_access_change", "audit_configuration_change"),
		),
		eligible: func(_ map[string]struct{}, rules map[string]struct{}, signals int) bool {
			return signals >= 2 && len(rules) >= 2
		},
	},
}

func StageFor(packID, ruleID string) string {
	for _, definition := range packs {
		if definition.id == packID {
			if stage := definition.rules[ruleID]; stage != "" {
				return stage
			}
			return "Observed"
		}
	}
	return "Observed"
}

type candidate struct {
	pack       pack
	groupKey   string
	principal  string
	detections []model.SecurityNativeDetection
}

// Evaluate returns only multi-signal storylines. A single high-severity
// detection remains visible in the incident queue but is not inflated into a
// narrative without independent supporting evidence.
func Evaluate(detections []model.SecurityNativeDetection, events []model.SecurityAuditEvent, tenantNames map[string]string, now time.Time) []model.SecurityStoryline {
	eventsByID := make(map[string]model.SecurityAuditEvent, len(events))
	for _, event := range events {
		eventsByID[event.ID] = event
	}
	groups := map[string]*candidate{}
	for _, detection := range detections {
		if detection.OccurredAt.Before(now.Add(-Lookback)) {
			continue
		}
		event := eventsByID[detection.EventID]
		principal := normalizedPrincipal(detection, event)
		if principal == "" {
			continue
		}
		for _, definition := range packs {
			if _, ok := definition.rules[detection.RuleID]; !ok {
				continue
			}
			groupKey := detection.TenantID + "|" + principal
			if definition.id == "msp_admin_compromise" {
				// Cross-tenant storylines are keyed by the authenticated actor,
				// never by an IP address alone.
				groupKey = principal
			}
			key := definition.id + "|" + groupKey
			if groups[key] == nil {
				groups[key] = &candidate{pack: definition, groupKey: groupKey, principal: principal}
			}
			groups[key].detections = append(groups[key].detections, detection)
		}
	}

	storylines := make([]model.SecurityStoryline, 0, len(groups))
	for _, group := range groups {
		storyline, ok := build(*group, eventsByID, tenantNames, now)
		if ok {
			storylines = append(storylines, storyline)
		}
	}
	sort.Slice(storylines, func(i, j int) bool {
		if storylines[i].RiskScore != storylines[j].RiskScore {
			return storylines[i].RiskScore > storylines[j].RiskScore
		}
		return storylines[i].LastSeen.After(storylines[j].LastSeen)
	})
	return storylines
}

func build(group candidate, events map[string]model.SecurityAuditEvent, tenantNames map[string]string, now time.Time) (model.SecurityStoryline, bool) {
	sort.Slice(group.detections, func(i, j int) bool { return group.detections[i].OccurredAt.Before(group.detections[j].OccurredAt) })
	stages, rules, workloads := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	tenantIDs, detectionIDs, eventIDs := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	entities := map[string]model.SecurityStorylineEntity{}
	sample := false
	for _, detection := range group.detections {
		stages[group.pack.rules[detection.RuleID]] = struct{}{}
		rules[detection.RuleID] = struct{}{}
		tenantIDs[detection.TenantID] = struct{}{}
		detectionIDs[detection.ID] = struct{}{}
		sample = sample || detection.Sample
		ids := detection.EventIDs
		if len(ids) == 0 {
			ids = []string{detection.EventID}
		}
		for _, id := range ids {
			eventIDs[id] = struct{}{}
			if event, ok := events[id]; ok {
				if event.Workload != "" {
					workloads[event.Workload] = struct{}{}
				}
				addEventEntities(entities, detection, event, group.principal)
			}
		}
	}
	if group.pack.id == "msp_admin_compromise" && len(tenantIDs) < 2 {
		return model.SecurityStoryline{}, false
	}
	if !group.pack.eligible(stages, rules, len(group.detections)) {
		return model.SecurityStoryline{}, false
	}

	first, last := group.detections[0].OccurredAt, group.detections[len(group.detections)-1].OccurredAt
	score, reasons, weak := riskScore(group.detections, stages, rules, workloads, tenantIDs, last.Sub(first))
	confidence := storylineConfidence(group.detections, len(rules))
	correlationKey := group.pack.id + "|" + group.groupKey
	digest := sha256.Sum256([]byte(correlationKey))
	story := model.SecurityStoryline{
		ID: "story_" + hex.EncodeToString(digest[:12]), CorrelationKey: correlationKey,
		PackID: group.pack.id, Title: group.pack.title, Summary: group.pack.summary,
		Severity: scoreSeverity(score), RiskScore: score, Confidence: confidence,
		Status: model.SecurityTriageNew, FirstSeen: first.UTC(), LastSeen: last.UTC(), UpdatedAt: now.UTC(),
		TenantIDs: sortedKeys(tenantIDs), Stages: orderedStages(stages), Workloads: sortedKeys(workloads),
		DetectionIDs: sortedKeys(detectionIDs), EventIDs: sortedKeys(eventIDs), SignalCount: len(group.detections),
		Reasons: reasons, WeakEvidence: weak, RecommendedActions: append([]string(nil), group.pack.actions...), Sample: sample,
	}
	for _, tenantID := range story.TenantIDs {
		name := tenantNames[tenantID]
		if name == "" {
			name = tenantID
		}
		story.TenantNames = append(story.TenantNames, name)
	}
	for _, entity := range entities {
		story.Entities = append(story.Entities, entity)
		if entity.Type == "account" {
			story.AffectedUsers++
		} else if entity.Type != "ip" && entity.Type != "country" {
			story.AffectedResources++
		}
	}
	sort.Slice(story.Entities, func(i, j int) bool {
		if story.Entities[i].Primary != story.Entities[j].Primary {
			return story.Entities[i].Primary
		}
		if story.Entities[i].Type != story.Entities[j].Type {
			return story.Entities[i].Type < story.Entities[j].Type
		}
		return story.Entities[i].Label < story.Entities[j].Label
	})
	return story, true
}

func normalizedPrincipal(detection model.SecurityNativeDetection, event model.SecurityAuditEvent) string {
	if value := strings.TrimSpace(event.Actor); value != "" {
		return strings.ToLower(value)
	}
	for _, entity := range detection.Entities {
		if strings.EqualFold(entity.Type, "account") && strings.TrimSpace(entity.Label) != "" {
			return strings.ToLower(strings.TrimSpace(entity.Label))
		}
	}
	return ""
}

func addEventEntities(out map[string]model.SecurityStorylineEntity, detection model.SecurityNativeDetection, event model.SecurityAuditEvent, principal string) {
	add := func(kind, label string, primary bool) {
		label = strings.TrimSpace(label)
		if label == "" {
			return
		}
		key := event.TenantID + "|" + kind + "|" + strings.ToLower(label)
		out[key] = model.SecurityStorylineEntity{Type: kind, Key: key, Label: label, TenantID: event.TenantID, Primary: primary}
	}
	add("account", event.Actor, strings.EqualFold(event.Actor, principal))
	if event.ClientIP != "" {
		add("ip", event.ClientIP, false)
	}
	if event.ObjectID != "" {
		kind := "resource"
		switch {
		case strings.Contains(detection.RuleID, "mailbox") || strings.Contains(detection.RuleID, "forward") || strings.Contains(detection.RuleID, "inbox"):
			kind = "mailbox"
		case strings.Contains(detection.RuleID, "application") || strings.Contains(detection.RuleID, "oauth") || strings.Contains(detection.RuleID, "secret"):
			kind = "application"
		}
		add(kind, event.ObjectID, false)
	}
}

func riskScore(detections []model.SecurityNativeDetection, stages, rules, workloads, tenants map[string]struct{}, span time.Duration) (int, []string, []string) {
	severityWeight := map[string]int{"Critical": 30, "High": 20, "Medium": 11, "Low": 4, "Informational": 1}
	confidenceWeight := map[string]float64{"high": 1, "medium": .75, "low": .5}
	score, highConfidence, novel := 0, 0, false
	weak := []string{}
	for _, detection := range detections {
		weight := severityWeight[detection.Severity]
		if weight == 0 {
			weight = 5
		}
		factor := confidenceWeight[strings.ToLower(detection.Confidence)]
		if factor == 0 {
			factor = .6
		}
		score += int(float64(weight) * factor)
		if strings.EqualFold(detection.Confidence, "high") {
			highConfidence++
		}
		if strings.Contains(detection.RuleID, "unusual") || strings.Contains(detection.RuleID, "impossible") || strings.Contains(detection.RuleID, "new_forwarding") || strings.Contains(detection.RuleID, "session") {
			novel = true
		}
		if strings.EqualFold(detection.Confidence, "low") {
			weak = append(weak, detection.Title+" has low-confidence contextual evidence.")
		}
	}
	if score > 55 {
		score = 55
	}
	independentBonus := min((len(rules)-1)*8, 24)
	stageBonus := min((len(stages)-1)*8, 24)
	score += independentBonus + stageBonus
	if len(workloads) > 1 {
		score += 8
	}
	if len(tenants) > 1 {
		score += 8
	}
	if span <= 30*time.Minute {
		score += 10
	} else if span <= 2*time.Hour {
		score += 5
	}
	if novel {
		score += 5
	}
	if score > 100 {
		score = 100
	}
	reasons := []string{
		fmt.Sprintf("%d independent detection types affected the same normalized identity.", len(rules)),
		fmt.Sprintf("Activity progressed across %d attack stages over %s.", len(stages), humanDuration(span)),
	}
	if len(workloads) > 1 {
		reasons = append(reasons, fmt.Sprintf("Connected evidence spans %d Microsoft 365 workloads.", len(workloads)))
	}
	if len(tenants) > 1 {
		reasons = append(reasons, fmt.Sprintf("The same authenticated actor affected %d managed tenants; IP address was not used as the grouping key.", len(tenants)))
	}
	if novel {
		reasons = append(reasons, "At least one signal contains newly observed, impossible-travel, or possible session-reuse context.")
	}
	if highConfidence > 1 {
		reasons = append(reasons, fmt.Sprintf("%d contributing detections have high-confidence evidence.", highConfidence))
	}
	return score, reasons, weak
}

func storylineConfidence(detections []model.SecurityNativeDetection, ruleCount int) string {
	high := 0
	for _, detection := range detections {
		if strings.EqualFold(detection.Confidence, "high") {
			high++
		}
	}
	if ruleCount >= 3 && high >= 2 {
		return "high"
	}
	if ruleCount >= 2 && high >= 1 {
		return "medium"
	}
	return "low"
}

func scoreSeverity(score int) string {
	switch {
	case score >= 80:
		return "Critical"
	case score >= 60:
		return "High"
	case score >= 35:
		return "Medium"
	default:
		return "Low"
	}
}

func orderedStages(values map[string]struct{}) []string {
	order := []string{"Initial Access", "Credential Access", "Persistence", "Privilege Escalation", "Privileged Action", "Cross-tenant Activity", "Collection", "Defense Evasion", "Impact"}
	out := make([]string, 0, len(values))
	for _, stage := range order {
		if has(values, stage) {
			out = append(out, stage)
		}
	}
	return out
}

func stageRules(stage string, ids ...string) map[string]string {
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		out[id] = stage
	}
	return out
}

func mergeRules(groups ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, group := range groups {
		for id, stage := range group {
			out[id] = stage
		}
	}
	return out
}

func has(values map[string]struct{}, value string) bool { _, ok := values[value]; return ok }

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func humanDuration(value time.Duration) string {
	if value < time.Minute {
		return "less than a minute"
	}
	if value < time.Hour {
		return fmt.Sprintf("%d minutes", int(value.Minutes()))
	}
	return fmt.Sprintf("%.1f hours", value.Hours())
}
