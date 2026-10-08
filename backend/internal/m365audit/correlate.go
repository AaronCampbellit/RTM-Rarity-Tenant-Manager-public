package m365audit

import (
	"fmt"
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/model"
)

// Correlate evaluates bounded, deterministic windows over recent immutable
// events. It never calls external geolocation or risk services: country,
// session, and client values must be present in Microsoft's audit record.
func Correlate(events []model.SecurityAuditEvent, createdAt time.Time) []model.SecurityNativeDetection {
	return CorrelateConfigured(events, createdAt, nil)
}

func CorrelateConfigured(events []model.SecurityAuditEvent, createdAt time.Time, configs []model.SecurityDetectionRule) []model.SecurityNativeDetection {
	ordered := append([]model.SecurityAuditEvent(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].OccurredAt.Before(ordered[j].OccurredAt) })
	rules := newRuleSet(configs)
	var out []model.SecurityNativeDetection
	out = append(out, correlateMassForwarding(ordered, createdAt, rules)...)
	out = append(out, correlateLargeGroupChanges(ordered, createdAt, rules)...)
	out = append(out, correlateBulkSharePoint(ordered, createdAt, rules)...)
	out = append(out, correlateAdministrativeBursts(ordered, createdAt, rules)...)
	out = append(out, correlateCrossTenantAdministrator(ordered, createdAt, rules)...)
	out = append(out, correlateUnusualAdministratorContext(ordered, createdAt, rules)...)
	out = append(out, correlateLoginSequences(ordered, createdAt, rules)...)
	for _, rule := range rules.customRules() {
		if rule.DetectionType == DetectionThreshold {
			out = append(out, evaluateCustomRule(ordered, rule, createdAt)...)
		}
	}
	for _, rule := range rules.replacementRules() {
		if rule.DetectionType == DetectionThreshold {
			out = append(out, evaluateCustomRule(rules.replacementEvents(ordered, rule), rule, createdAt)...)
		}
	}
	return out
}

func correlateMassForwarding(events []model.SecurityAuditEvent, createdAt time.Time, rules ruleSet) []model.SecurityNativeDetection {
	groups := map[string][]model.SecurityAuditEvent{}
	for _, event := range events {
		_, allowed := rules.allows("mass_mailbox_forwarding", event, "Critical", ConfidenceHigh)
		if allowed && matchesForwarding(event) {
			groups[event.TenantID+"|"+strings.ToLower(event.Actor)] = append(groups[event.TenantID+"|"+strings.ToLower(event.Actor)], event)
		}
	}
	var out []model.SecurityNativeDetection
	for _, group := range groups {
		effective := rules.effective("mass_mailbox_forwarding", group[0].TenantID, "Critical", ConfidenceHigh, 5, 30)
		out = append(out, thresholdWindows(group, effective.window, effective.threshold, func(window []model.SecurityAuditEvent) (model.SecurityAuditEvent, string, string, bool) {
			objects := distinctObjects(window)
			if len(objects) < effective.threshold {
				return model.SecurityAuditEvent{}, "", "", false
			}
			anchor := window[len(window)-1]
			detail := fmt.Sprintf("%s changed forwarding or redirect settings on %d distinct mailboxes within %d minutes.", actorLabel(anchor), len(objects), int(effective.window.Minutes()))
			return anchor, effective.title("Mass mailbox forwarding changes"), effective.detail(detail), true
		}, "mass_mailbox_forwarding", effective.version, effective.severity, DetectionThreshold, effective.confidence, createdAt)...)
	}

	// A domain becomes "new" only after RTM has at least three earlier
	// forwarding observations for the tenant, avoiding a first-run baseline lie.
	seen, previous := map[string]map[string]struct{}{}, map[string]int{}
	for _, event := range events {
		effective, allowed := rules.allows("new_forwarding_domain", event, "High", ConfidenceMedium)
		if !allowed || !matchesForwarding(event) {
			continue
		}
		domain := forwardingDomain(event)
		if domain == "" {
			continue
		}
		if seen[event.TenantID] == nil {
			seen[event.TenantID] = map[string]struct{}{}
		}
		_, known := seen[event.TenantID][domain]
		if !known && previous[event.TenantID] >= 3 {
			detail := "A forwarding destination uses " + domain + ", which has not appeared in this tenant's retained forwarding-event baseline."
			out = append(out, makeDetection("new_forwarding_domain", effective.version, effective.title("Forwarding to a newly observed domain"), effective.detail(detail), effective.severity, DetectionHeuristic, effective.confidence, event, event.ID+"|"+domain, createdAt))
		}
		seen[event.TenantID][domain] = struct{}{}
		previous[event.TenantID]++
	}
	return out
}

func correlateLargeGroupChanges(events []model.SecurityAuditEvent, createdAt time.Time, rules ruleSet) []model.SecurityNativeDetection {
	groups := map[string][]model.SecurityAuditEvent{}
	for _, event := range events {
		_, allowed := rules.allows("large_group_membership_change", event, "Medium", ConfidenceHigh)
		if allowed && operationContains(event, "member to group", "member from group", "add group member", "remove group member") {
			groups[event.TenantID+"|"+strings.ToLower(event.Actor)] = append(groups[event.TenantID+"|"+strings.ToLower(event.Actor)], event)
		}
	}
	var out []model.SecurityNativeDetection
	for _, group := range groups {
		effective := rules.effective("large_group_membership_change", group[0].TenantID, "Medium", ConfidenceHigh, 20, 15)
		out = append(out, thresholdWindows(group, effective.window, effective.threshold, func(window []model.SecurityAuditEvent) (model.SecurityAuditEvent, string, string, bool) {
			anchor := window[len(window)-1]
			detail := fmt.Sprintf("%s performed %d group membership changes within %d minutes.", actorLabel(anchor), len(window), int(effective.window.Minutes()))
			return anchor, effective.title("Large group membership change"), effective.detail(detail), true
		}, "large_group_membership_change", effective.version, effective.severity, DetectionThreshold, effective.confidence, createdAt)...)
	}
	return out
}

func correlateBulkSharePoint(events []model.SecurityAuditEvent, createdAt time.Time, rules ruleSet) []model.SecurityNativeDetection {
	type category struct {
		id, title, description, severity string
		threshold                        int
		match                            func(model.SecurityAuditEvent) bool
	}
	categories := []category{
		{"bulk_file_download", "Bulk SharePoint/OneDrive downloads", "downloaded or accessed", "High", 50, isFileReadEvent},
		{"bulk_file_deletion", "Bulk SharePoint/OneDrive deletions", "deleted or recycled", "High", 20, func(e model.SecurityAuditEvent) bool {
			return operationContains(e, "filedeleted", "filerecycled", "folderdeleted", "file deleted")
		}},
		{"bulk_external_sharing", "Bulk SharePoint/OneDrive sharing", "created or changed sharing access for", "High", 10, func(e model.SecurityAuditEvent) bool {
			return operationContains(e, "sharinginvitationcreated", "anonymouslinkcreated", "securelinkcreated", "sharingset", "sharingpermission")
		}},
	}
	var out []model.SecurityNativeDetection
	for _, candidate := range categories {
		groups := map[string][]model.SecurityAuditEvent{}
		for _, event := range events {
			_, allowed := rules.allows(candidate.id, event, candidate.severity, ConfidenceMedium)
			if allowed && isSharePointEvent(event) && candidate.match(event) {
				groups[event.TenantID+"|"+strings.ToLower(event.Actor)] = append(groups[event.TenantID+"|"+strings.ToLower(event.Actor)], event)
			}
		}
		for _, group := range groups {
			category := candidate
			effective := rules.effective(category.id, group[0].TenantID, category.severity, ConfidenceMedium, category.threshold, 15)
			out = append(out, thresholdWindows(group, effective.window, effective.threshold, func(window []model.SecurityAuditEvent) (model.SecurityAuditEvent, string, string, bool) {
				objects := distinctObjects(window)
				if len(objects) < effective.threshold {
					return model.SecurityAuditEvent{}, "", "", false
				}
				anchor := window[len(window)-1]
				detail := fmt.Sprintf("%s %s %d distinct objects within %d minutes.", actorLabel(anchor), category.description, len(objects), int(effective.window.Minutes()))
				return anchor, effective.title(category.title), effective.detail(detail), true
			}, category.id, effective.version, effective.severity, DetectionThreshold, effective.confidence, createdAt)...)
		}
	}
	return out
}

func correlateAdministrativeBursts(events []model.SecurityAuditEvent, createdAt time.Time, rules ruleSet) []model.SecurityNativeDetection {
	groups, failures := map[string][]model.SecurityAuditEvent{}, map[string][]model.SecurityAuditEvent{}
	for _, event := range events {
		if !isAdministrativeEvent(event) || event.Actor == "" {
			continue
		}
		key := event.TenantID + "|" + strings.ToLower(event.Actor)
		_, burstAllowed := rules.allows("administrator_object_burst", event, "High", ConfidenceMedium)
		if burstAllowed {
			groups[key] = append(groups[key], event)
		}
		_, failureAllowed := rules.allows("repeated_administrative_failures", event, "Medium", ConfidenceHigh)
		if failureAllowed && isFailure(event) {
			failures[key] = append(failures[key], event)
		}
	}
	var out []model.SecurityNativeDetection
	for _, group := range failures {
		effective := rules.effective("repeated_administrative_failures", group[0].TenantID, "Medium", ConfidenceHigh, 5, 10)
		out = append(out, thresholdWindows(group, effective.window, effective.threshold, func(window []model.SecurityAuditEvent) (model.SecurityAuditEvent, string, string, bool) {
			anchor := window[len(window)-1]
			detail := fmt.Sprintf("%s generated %d failed administrative operations within %d minutes.", actorLabel(anchor), len(window), int(effective.window.Minutes()))
			return anchor, effective.title("Repeated administrative failures"), effective.detail(detail), true
		}, "repeated_administrative_failures", effective.version, effective.severity, DetectionThreshold, effective.confidence, createdAt)...)
	}
	for _, group := range groups {
		effective := rules.effective("administrator_object_burst", group[0].TenantID, "High", ConfidenceMedium, 15, 10)
		out = append(out, thresholdWindows(group, effective.window, effective.threshold, func(window []model.SecurityAuditEvent) (model.SecurityAuditEvent, string, string, bool) {
			objects := distinctObjects(window)
			if len(objects) < effective.threshold {
				return model.SecurityAuditEvent{}, "", "", false
			}
			anchor := window[len(window)-1]
			detail := fmt.Sprintf("%s changed %d distinct objects within %d minutes.", actorLabel(anchor), len(objects), int(effective.window.Minutes()))
			return anchor, effective.title("Administrator changed many objects rapidly"), effective.detail(detail), true
		}, "administrator_object_burst", effective.version, effective.severity, DetectionThreshold, effective.confidence, createdAt)...)
	}
	return out
}

func correlateCrossTenantAdministrator(events []model.SecurityAuditEvent, createdAt time.Time, rules ruleSet) []model.SecurityNativeDetection {
	groups := map[string][]model.SecurityAuditEvent{}
	for _, event := range events {
		_, allowed := rules.allows("cross_tenant_administrator_burst", event, "High", ConfidenceMedium)
		if allowed && isAdministrativeEvent(event) && event.Actor != "" {
			groups[strings.ToLower(event.Actor)] = append(groups[strings.ToLower(event.Actor)], event)
		}
	}
	var out []model.SecurityNativeDetection
	for _, group := range groups {
		effective := rules.effective("cross_tenant_administrator_burst", group[0].TenantID, "High", ConfidenceMedium, 15, 15)
		out = append(out, thresholdWindows(group, effective.window, effective.threshold, func(window []model.SecurityAuditEvent) (model.SecurityAuditEvent, string, string, bool) {
			tenants, objects := map[string]struct{}{}, map[string]struct{}{}
			for _, event := range window {
				tenants[event.TenantID] = struct{}{}
				if event.ObjectID != "" {
					objects[event.TenantID+"|"+event.ObjectID] = struct{}{}
				}
			}
			if len(tenants) < 2 || len(objects) < effective.threshold {
				return model.SecurityAuditEvent{}, "", "", false
			}
			anchor := window[len(window)-1]
			detail := fmt.Sprintf("%s changed %d objects across %d managed tenants within %d minutes.", actorLabel(anchor), len(objects), len(tenants), int(effective.window.Minutes()))
			return anchor, effective.title("Administrator activity burst across tenants"), effective.detail(detail), true
		}, "cross_tenant_administrator_burst", effective.version, effective.severity, DetectionCorrelation, effective.confidence, createdAt)...)
	}
	return out
}

func correlateUnusualAdministratorContext(events []model.SecurityAuditEvent, createdAt time.Time, rules ruleSet) []model.SecurityNativeDetection {
	groups := map[string][]model.SecurityAuditEvent{}
	for _, event := range events {
		if isAdministrativeEvent(event) && event.Actor != "" {
			groups[event.TenantID+"|"+strings.ToLower(event.Actor)] = append(groups[event.TenantID+"|"+strings.ToLower(event.Actor)], event)
		}
	}
	var out []model.SecurityNativeDetection
	for _, group := range groups {
		seenIP, seenCountry := map[string]struct{}{}, map[string]struct{}{}
		hourCounts := [24]int{}
		var first time.Time
		for index, event := range group {
			if first.IsZero() {
				first = event.OccurredAt
			}
			ipRule := rules.effective("unusual_administrator_ip", event.TenantID, "Medium", ConfidenceLow, 10, 10080)
			countryRule := rules.effective("unusual_administrator_country", event.TenantID, "Medium", ConfidenceLow, 10, 10080)
			timeRule := rules.effective("unusual_administrator_time", event.TenantID, "Low", ConfidenceLow, 20, 10080)
			ipReady := ipRule.enabled && !eventExcluded(event, ipRule.exclusions) && index >= ipRule.threshold && event.OccurredAt.Sub(first) >= ipRule.window
			if ipReady && event.ClientIP != "" {
				if _, known := seenIP[event.ClientIP]; !known {
					detail := "The administrator source IP has not appeared in this actor's retained administrative baseline."
					out = append(out, makeDetection("unusual_administrator_ip", ipRule.version, ipRule.title("Administrator used a newly observed IP"), ipRule.detail(detail), ipRule.severity, DetectionHeuristic, ipRule.confidence, event, event.ID+"|"+event.ClientIP, createdAt))
				}
			}
			country := eventCountry(event)
			countryReady := countryRule.enabled && !eventExcluded(event, countryRule.exclusions) && index >= countryRule.threshold && event.OccurredAt.Sub(first) >= countryRule.window
			if countryReady && country != "" {
				if _, known := seenCountry[strings.ToLower(country)]; !known {
					detail := "The country has not appeared in this actor's retained administrative baseline."
					out = append(out, makeDetection("unusual_administrator_country", countryRule.version, countryRule.title("Administrator active from a newly observed country"), countryRule.detail(detail), countryRule.severity, DetectionHeuristic, countryRule.confidence, event, event.ID+"|"+country, createdAt))
				}
			}
			timeReady := timeRule.enabled && !eventExcluded(event, timeRule.exclusions) && index >= timeRule.threshold && event.OccurredAt.Sub(first) >= timeRule.window
			if timeReady && hourCounts[event.OccurredAt.UTC().Hour()] == 0 {
				detail := "This UTC hour has not appeared in the retained administrative baseline for the actor. Tenant-local working hours are not configured, so confidence is low."
				out = append(out, makeDetection("unusual_administrator_time", timeRule.version, timeRule.title("Administrator active at an unusual UTC hour"), timeRule.detail(detail), timeRule.severity, DetectionHeuristic, timeRule.confidence, event, event.ID+"|hour", createdAt))
			}
			if event.ClientIP != "" {
				seenIP[event.ClientIP] = struct{}{}
			}
			if country != "" {
				seenCountry[strings.ToLower(country)] = struct{}{}
			}
			hourCounts[event.OccurredAt.UTC().Hour()]++
		}
	}
	return out
}

func correlateLoginSequences(events []model.SecurityAuditEvent, createdAt time.Time, rules ruleSet) []model.SecurityNativeDetection {
	groups := map[string][]model.SecurityAuditEvent{}
	for _, event := range events {
		if isLoginEvent(event) && event.Actor != "" {
			groups[event.TenantID+"|"+strings.ToLower(event.Actor)] = append(groups[event.TenantID+"|"+strings.ToLower(event.Actor)], event)
		}
	}
	var out []model.SecurityNativeDetection
	for _, group := range groups {
		var failures []model.SecurityAuditEvent
		var previousSuccess *model.SecurityAuditEvent
		sessions := map[string]model.SecurityAuditEvent{}
		for _, event := range group {
			if isFailure(event) {
				failedRule := rules.effective("failed_logins_then_success", event.TenantID, "High", ConfidenceHigh, 5, 15)
				if failedRule.enabled && !eventExcluded(event, failedRule.exclusions) {
					failures = append(failures, event)
				}
				continue
			}
			if !isSuccessfulLogin(event) {
				continue
			}
			failedRule := rules.effective("failed_logins_then_success", event.TenantID, "High", ConfidenceHigh, 5, 15)
			cutoff := event.OccurredAt.Add(-failedRule.window)
			start := 0
			for start < len(failures) && failures[start].OccurredAt.Before(cutoff) {
				start++
			}
			failures = failures[start:]
			if failedRule.enabled && !eventExcluded(event, failedRule.exclusions) && len(failures) >= failedRule.threshold {
				detail := fmt.Sprintf("The account recorded %d failed logins in the %d minutes before a successful login.", len(failures), int(failedRule.window.Minutes()))
				out = append(out, makeDetection("failed_logins_then_success", failedRule.version, failedRule.title("Repeated failed logins followed by success"), failedRule.detail(detail), failedRule.severity, DetectionCorrelation, failedRule.confidence, event, event.ID+"|fail-success", createdAt))
			}
			failures = nil
			country := eventCountry(event)
			if previousSuccess != nil {
				previousCountry := eventCountry(*previousSuccess)
				gap := event.OccurredAt.Sub(previousSuccess.OccurredAt)
				travelRule := rules.effective("possible_impossible_travel", event.TenantID, "High", ConfidenceMedium, 2, 120)
				if travelRule.enabled && !eventExcluded(event, travelRule.exclusions) && !eventExcluded(*previousSuccess, travelRule.exclusions) && gap >= 0 && gap <= travelRule.window && country != "" && previousCountry != "" && !strings.EqualFold(country, previousCountry) {
					detail := fmt.Sprintf("Successful logins for the same account occurred from %s and %s within %s. This is an audit-log heuristic, not an Entra risk verdict.", previousCountry, country, gap.Round(time.Minute))
					out = append(out, makeDetection("possible_impossible_travel", travelRule.version, travelRule.title("Possible impossible-travel login"), travelRule.detail(detail), travelRule.severity, DetectionHeuristic, travelRule.confidence, event, event.ID+"|travel", createdAt))
				}
			}
			previousSuccess = &event
			sessionID := eventSessionID(event)
			if sessionID != "" {
				sessionRule := rules.effective("possible_session_token_reuse", event.TenantID, "High", ConfidenceMedium, 2, 30)
				if prior, exists := sessions[sessionID]; exists && sessionRule.enabled && !eventExcluded(event, sessionRule.exclusions) && !eventExcluded(prior, sessionRule.exclusions) && event.OccurredAt.Sub(prior.OccurredAt) <= sessionRule.window && prior.ClientIP != "" && event.ClientIP != "" && prior.ClientIP != event.ClientIP {
					description := fmt.Sprintf("The same audit session identifier was observed from %s and %s within %d minutes.", prior.ClientIP, event.ClientIP, int(sessionRule.window.Minutes()))
					if before, after := eventUserAgent(prior), eventUserAgent(event); before != "" && after != "" && before != after {
						description += " The recorded client also changed."
					}
					detail := description + " Investigate and revoke sessions if unauthorized."
					out = append(out, makeDetection("possible_session_token_reuse", sessionRule.version, sessionRule.title("Possible stolen-session or token reuse"), sessionRule.detail(detail), sessionRule.severity, DetectionCorrelation, sessionRule.confidence, event, event.ID+"|session-reuse", createdAt))
				}
				sessions[sessionID] = event
			}
		}
	}
	return out
}

type thresholdEvaluator func([]model.SecurityAuditEvent) (model.SecurityAuditEvent, string, string, bool)

func thresholdWindows(events []model.SecurityAuditEvent, duration time.Duration, minimum int, evaluate thresholdEvaluator, ruleID string, version int, severity, detectionType, confidence string, createdAt time.Time) []model.SecurityNativeDetection {
	if len(events) < minimum {
		return nil
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].OccurredAt.Before(events[j].OccurredAt) })
	var out []model.SecurityNativeDetection
	start := 0
	var suppressUntil time.Time
	for end, event := range events {
		for start <= end && events[start].OccurredAt.Before(event.OccurredAt.Add(-duration)) {
			start++
		}
		if end-start+1 < minimum || event.OccurredAt.Before(suppressUntil) {
			continue
		}
		anchor, title, description, ok := evaluate(events[start : end+1])
		if !ok {
			continue
		}
		identity := anchor.ID + "|" + events[start].OccurredAt.UTC().Format(time.RFC3339)
		detection := makeDetection(ruleID, version, title, description, severity, detectionType, confidence, anchor, identity, createdAt)
		for _, supportingEvent := range events[start : end+1] {
			detection.EventIDs = append(detection.EventIDs, supportingEvent.ID)
		}
		detection.EventIDs = uniqueStrings(detection.EventIDs)
		out = append(out, detection)
		suppressUntil = event.OccurredAt.Add(duration)
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func distinctObjects(events []model.SecurityAuditEvent) map[string]struct{} {
	out := map[string]struct{}{}
	for _, event := range events {
		object := event.ObjectID
		if object == "" {
			object = event.ProviderRecordID
		}
		out[object] = struct{}{}
	}
	return out
}

func actorLabel(event model.SecurityAuditEvent) string {
	if event.Actor == "" {
		return "An actor"
	}
	return event.Actor
}

func forwardingDomain(event model.SecurityAuditEvent) string {
	value := rawString(event, "ForwardingSmtpAddress", "ForwardingAddress", "RedirectTo", "ForwardTo")
	value = strings.TrimPrefix(strings.TrimSpace(value), "smtp:")
	address, err := mail.ParseAddress(value)
	if err == nil {
		value = address.Address
	}
	parts := strings.Split(value, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[1]))
}
