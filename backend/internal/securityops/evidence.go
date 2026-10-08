package securityops

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/rarity/rtm/internal/model"
)

const maxEvidenceChanges = 6

func summarizeSecurityEvent(event model.SecurityAuditEvent) *model.SecurityEvidenceSummary {
	summary := &model.SecurityEvidenceSummary{
		EventID: event.ID, Operation: event.Operation, Actor: event.Actor,
		Workload: event.Workload, ClientIP: event.ClientIP, ResultStatus: event.ResultStatus,
		OccurredAt: event.OccurredAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	var raw any
	if len(event.Raw) > 0 {
		_ = json.Unmarshal(event.Raw, &raw)
	}
	modified := mapsAtKeys(raw, "ModifiedProperties", "modifiedProperties")
	summary.Changes = evidenceChanges(modified)
	summary.Target = modifiedDisplayName(modified)

	targetName := namedTarget(raw)
	if summary.Target == "" {
		summary.Target = targetName
	} else if targetName != "" && !strings.EqualFold(targetName, summary.Target) {
		summary.RelatedResource = targetName
	}
	if summary.Target == "" && readableEvidenceValue(event.ObjectID) {
		summary.Target = strings.TrimSpace(event.ObjectID)
	}
	return summary
}

func mapsAtKeys(value any, keys ...string) []map[string]any {
	wanted := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		wanted[strings.ToLower(key)] = struct{}{}
	}
	var out []map[string]any
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, ok := wanted[strings.ToLower(key)]; ok {
					if list, ok := child.([]any); ok {
						for _, item := range list {
							if row, ok := item.(map[string]any); ok {
								out = append(out, row)
							}
						}
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return out
}

func modifiedDisplayName(rows []map[string]any) string {
	priorities := []string{"serviceprincipal.displayname", "application.displayname", "user.displayname", "group.displayname", "role.displayname", "displayname"}
	for _, priority := range priorities {
		for _, row := range rows {
			name := strings.ToLower(mapString(row, "Name", "displayName"))
			if name != priority && !(priority == "displayname" && strings.HasSuffix(name, ".displayname")) {
				continue
			}
			if value := cleanEvidenceValue(mapString(row, "NewValue", "newValue")); readableEvidenceValue(value) {
				return value
			}
		}
	}
	return ""
}

func namedTarget(raw any) string {
	for _, row := range mapsAtKeys(raw, "Target", "target") {
		if typeValue := fmt.Sprint(mapValue(row, "Type", "type")); typeValue != "1" {
			continue
		}
		if value := cleanEvidenceValue(mapString(row, "ID", "id", "displayName")); readableEvidenceValue(value) {
			return value
		}
	}
	for _, row := range mapsAtKeys(raw, "TargetResources", "targetResources") {
		if value := cleanEvidenceValue(mapString(row, "displayName", "userPrincipalName", "DisplayName")); readableEvidenceValue(value) {
			return value
		}
	}
	return ""
}

func evidenceChanges(rows []map[string]any) []model.SecurityEvidenceChange {
	out := make([]model.SecurityEvidenceChange, 0, maxEvidenceChanges)
	seen := map[string]struct{}{}
	for _, row := range rows {
		name := mapString(row, "Name", "displayName")
		if !meaningfulEvidenceField(name) {
			continue
		}
		before := cleanEvidenceValue(mapString(row, "OldValue", "oldValue"))
		after := cleanEvidenceValue(mapString(row, "NewValue", "newValue"))
		if before == "" && after == "" || !readableEvidenceValue(before) && !readableEvidenceValue(after) {
			continue
		}
		field := evidenceFieldLabel(name)
		key := strings.ToLower(field + "\x00" + before + "\x00" + after)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, model.SecurityEvidenceChange{Field: field, Before: before, After: after})
		if len(out) == maxEvidenceChanges {
			break
		}
	}
	return out
}

func meaningfulEvidenceField(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	technicalName := strings.HasSuffix(lower, ".name") && !strings.HasSuffix(lower, ".displayname")
	if lower == "" || technicalName || strings.Contains(lower, "datetime") || strings.Contains(lower, "serviceprincipalnames") || strings.HasSuffix(lower, ".id") || strings.Contains(lower, "objectid") || strings.Contains(lower, "appid") {
		return false
	}
	return true
}

func evidenceFieldLabel(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "approle.value"):
		return "Application permission"
	case strings.Contains(lower, "approle.displayname"):
		return "Permission name"
	case strings.Contains(lower, "serviceprincipal.displayname"):
		return "Service principal"
	case strings.Contains(lower, "role.displayname"):
		return "Directory role"
	case strings.Contains(lower, "group.displayname"):
		return "Group"
	case strings.Contains(lower, "user.displayname"):
		return "User"
	case strings.Contains(lower, "accountenabled"):
		return "Account enabled"
	}
	part := name
	if index := strings.LastIndex(part, "."); index >= 0 {
		part = part[index+1:]
	}
	part = strings.NewReplacer("_", " ", "-", " ").Replace(part)
	var builder strings.Builder
	for index, char := range part {
		if index > 0 && unicode.IsUpper(char) {
			builder.WriteByte(' ')
		}
		builder.WriteRune(char)
	}
	return strings.TrimSpace(builder.String())
}

func cleanEvidenceValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "null") {
		return ""
	}
	var decoded any
	if json.Unmarshal([]byte(value), &decoded) == nil {
		switch typed := decoded.(type) {
		case string:
			value = typed
		case []any:
			parts := make([]string, 0, len(typed))
			for _, item := range typed {
				parts = append(parts, fmt.Sprint(item))
			}
			value = strings.Join(parts, ", ")
		}
	}
	return strings.TrimSpace(value)
}

func readableEvidenceValue(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 180 && strings.Count(value, ";") < 4
}

func mapString(row map[string]any, keys ...string) string {
	value := mapValue(row, keys...)
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func mapValue(row map[string]any, keys ...string) any {
	for _, wanted := range keys {
		for key, value := range row {
			if strings.EqualFold(key, wanted) {
				return value
			}
		}
	}
	return nil
}
