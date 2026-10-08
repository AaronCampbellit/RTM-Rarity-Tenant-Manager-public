// Package offlineinvestigations analyzes uploaded Microsoft 365 evidence in a
// case-scoped namespace. It deliberately never writes to the live Security
// Operations event, incident, detection, or storyline tables.
package offlineinvestigations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
	attackstorylines "github.com/rarity/rtm/internal/storylines"
)

const (
	AnalysisJobType = "offline_investigation_analysis"
	MaxCaseRecords  = store.OfflineInvestigationMaxRecords
)

type AnalysisPayload struct {
	InvestigationID string `json:"investigationId"`
	Actor           string `json:"actor"`
	CorrelationID   string `json:"correlationId"`
}

type Service struct {
	store store.Store
	log   *slog.Logger
	now   func() time.Time
}

func New(st store.Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: st, log: log, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) RunAnalysis(ctx context.Context, jobID, rawPayload string) error {
	started := s.now()
	var payload AnalysisPayload
	if err := json.Unmarshal([]byte(rawPayload), &payload); err != nil || payload.InvestigationID == "" {
		return s.fail(ctx, jobID, payload.InvestigationID, payload.Actor, payload.CorrelationID, started, "invalid analysis payload")
	}
	if err := s.store.UpdateJobStatus(ctx, jobID, "Running", 5); err != nil {
		return err
	}
	if err := s.store.UpdateOfflineInvestigationStatus(ctx, payload.InvestigationID, "analyzing", 5, "Validating uploaded evidence"); err != nil {
		return s.fail(ctx, jobID, payload.InvestigationID, payload.Actor, payload.CorrelationID, started, err.Error())
	}
	investigation, err := s.store.OfflineInvestigation(ctx, payload.InvestigationID)
	if err != nil {
		return s.fail(ctx, jobID, payload.InvestigationID, payload.Actor, payload.CorrelationID, started, err.Error())
	}
	files, err := s.store.OfflineInvestigationEvidenceFiles(ctx, payload.InvestigationID)
	if err != nil || len(files) == 0 {
		if err == nil {
			err = fmt.Errorf("upload at least one supported evidence file before analysis")
		}
		return s.fail(ctx, jobID, payload.InvestigationID, payload.Actor, payload.CorrelationID, started, err.Error())
	}

	parsed := make([]ParsedFile, 0, len(files))
	totalRecords := 0
	for _, file := range files {
		result, err := ParseFile(file.Name, file.MediaType, file.Content)
		if err != nil {
			return s.fail(ctx, jobID, payload.InvestigationID, payload.Actor, payload.CorrelationID, started, file.Name+": "+err.Error())
		}
		totalRecords += len(result.Records)
		if totalRecords > MaxCaseRecords {
			return s.fail(ctx, jobID, payload.InvestigationID, payload.Actor, payload.CorrelationID, started, fmt.Sprintf("case exceeds the %d record limit", MaxCaseRecords))
		}
		parsed = append(parsed, result)
	}
	_ = s.store.UpdateOfflineInvestigationStatus(ctx, payload.InvestigationID, "analyzing", 35, "Normalizing case evidence")

	tenantID := "offline:" + payload.InvestigationID
	events, err := normalizeEvidence(tenantID, parsed, s.now())
	if err != nil {
		return s.fail(ctx, jobID, payload.InvestigationID, payload.Actor, payload.CorrelationID, started, err.Error())
	}
	rules, err := s.store.SecurityDetectionRules(ctx)
	if err != nil {
		return s.fail(ctx, jobID, payload.InvestigationID, payload.Actor, payload.CorrelationID, started, "load detection rules: "+err.Error())
	}
	_ = s.store.UpdateOfflineInvestigationStatus(ctx, payload.InvestigationID, "analyzing", 65, "Evaluating detections and attack paths")
	analyzedAt := s.now()
	detections := deduplicateDetections(append(
		append(m365audit.DetectConfigured(events, analyzedAt, rules), m365audit.CorrelateConfigured(events, analyzedAt, rules)...),
		m365audit.DetectCustom(events, analyzedAt, rules)...,
	))
	storylines := attackstorylines.Evaluate(detections, events, map[string]string{tenantID: investigation.TenantLabel}, analyzedAt)

	investigation.Status, investigation.Progress, investigation.Detail = "complete", 100, "Analysis complete"
	investigation.UpdatedAt, investigation.AnalyzedAt = analyzedAt, analyzedAt
	investigation.EventCount, investigation.DetectionCount = len(events), len(detections)
	investigation.StorylineCount = len(storylines)
	investigation.Coverage = coverageForParsed(parsed)
	for _, detection := range detections {
		if detection.Severity == "Critical" || detection.Severity == "High" {
			investigation.HighPriorityCount++
		}
	}
	if len(events) > 0 {
		investigation.PeriodStart, investigation.PeriodEnd = events[0].OccurredAt, events[0].OccurredAt
		for _, event := range events[1:] {
			if event.OccurredAt.Before(investigation.PeriodStart) {
				investigation.PeriodStart = event.OccurredAt
			}
			if event.OccurredAt.After(investigation.PeriodEnd) {
				investigation.PeriodEnd = event.OccurredAt
			}
		}
	}
	if err := s.store.ReplaceOfflineInvestigationAnalysis(ctx, investigation, model.OfflineInvestigationAnalysis{
		Events: events, Detections: detections, Storylines: storylines,
	}); err != nil {
		return s.fail(ctx, jobID, payload.InvestigationID, payload.Actor, payload.CorrelationID, started, err.Error())
	}
	duration := time.Since(started).Round(time.Millisecond).String()
	if err := s.store.CompleteJob(ctx, jobID, "Completed", duration); err != nil {
		return err
	}
	_ = s.store.AppendAudit(ctx, model.AuditEntry{
		Actor: payload.Actor, Action: "security.offline_case.analysis_complete", Resource: investigation.Name,
		Result: fmt.Sprintf("Success — %d events, %d detections, %d storylines", len(events), len(detections), len(storylines)), CorrelationID: payload.CorrelationID,
	})
	return nil
}

func (s *Service) fail(ctx context.Context, jobID, investigationID, actor, correlationID string, started time.Time, detail string) error {
	if investigationID != "" {
		_ = s.store.UpdateOfflineInvestigationStatus(ctx, investigationID, "failed", 100, detail)
	}
	if jobID != "" {
		_ = s.store.CompleteJob(ctx, jobID, "Failed", time.Since(started).Round(time.Millisecond).String())
	}
	_ = s.store.AppendAudit(ctx, model.AuditEntry{Actor: actor, Action: "security.offline_case.analysis_complete", Resource: investigationID, Result: "Failed — " + detail, CorrelationID: correlationID})
	return fmt.Errorf("offline investigation analysis: %s", detail)
}

func normalizeEvidence(tenantID string, parsed []ParsedFile, observedAt time.Time) ([]model.SecurityAuditEvent, error) {
	var events []model.SecurityAuditEvent
	for _, file := range parsed {
		for _, raw := range file.Records {
			var event model.SecurityAuditEvent
			var err error
			switch file.EvidenceType {
			case EvidenceEntraSignIns:
				event, err = m365audit.NormalizeImportedFastIdentityEvent(tenantID, m365audit.ContentTypeEntraSignIn, raw, observedAt)
			case EvidenceEntraDirectoryAudit:
				event, err = m365audit.NormalizeImportedFastIdentityEvent(tenantID, m365audit.ContentTypeEntraDirectoryAudit, raw, observedAt)
			case EvidenceM365Activity:
				contentType := managementContentType(raw)
				event, err = m365audit.NormalizeImportedManagementEvent(tenantID, contentType, raw, observedAt)
			default:
				err = ErrUnsupportedEvidence
			}
			if err != nil {
				return nil, fmt.Errorf("normalize %s record: %w", file.EvidenceType, err)
			}
			digest := sha256.Sum256([]byte(tenantID + "|" + file.EvidenceType + "|" + event.ProviderRecordID))
			event.ID = "osae_" + hex.EncodeToString(digest[:12])
			event.ProviderRecordID = file.EvidenceType + ":" + event.ProviderRecordID
			event.Sources = appendUnique(event.Sources, "offline_import")
			events = append(events, event)
		}
	}
	events = semanticDeduplicate(events)
	sort.Slice(events, func(i, j int) bool { return events[i].OccurredAt.Before(events[j].OccurredAt) })
	return events, nil
}

func managementContentType(raw json.RawMessage) string {
	var record map[string]any
	_ = json.Unmarshal(raw, &record)
	workload := strings.ToLower(fmt.Sprint(record["Workload"]))
	switch {
	case strings.Contains(workload, "exchange"):
		return "Audit.Exchange"
	case strings.Contains(workload, "sharepoint") || strings.Contains(workload, "onedrive"):
		return "Audit.SharePoint"
	case strings.Contains(workload, "azureactivedirectory") || strings.Contains(workload, "entra"):
		return "Audit.AzureActiveDirectory"
	default:
		return "Audit.General"
	}
}

func semanticDeduplicate(events []model.SecurityAuditEvent) []model.SecurityAuditEvent {
	seenIDs := map[string]struct{}{}
	bySemantic := map[string][]int{}
	out := make([]model.SecurityAuditEvent, 0, len(events))
	for _, event := range events {
		if _, exists := seenIDs[event.ID]; exists {
			continue
		}
		seenIDs[event.ID] = struct{}{}
		key := strings.ToLower(strings.Join([]string{event.Operation, event.Actor, event.ObjectID, event.ClientIP, event.ResultStatus}, "|"))
		duplicate := false
		for _, candidateIndex := range bySemantic[key] {
			candidate := out[candidateIndex]
			delta := event.OccurredAt.Sub(candidate.OccurredAt)
			if delta < 0 {
				delta = -delta
			}
			if key != "||||" && delta <= 10*time.Second {
				for _, source := range event.Sources {
					out[candidateIndex].Sources = appendUnique(out[candidateIndex].Sources, source)
				}
				if event.AvailableAt.Before(out[candidateIndex].AvailableAt) {
					out[candidateIndex].AvailableAt = event.AvailableAt
				}
				if event.IngestedAt.Before(out[candidateIndex].IngestedAt) {
					out[candidateIndex].IngestedAt = event.IngestedAt
				}
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		out = append(out, event)
		bySemantic[key] = append(bySemantic[key], len(out)-1)
	}
	return out
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func deduplicateDetections(detections []model.SecurityNativeDetection) []model.SecurityNativeDetection {
	seen := map[string]struct{}{}
	out := make([]model.SecurityNativeDetection, 0, len(detections))
	for _, detection := range detections {
		if _, exists := seen[detection.ID]; exists {
			continue
		}
		seen[detection.ID] = struct{}{}
		out = append(out, detection)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	return out
}

func coverageForParsed(parsed []ParsedFile) []model.OfflineEvidenceCoverage {
	type coverageDefinition struct {
		key, label string
		required   []string
		oneOf      []string
	}
	definitions := []coverageDefinition{
		{EvidenceEntraSignIns, "Microsoft Entra sign-ins", []string{"createddatetime", "userprincipalname", "ipaddress", "authenticationrequirement", "conditionalaccessstatus", "isinteractive"}, []string{"authenticationdetails", "authenticationmethodsused"}},
		{EvidenceEntraDirectoryAudit, "Microsoft Entra directory audit", []string{"activitydatetime", "activitydisplayname", "initiatedby", "targetresources"}, nil},
		{EvidenceM365Activity, "Microsoft 365 activity", []string{"creationtime", "operation", "workload", "userid"}, nil},
	}
	coverage := make([]model.OfflineEvidenceCoverage, 0, len(definitions))
	for _, definition := range definitions {
		fields := map[string]struct{}{}
		records := 0
		for _, file := range parsed {
			if file.EvidenceType != definition.key {
				continue
			}
			records += len(file.Records)
			for _, field := range file.Fields {
				fields[field] = struct{}{}
			}
		}
		item := model.OfflineEvidenceCoverage{Key: definition.key, Label: definition.label, Records: records, Fields: sortedKeys(fields)}
		if records == 0 {
			item.Status, item.Detail = "missing", "No evidence uploaded"
			coverage = append(coverage, item)
			continue
		}
		for _, field := range definition.required {
			if _, ok := fields[field]; !ok {
				item.MissingFields = append(item.MissingFields, field)
			}
		}
		if len(definition.oneOf) > 0 {
			found := false
			for _, field := range definition.oneOf {
				if _, ok := fields[field]; ok {
					found = true
					break
				}
			}
			if !found {
				item.MissingFields = append(item.MissingFields, strings.Join(definition.oneOf, " or "))
			}
		}
		if len(item.MissingFields) > 0 {
			item.Status = "partial"
			if definition.key == EvidenceEntraSignIns && len(item.MissingFields) > 0 {
				item.Detail = "Sign-ins loaded; missing fields may limit MFA and Conditional Access conclusions"
			} else {
				item.Detail = "Evidence loaded with incomplete fields"
			}
		} else {
			item.Status, item.Detail = "present", "Evidence ready for analysis"
		}
		coverage = append(coverage, item)
	}
	return coverage
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
