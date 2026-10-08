package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/offlineinvestigations"
	"github.com/rarity/rtm/internal/store"
)

func (s *Server) listOfflineInvestigations(w http.ResponseWriter, r *http.Request) {
	investigations, err := s.store.OfflineInvestigations(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if investigations == nil {
		investigations = []model.OfflineInvestigation{}
	}
	httpx.WriteJSON(w, http.StatusOK, investigations)
}

func (s *Server) createOfflineInvestigation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		TenantLabel string `json:"tenantLabel"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid case body.")
		return
	}
	body.Name, body.TenantLabel = strings.TrimSpace(body.Name), strings.TrimSpace(body.TenantLabel)
	if body.Name == "" || body.TenantLabel == "" || len(body.Name) > 120 || len(body.TenantLabel) > 120 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Case name and tenant label are required and must be 120 characters or fewer.")
		return
	}
	principal := auth.UserFromContext(r.Context())
	investigation, err := s.store.CreateOfflineInvestigation(r.Context(), store.NewOfflineInvestigation{
		Name: body.Name, TenantLabel: body.TenantLabel, CreatedBy: principal.Name,
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: principal.Name, Action: "security.offline_case.create", Resource: investigation.Name,
		Result: "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusCreated, investigation)
}

func (s *Server) getOfflineInvestigation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "investigationId")
	investigation, err := s.store.OfflineInvestigation(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	files, err := s.store.OfflineInvestigationFiles(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	analysis, err := s.store.OfflineInvestigationAnalysis(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	limit := 500
	if value := r.URL.Query().Get("timelineLimit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1000 {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Timeline limit must be between 1 and 1,000.")
			return
		}
		limit = parsed
	}
	severityByEvent := map[string]string{}
	signalsByEvent := map[string][]model.OfflineTimelineSignal{}
	for _, detection := range analysis.Detections {
		for _, eventID := range append(detection.EventIDs, detection.EventID) {
			if severityRank(detection.Severity) > severityRank(severityByEvent[eventID]) {
				severityByEvent[eventID] = detection.Severity
			}
			signal := model.OfflineTimelineSignal{RuleID: detection.RuleID, Title: detection.Title, Severity: detection.Severity}
			if !containsTimelineSignal(signalsByEvent[eventID], signal) {
				signalsByEvent[eventID] = append(signalsByEvent[eventID], signal)
			}
		}
	}
	sort.Slice(analysis.Events, func(i, j int) bool { return analysis.Events[i].OccurredAt.After(analysis.Events[j].OccurredAt) })
	if len(analysis.Events) > limit {
		analysis.Events = analysis.Events[:limit]
	}
	timeline := make([]model.OfflineTimelineEvent, 0, len(analysis.Events))
	for _, event := range analysis.Events {
		clientIP := event.ClientIP
		if clientIP == "" {
			clientIP = offlineTimelineRawString(event.Raw, "ClientIPAddress", "ActorIpAddress")
		}
		objectID := event.ObjectID
		if objectID == "" {
			objectID = offlineTimelineRawString(event.Raw, "MailboxOwnerUPN", "SourceFileName")
		}
		timeline = append(timeline, model.OfflineTimelineEvent{
			ID: event.ID, EvidenceType: offlineEvidenceType(event.ContentType), Source: offlineEventSource(event.Sources),
			Workload: event.Workload, Operation: event.Operation, Actor: event.Actor, ClientIP: clientIP,
			ObjectID: objectID, ResultStatus: event.ResultStatus, OccurredAt: event.OccurredAt, Severity: severityByEvent[event.ID],
			Facts: offlineTimelineFacts(event.Raw), Signals: nonNilTimelineSignals(signalsByEvent[event.ID]),
		})
	}
	if files == nil {
		files = []model.OfflineInvestigationFile{}
	}
	if analysis.Detections == nil {
		analysis.Detections = []model.SecurityNativeDetection{}
	}
	if analysis.Storylines == nil {
		analysis.Storylines = []model.SecurityStoryline{}
	}
	httpx.WriteJSON(w, http.StatusOK, model.OfflineInvestigationDetail{
		OfflineInvestigation: investigation, Files: files, Timeline: timeline,
		Detections: analysis.Detections, Storylines: analysis.Storylines,
	})
}

func containsTimelineSignal(signals []model.OfflineTimelineSignal, candidate model.OfflineTimelineSignal) bool {
	for _, signal := range signals {
		if signal.RuleID == candidate.RuleID && signal.Title == candidate.Title {
			return true
		}
	}
	return false
}

func nonNilTimelineSignals(signals []model.OfflineTimelineSignal) []model.OfflineTimelineSignal {
	if signals == nil {
		return []model.OfflineTimelineSignal{}
	}
	return signals
}

// offlineTimelineFacts projects only a small investigator-useful allowlist.
// Provider-native payloads remain private to the case analysis store.
func offlineTimelineFacts(raw json.RawMessage) []model.OfflineTimelineFact {
	var record map[string]any
	if json.Unmarshal(raw, &record) != nil {
		return []model.OfflineTimelineFact{}
	}
	facts := make([]model.OfflineTimelineFact, 0, 6)
	add := func(label, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if len(value) > 120 {
			value = value[:117] + "..."
		}
		facts = append(facts, model.OfflineTimelineFact{Label: label, Value: value})
	}
	add("Application", offlineTimelineString(record, "ApplicationDisplayName", "appDisplayName", "ClientProcessName"))
	add("Authentication", offlineTimelineString(record, "AuthenticationType", "authenticationRequirement", "AuthType"))
	add("Conditional Access", offlineTimelineString(record, "conditionalAccessStatus", "ConditionalAccessStatus"))
	add("Location", offlineTimelineLocation(record))
	if value, exists := offlineTimelineBool(record, "ExternalAccess"); exists {
		if value {
			add("Access", "External")
		} else {
			add("Access", "Internal")
		}
	}
	if count := offlineTimelineItemCount(record); count > 0 {
		add("Affected", fmt.Sprintf("%d items", count))
	}
	add("Device", offlineTimelineString(record, "DeviceDisplayName", "Platform"))
	return facts
}

func offlineTimelineRawString(raw json.RawMessage, keys ...string) string {
	var record map[string]any
	if json.Unmarshal(raw, &record) != nil {
		return ""
	}
	return offlineTimelineString(record, keys...)
}

func offlineTimelineString(record map[string]any, keys ...string) string {
	for _, key := range keys {
		value, exists := record[key]
		if !exists {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return typed
			}
		case json.Number:
			return typed.String()
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		}
	}
	return ""
}

func offlineTimelineBool(record map[string]any, key string) (bool, bool) {
	value, exists := record[key]
	if !exists {
		return false, false
	}
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(typed)
		return parsed, err == nil
	default:
		return false, false
	}
}

func offlineTimelineLocation(record map[string]any) string {
	if location := offlineTimelineString(record, "GeoLocation"); location != "" {
		return location
	}
	location, _ := record["location"].(map[string]any)
	if location == nil {
		return ""
	}
	parts := make([]string, 0, 3)
	for _, key := range []string{"city", "state", "countryOrRegion"} {
		if value, _ := location[key].(string); strings.TrimSpace(value) != "" {
			parts = append(parts, strings.TrimSpace(value))
		}
	}
	return strings.Join(parts, ", ")
}

func offlineTimelineItemCount(record map[string]any) int {
	for _, key := range []string{"OperationCount", "operationCount"} {
		switch typed := record[key].(type) {
		case float64:
			return int(typed)
		case json.Number:
			value, _ := strconv.Atoi(typed.String())
			return value
		case string:
			value, _ := strconv.Atoi(typed)
			return value
		}
	}
	if affected, ok := record["AffectedItems"].([]any); ok {
		return len(affected)
	}
	return 0
}

func (s *Server) uploadOfflineInvestigationFile(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "investigationId")
	if _, err := s.store.OfflineInvestigation(r.Context(), id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, offlineinvestigations.MaxFileSize+(1<<20))
	// Keep only a small multipart window in memory. Larger source files are
	// spooled to a temporary file while they are validated and persisted.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		httpx.WriteError(w, r, status, httpx.CodeValidationFailed, "Upload one JSON, JSONL, or CSV evidence file up to 1 GiB.")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	part, header, err := r.FormFile("file")
	if err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A file field is required.")
		return
	}
	defer part.Close()
	content, err := io.ReadAll(io.LimitReader(part, offlineinvestigations.MaxFileSize+1))
	if err != nil || int64(len(content)) > offlineinvestigations.MaxFileSize {
		httpx.WriteError(w, r, http.StatusRequestEntityTooLarge, httpx.CodeValidationFailed, "Evidence files must be 1 GiB or smaller.")
		return
	}
	name := filepath.Base(strings.TrimSpace(header.Filename))
	if name == "." || name == "" || len(name) > 200 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Evidence file names must be 200 characters or fewer.")
		return
	}
	mediaType := strings.TrimSpace(header.Header.Get("Content-Type"))
	parsed, err := offlineinvestigations.ParseFile(name, mediaType, content)
	if err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, err.Error())
		return
	}
	digest := sha256.Sum256(content)
	file, err := s.store.AddOfflineInvestigationFile(r.Context(), id, model.OfflineInvestigationFile{
		Name: name, MediaType: mediaType, EvidenceType: parsed.EvidenceType, SizeBytes: int64(len(content)),
		SHA256: hex.EncodeToString(digest[:]), Status: "ready", RecordCount: len(parsed.Records), Content: content,
	})
	if errors.Is(err, store.ErrConflict) {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeValidationFailed, "This file is already in the case, or the case is currently analyzing.")
		return
	}
	if errors.Is(err, store.ErrLimitExceeded) {
		httpx.WriteError(w, r, http.StatusRequestEntityTooLarge, httpx.CodeValidationFailed, "A case can retain up to 20 files, 10 GiB, and 50,000,000 records. Start another case for additional evidence.")
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	principal := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: principal.Name, Action: "security.offline_case.upload", Resource: name,
		Result:        fmt.Sprintf("Success — %s, %d records, sha256 %s", parsed.EvidenceType, len(parsed.Records), file.SHA256),
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusCreated, file)
}

func (s *Server) analyzeOfflineInvestigation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "investigationId")
	investigation, err := s.store.OfflineInvestigation(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if investigation.Status == "queued" || investigation.Status == "analyzing" {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeValidationFailed, "This case is already being analyzed.")
		return
	}
	files, err := s.store.OfflineInvestigationFiles(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if len(files) == 0 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Upload at least one supported evidence file before analysis.")
		return
	}
	principal := auth.UserFromContext(r.Context())
	job, err := s.store.CreateJob(r.Context(), model.Job{
		Type: offlineinvestigations.AnalysisJobType, Tenant: investigation.TenantLabel, Status: "Queued",
		Progress: 0, Started: "Just now", TriggeredBy: principal.Name,
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	payload, _ := json.Marshal(offlineinvestigations.AnalysisPayload{
		InvestigationID: id, Actor: principal.Name, CorrelationID: httpx.CorrelationID(r.Context()),
	})
	if err := s.store.UpdateOfflineInvestigationStatus(r.Context(), id, "queued", 0, "Waiting for analysis worker"); err != nil {
		_ = s.store.CompleteJob(r.Context(), job.ID, "Failed", "0s")
		s.writeErr(w, r, err)
		return
	}
	if err := s.jobs.Enqueue(r.Context(), offlineinvestigations.AnalysisJobType, job.ID, string(payload)); err != nil {
		_ = s.store.UpdateOfflineInvestigationStatus(r.Context(), id, "failed", 100, "Could not queue analysis")
		_ = s.store.CompleteJob(r.Context(), job.ID, "Failed", "0s")
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: principal.Name, Action: "security.offline_case.analyze", Resource: investigation.Name,
		Result: "Queued", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusAccepted, job)
}

func (s *Server) deleteOfflineInvestigation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "investigationId")
	investigation, err := s.store.OfflineInvestigation(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if investigation.Status == "queued" || investigation.Status == "analyzing" {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeValidationFailed, "Wait for analysis to finish before deleting the case.")
		return
	}
	if err := s.store.DeleteOfflineInvestigation(r.Context(), id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	principal := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: principal.Name, Action: "security.offline_case.delete", Resource: investigation.Name,
		Result: "Success — encrypted source files and derived case data removed", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	w.WriteHeader(http.StatusNoContent)
}

func offlineEvidenceType(contentType string) string {
	switch contentType {
	case m365audit.ContentTypeEntraSignIn:
		return offlineinvestigations.EvidenceEntraSignIns
	case m365audit.ContentTypeEntraDirectoryAudit:
		return offlineinvestigations.EvidenceEntraDirectoryAudit
	default:
		return offlineinvestigations.EvidenceM365Activity
	}
}

func offlineEventSource(sources []string) string {
	for _, source := range sources {
		if source != "offline_import" {
			return source
		}
	}
	return "offline_import"
}

func severityRank(severity string) int {
	return map[string]int{"Critical": 4, "High": 3, "Medium": 2, "Low": 1}[severity]
}
