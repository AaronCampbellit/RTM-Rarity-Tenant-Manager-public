package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/securityops"
	"github.com/rarity/rtm/internal/store"
)

const maxBulkSecurityIncidents = 100

// securityOperations returns one bounded-concurrency cross-tenant snapshot so
// the frontend does not issue separate overview, connector, and incident
// requests. Partial tenant failures remain visible in Coverage and Warnings.
func (s *Server) securityOperations(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.security.Snapshot(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "security.operations.view", Resource: "All managed tenants", Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, snapshot)
}

func (s *Server) getSecurityStoryline(w http.ResponseWriter, r *http.Request) {
	detail, err := s.security.Storyline(r.Context(), chi.URLParam(r, "storylineId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "security.storyline.view", Resource: detail.Title, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, detail)
}

// triageSecurityStoryline changes RTM's analyst workflow only. It never
// mutates Microsoft 365; containment actions remain separate What-If writes.
func (s *Server) triageSecurityStoryline(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status     *string `json:"status"`
		Assignment *string `json:"assignment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if body.Status == nil && body.Assignment == nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Provide a storyline status or assignment change.")
		return
	}
	current, err := s.security.Storyline(r.Context(), chi.URLParam(r, "storylineId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	status, owner := current.Status, current.Owner
	if body.Status != nil {
		status = strings.TrimSpace(*body.Status)
	}
	user := auth.UserFromContext(r.Context())
	if body.Assignment != nil {
		switch strings.ToLower(strings.TrimSpace(*body.Assignment)) {
		case "me":
			owner = user.Name
		case "unassigned":
			owner = ""
		default:
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Assignment must be 'me' or 'unassigned'.")
			return
		}
	}
	updated, err := s.security.TriageStoryline(r.Context(), current.ID, status, owner, user.Name)
	if errors.Is(err, securityops.ErrInvalidTriageStatus) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Status must be New, In Progress, Resolved, or Dismissed.")
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "security.storyline.triage", Resource: updated.Title, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, updated)
}

func (s *Server) getSecurityIncident(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	incidentID := chi.URLParam(r, "incidentId")
	detail, err := s.security.Incident(r.Context(), tenantID, incidentID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "security.incident.view",
		Resource: detail.TenantName + " / " + detail.Title, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, detail)
}

// triageSecurityIncident updates RTM-local SOC workflow state only. It does
// not patch Defender and does not mutate the customer tenant, so the M365
// What-If gate is intentionally not involved.
func (s *Server) triageSecurityIncident(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status     *string `json:"status"`
		Assignment *string `json:"assignment"` // me | unassigned
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if body.Status == nil && body.Assignment == nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Provide a triage status or assignment change.")
		return
	}
	user := auth.UserFromContext(r.Context())
	var owner *string
	if body.Assignment != nil {
		value := ""
		switch strings.ToLower(strings.TrimSpace(*body.Assignment)) {
		case "me":
			value = user.Name
		case "unassigned":
		default:
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
				"Assignment must be 'me' or 'unassigned'.")
			return
		}
		owner = &value
	}
	detail, err := s.security.Triage(
		r.Context(), chi.URLParam(r, "tenantId"), chi.URLParam(r, "incidentId"),
		body.Status, owner, user.Name,
	)
	if errors.Is(err, securityops.ErrInvalidTriageStatus) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Status must be New, In Progress, Resolved, or Dismissed.")
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "security.incident.triage",
		Resource: detail.TenantName + " / " + detail.Title, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, detail)
}

// bulkTriageSecurityIncidents updates multiple RTM-local incident workflow
// overlays. It never writes to Microsoft or a customer tenant. Accept assigns
// the current operator and advances only New incidents to In Progress; an
// explicit status change preserves the current owner.
func (s *Server) bulkTriageSecurityIncidents(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Incidents []struct {
			TenantID   string `json:"tenantId"`
			IncidentID string `json:"incidentId"`
		} `json:"incidents"`
		Action string  `json:"action"`
		Status *string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if len(body.Incidents) == 0 || len(body.Incidents) > maxBulkSecurityIncidents {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Select between 1 and 100 incidents.")
		return
	}
	action := strings.ToLower(strings.TrimSpace(body.Action))
	if action != "accept" && action != "set_status" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Action must be 'accept' or 'set_status'.")
		return
	}
	if action == "accept" && body.Status != nil || action == "set_status" && body.Status == nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Accept does not take a status; set_status requires one.")
		return
	}

	references := make([]securityops.IncidentReference, 0, len(body.Incidents))
	seen := make(map[string]struct{}, len(body.Incidents))
	for _, incident := range body.Incidents {
		tenantID, incidentID := strings.TrimSpace(incident.TenantID), strings.TrimSpace(incident.IncidentID)
		if tenantID == "" || incidentID == "" {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
				"Every selected incident must include tenantId and incidentId.")
			return
		}
		key := tenantID + "\x00" + incidentID
		if _, duplicate := seen[key]; duplicate {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
				"The selected incident list contains a duplicate.")
			return
		}
		seen[key] = struct{}{}
		references = append(references, securityops.IncidentReference{TenantID: tenantID, IncidentID: incidentID})
	}

	user := auth.UserFromContext(r.Context())
	outcomes, err := s.security.BulkTriage(r.Context(), references, securityops.BulkTriageOptions{
		Status: body.Status, Accept: action == "accept", Actor: user.Name,
	})
	if errors.Is(err, securityops.ErrInvalidTriageStatus) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Status must be New, In Progress, Resolved, or Dismissed.")
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}

	type failure struct {
		TenantID   string `json:"tenantId"`
		IncidentID string `json:"incidentId"`
		Message    string `json:"message"`
	}
	type updatedIncident struct {
		TenantID   string `json:"tenantId"`
		IncidentID string `json:"incidentId"`
		Status     string `json:"status"`
		Owner      string `json:"owner,omitempty"`
	}
	response := struct {
		Requested int               `json:"requested"`
		Updated   int               `json:"updated"`
		Failed    int               `json:"failed"`
		Incidents []updatedIncident `json:"incidents"`
		Failures  []failure         `json:"failures"`
	}{
		Requested: len(references),
		Incidents: make([]updatedIncident, 0, len(references)),
		Failures:  []failure{},
	}
	for _, outcome := range outcomes {
		if outcome.Err == nil {
			response.Updated++
			response.Incidents = append(response.Incidents, updatedIncident{
				TenantID: outcome.Incident.TenantID, IncidentID: outcome.Incident.ID,
				Status: outcome.Incident.Status, Owner: outcome.Incident.Owner,
			})
			continue
		}
		response.Failed++
		message := "Incident could not be updated. Refresh the queue and try again."
		if errors.Is(outcome.Err, store.ErrNotFound) {
			message = "Incident is no longer available. Refresh the queue."
		}
		s.log.Warn("bulk security incident triage failed",
			"tenant_id", outcome.Reference.TenantID, "incident_id", outcome.Reference.IncidentID,
			"error", outcome.Err, "correlation_id", httpx.CorrelationID(r.Context()))
		response.Failures = append(response.Failures, failure{
			TenantID: outcome.Reference.TenantID, IncidentID: outcome.Reference.IncidentID, Message: message,
		})
	}
	result := "Success"
	if response.Failed > 0 {
		result = "Partial"
		if response.Updated == 0 {
			result = "Failed"
		}
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "security.incident.bulk_triage",
		Resource: fmt.Sprintf("%d security incidents", response.Requested), Result: result,
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, response)
}
