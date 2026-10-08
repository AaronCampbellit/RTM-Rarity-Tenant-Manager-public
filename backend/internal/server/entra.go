package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
)

func (s *Server) getPreflight(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	if _, err := s.store.Tenant(r.Context(), tenantID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	preflight, err := s.store.TenantPreflight(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, preflight)
}

// runPreflight probes the tenant's Graph app permissions per feature area
// (POST, like /test, because it performs live diagnostics). Read areas are
// verified with harmless GETs; write permissions report "unchecked" with the
// required permission listed. The run is audited.
func (s *Server) runPreflight(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	t, err := s.store.Tenant(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	checks, err := s.graph.Preflight(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if provider, ok := s.graph.(graph.SharePointPreflightProvider); ok {
		checks = append(checks, provider.SharePointPreflight(r.Context(), tenantID)...)
	}
	if s.audit != nil {
		checks = append(checks, s.audit.FastIdentityPreflight(r.Context(), tenantID), s.audit.Preflight(r.Context(), tenantID))
	}
	for i := range checks {
		checks[i].Category = preflightCategory(checks[i])
	}
	mode := "live"
	missing := 0
	for _, c := range checks {
		if c.Status == "sample" {
			mode = "sample"
		}
		if c.Status == "missing" {
			missing++
		}
	}
	preflight := model.Preflight{
		Mode: mode, RanAt: time.Now().UTC().Format(time.RFC3339), Checks: checks,
	}
	if err := s.store.UpsertTenantPreflight(r.Context(), tenantID, preflight); err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	result := "Success"
	if missing > 0 {
		result = "Failed"
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "tenant.preflight", Resource: t.Name, Result: result,
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, preflight)
}

func preflightCategory(check model.PreflightCheck) string {
	area := strings.ToLower(check.Area)
	resource := strings.ToLower(check.Resource)
	switch {
	case strings.Contains(area, "security operations"),
		strings.Contains(area, "fast identity"),
		strings.Contains(area, "audit ingestion"):
		return "Security Operations"
	case strings.Contains(area, "sharepoint"), strings.Contains(resource, "sharepoint"):
		return "SharePoint"
	case strings.Contains(area, "exchange"), strings.Contains(area, "mailbox"),
		strings.Contains(resource, "exchange"):
		return "Exchange"
	case area == "licensing":
		return "Licensing"
	default:
		return "Directory & Identity"
	}
}

// getUserRaw serves the full directory object for one user — every attribute
// the app can read, including extension attributes. It is a deep PII read, so
// each view is audited.
func (s *Server) getUserRaw(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	userID := chi.URLParam(r, "userId")
	if _, err := s.store.Tenant(r.Context(), tenantID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	raw, err := s.graph.UserRaw(r.Context(), tenantID, userID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "user.raw_view", Resource: raw.ID, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, raw)
}
