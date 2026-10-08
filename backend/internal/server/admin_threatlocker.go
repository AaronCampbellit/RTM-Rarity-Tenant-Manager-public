package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
)

type adminThreatLockerStatus struct {
	Configured      bool   `json:"configured"`
	TokenConfigured bool   `json:"tokenConfigured"`
	Source          string `json:"source"`
	Instance        string `json:"instance"`
	ParentOrgID     string `json:"parentOrganizationId"`
}

func completeThreatLockerAuth(a threatlocker.Auth) bool {
	return strings.TrimSpace(a.Instance) != "" && a.Token != "" && strings.TrimSpace(a.OrgID) != ""
}

func (s *Server) globalThreatLockerAuth(ctx context.Context) (threatlocker.Auth, string, error) {
	c, err := s.store.ThreatLockerGlobalConfig(ctx)
	if err != nil {
		return threatlocker.Auth{}, "", err
	}
	a := threatlocker.Auth{Instance: strings.TrimSpace(c.Instance), Token: c.Token, OrgID: strings.TrimSpace(c.ParentOrgID)}
	if completeThreatLockerAuth(a) {
		return a, "database", nil
	}
	if s.cfg == nil {
		return threatlocker.Auth{}, "none", nil
	}
	a = threatlocker.Auth{Instance: strings.TrimSpace(s.cfg.ThreatLockerInstance), Token: s.cfg.ThreatLockerToken, OrgID: strings.TrimSpace(s.cfg.ThreatLockerParentOrgID)}
	if completeThreatLockerAuth(a) {
		return a, "environment", nil
	}
	return threatlocker.Auth{}, "none", nil
}

func (s *Server) adminThreatLocker(w http.ResponseWriter, r *http.Request) {
	a, source, err := s.globalThreatLockerAuth(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, adminThreatLockerStatus{
		Configured: completeThreatLockerAuth(a), TokenConfigured: a.Token != "", Source: source,
		Instance: a.Instance, ParentOrgID: a.OrgID,
	})
}

func (s *Server) updateAdminThreatLocker(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Instance    string `json:"instance"`
		Token       string `json:"token"`
		ParentOrgID string `json:"parentOrganizationId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if body.Token == "" {
		current, _, err := s.globalThreatLockerAuth(r.Context())
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		body.Token = current.Token
	}
	c := store.ThreatLockerGlobalConfig{Instance: strings.TrimSpace(body.Instance), Token: body.Token, ParentOrgID: strings.TrimSpace(body.ParentOrgID)}
	if c.Instance == "" || c.Token == "" || c.ParentOrgID == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Portal instance, API token, and MSP parent organization ID are required.")
		return
	}
	candidate := threatlocker.Auth{Instance: c.Instance, Token: c.Token, OrgID: c.ParentOrgID}
	if err := s.tl.TestConnectionForAuth(r.Context(), candidate); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"ThreatLocker connection test failed; the current global settings were preserved. "+threatLockerConnectionDetail(err))
		return
	}
	if err := s.store.UpdateThreatLockerGlobalConfig(r.Context(), c); err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{Actor: user.Name, Action: "threatlocker.global.configure", Resource: "MSP parent organization", Result: "Success", CorrelationID: httpx.CorrelationID(r.Context())})
	httpx.WriteJSON(w, http.StatusOK, adminThreatLockerStatus{Configured: true, TokenConfigured: true, Source: "database", Instance: c.Instance, ParentOrgID: c.ParentOrgID})
}
