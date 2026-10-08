package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
)

type tenantSettingsRequest struct {
	Name                 *string `json:"name,omitempty"`
	Domain               *string `json:"domain,omitempty"`
	MicrosoftTenantID    *string `json:"microsoftTenantId,omitempty"`
	ClientID             *string `json:"clientId,omitempty"`
	ClientSecret         *string `json:"clientSecret,omitempty"`
	ExchangeClientID     *string `json:"exchangeClientId,omitempty"`
	ExchangeClientSecret *string `json:"exchangeClientSecret,omitempty"`
	SharePointAdminURL   *string `json:"sharePointAdminUrl,omitempty"`
	ThreatLockerInstance *string `json:"threatLockerInstance,omitempty"`
	ThreatLockerToken    *string `json:"threatLockerToken,omitempty"`
	ThreatLockerOrgID    *string `json:"threatLockerOrgId,omitempty"`
	ClearGraph           bool    `json:"clearGraph,omitempty"`
	ClearExchange        bool    `json:"clearExchange,omitempty"`
	ClearThreatLocker    bool    `json:"clearThreatLocker,omitempty"`
}

func (s *Server) updateTenantSettings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "tenantId")
	current, err := s.store.Tenant(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	currentCreds, err := s.store.TenantCreds(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var body tenantSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if message := validateTenantSettings(body, currentCreds); message != "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, message)
		return
	}
	update := store.TenantUpdate{
		Name: body.Name, Domain: body.Domain, MicrosoftTenantID: body.MicrosoftTenantID,
		ClientID: body.ClientID, ClientSecret: nonblank(body.ClientSecret),
		ExchangeClientID: body.ExchangeClientID, ExchangeClientSecret: nonblank(body.ExchangeClientSecret),
		SharePointAdminURL: body.SharePointAdminURL,
		ClearGraph:         body.ClearGraph, ClearExchange: body.ClearExchange,
	}
	updated, err := s.store.UpdateTenant(r.Context(), id, update)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}

	graphChanged := graphSettingsChanged(body, current, currentCreds)
	if graphChanged {
		if testErr := s.graph.TestConnection(r.Context(), id); testErr != nil {
			_, _ = s.store.UpdateTenant(r.Context(), id, restoreTenantUpdate(current, currentCreds))
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
				"Updated Microsoft connection test failed; previous settings were restored. "+connectionDetail(testErr))
			return
		}
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "tenant.settings_update",
		Resource: tenantSettingsAuditSummary(updated.Name, body), Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, struct {
		Tenant model.Tenant `json:"tenant"`
	}{updated})
}

func graphSettingsChanged(body tenantSettingsRequest, current model.Tenant, creds store.TenantCreds) bool {
	return body.ClearGraph ||
		(body.ClientID != nil && *body.ClientID != creds.ClientID) ||
		nonblank(body.ClientSecret) != nil ||
		(body.Domain != nil && *body.Domain != current.Domain) ||
		(body.MicrosoftTenantID != nil && *body.MicrosoftTenantID != current.MicrosoftTenantID)
}

func validateTenantSettings(body tenantSettingsRequest, current store.TenantCreds) string {
	for label, value := range map[string]*string{
		"Tenant name": body.Name, "Domain": body.Domain, "Microsoft tenant ID": body.MicrosoftTenantID,
	} {
		if value != nil && strings.TrimSpace(*value) == "" {
			return label + " cannot be blank."
		}
	}
	if body.ClearGraph && (body.ClientID != nil || nonblank(body.ClientSecret) != nil) {
		return "Graph credentials cannot be replaced and cleared in the same update."
	}
	if body.ClearExchange && (body.ExchangeClientID != nil || nonblank(body.ExchangeClientSecret) != nil) {
		return "Exchange credentials cannot be replaced and cleared in the same update."
	}
	if body.ThreatLockerInstance != nil || body.ThreatLockerToken != nil || body.ThreatLockerOrgID != nil || body.ClearThreatLocker {
		return "ThreatLocker is configured globally in Admin Settings and cannot be set on a tenant."
	}
	if body.ClientID != nil && *body.ClientID != current.ClientID && nonblank(body.ClientSecret) == nil {
		return "Changing the Graph client ID requires a replacement client secret."
	}
	if body.ExchangeClientID != nil && *body.ExchangeClientID != current.ExchangeClientID && nonblank(body.ExchangeClientSecret) == nil {
		return "Changing the Exchange client ID requires a replacement client secret."
	}
	if body.SharePointAdminURL != nil && *body.SharePointAdminURL != "" {
		parsed, err := url.Parse(*body.SharePointAdminURL)
		if err != nil || parsed.Scheme != "https" || !strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".sharepoint.com") {
			return "SharePoint admin URL must be an HTTPS sharepoint.com URL."
		}
	}
	return ""
}

func nonblank(value *string) *string {
	if value == nil || *value == "" {
		return nil
	}
	return value
}

func restoreTenantUpdate(t model.Tenant, c store.TenantCreds) store.TenantUpdate {
	return store.TenantUpdate{
		Name: &t.Name, Domain: &t.Domain, MicrosoftTenantID: &t.MicrosoftTenantID,
		ClientID: &c.ClientID, ClientSecret: &c.ClientSecret,
		ExchangeClientID: &c.ExchangeClientID, ExchangeClientSecret: &c.ExchangeClientSecret,
		SharePointAdminURL: &c.SharePointAdminURL,
		ClearGraph:         c.ClientID == "", ClearExchange: c.ExchangeClientID == "",
	}
}

func tenantSettingsAuditSummary(name string, body tenantSettingsRequest) string {
	changes := []string{}
	if body.Name != nil || body.Domain != nil || body.MicrosoftTenantID != nil {
		changes = append(changes, "metadata")
	}
	if body.ClientID != nil || nonblank(body.ClientSecret) != nil || body.ClearGraph {
		changes = append(changes, "graph_credentials_changed")
	}
	if body.ExchangeClientID != nil || nonblank(body.ExchangeClientSecret) != nil || body.ClearExchange {
		changes = append(changes, "exchange_credentials_changed")
	}
	if body.SharePointAdminURL != nil {
		changes = append(changes, "sharepoint_admin_url")
	}
	return name + " (" + strings.Join(changes, ",") + ")"
}
