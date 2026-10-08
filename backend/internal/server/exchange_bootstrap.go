package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/exchangebootstrap"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
)

type exchangeBootstrapApproval struct {
	TenantID    string `json:"tenantId"`
	Role        string `json:"role"`
	Scope       string `json:"scope"`
	CallbackURL string `json:"callbackUrl"`
}

func exchangeBootstrapApprovalPayload(tenantID, callbackURL string) exchangeBootstrapApproval {
	return exchangeBootstrapApproval{TenantID: tenantID, Role: "Recipient Management", Scope: "/", CallbackURL: callbackURL}
}

func (s *Server) previewExchangeBootstrap(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	tenant, err := s.store.Tenant(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	callbackURL, httpsReady := s.exchangeBootstrapCallback()
	principal := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: principal.Name, Action: "exchange.bootstrap.preview", Resource: tenant.Name + " / Recipient Management", Result: "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"approvalToken": s.issueApproval(r, exchangeBootstrapApprovalPayload(tenantID, callbackURL)),
		"preview":       exchangebootstrap.AuthorizationPreview(),
		"callbackUrl":   callbackURL,
		"httpsReady":    httpsReady,
	})
}

func (s *Server) startExchangeBootstrap(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	callbackURL, httpsReady := s.exchangeBootstrapCallback()
	if !httpsReady {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeNotConnected,
			"RTM must be available through HTTPS before Microsoft can return the one-time Exchange authorization.")
		return
	}
	var body struct {
		ApprovalToken string `json:"approvalToken"`
		ClientID      string `json:"clientId"`
		ClientSecret  string `json:"clientSecret"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A current preview and one-time bootstrap application credentials are required.")
		return
	}
	body.ClientID = strings.TrimSpace(body.ClientID)
	if !validApplicationID(body.ClientID) || len(body.ClientSecret) < 8 || len(body.ClientSecret) > 2048 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Enter a valid bootstrap application ID and client secret.")
		return
	}
	if !s.consumeApproval(w, r, body.ApprovalToken, exchangeBootstrapApprovalPayload(tenantID, callbackURL)) {
		return
	}
	tenant, err := s.store.Tenant(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	creds, err := s.store.TenantCreds(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	principal := auth.UserFromContext(r.Context())
	bootstrapSecret := []byte(body.ClientSecret)
	result, err := s.exchangeBootstrap.Start(exchangebootstrap.StartInput{
		TenantID: tenant.ID, TenantName: tenant.Name, DirectoryID: creds.Authority(),
		ActorID: principal.ID, ActorName: principal.Name,
		BootstrapClientID: body.ClientID, BootstrapClientSecret: bootstrapSecret, RedirectURL: callbackURL,
	})
	for i := range bootstrapSecret {
		bootstrapSecret[i] = 0
	}
	body.ClientSecret = ""
	if err != nil {
		s.log.Error("exchange bootstrap start", "error", err, "tenant_id", tenantID, "correlation_id", httpx.CorrelationID(r.Context()))
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.CodeInternalError, "Exchange authorization could not be started.")
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: principal.Name, Action: "exchange.bootstrap.start", Resource: tenant.Name + " / Recipient Management", Result: "Pending", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) exchangeBootstrapCallback() (string, bool) {
	callback := strings.TrimRight(s.cfg.CORSOrigin, "/") + "/api/v1/microsoft/exchange/bootstrap/callback"
	parsed, err := url.Parse(callback)
	if err != nil || parsed.Host == "" {
		return callback, false
	}
	if parsed.Scheme == "https" {
		return callback, true
	}
	local := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"
	return callback, !s.cfg.IsProduction() && parsed.Scheme == "http" && local
}

func validApplicationID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func (s *Server) completeExchangeBootstrap(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Exchange authorization response was invalid. Return to RTM.", http.StatusBadRequest)
		return
	}
	state := strings.TrimSpace(r.PostFormValue("state"))
	code := strings.TrimSpace(r.PostFormValue("code"))
	completion, err := s.exchangeBootstrap.Complete(r.Context(), state, code)
	status := "success"
	result := "Success"
	if err != nil {
		status, result = "error", "Failed"
		if r.PostFormValue("error") == "access_denied" {
			status, result = "cancelled", "Cancelled"
		}
		s.log.Warn("exchange bootstrap callback failed", "error", err, "tenant_id", completion.TenantID, "correlation_id", httpx.CorrelationID(r.Context()))
	}
	if completion.ActorName != "" {
		_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
			Actor: completion.ActorName, Action: "exchange.bootstrap.complete", Resource: completion.TenantName + " / Recipient Management", Result: result, CorrelationID: httpx.CorrelationID(r.Context()),
		})
	}

	base := strings.TrimRight(s.cfg.CORSOrigin, "/")
	path := "/tenants"
	if completion.TenantID != "" {
		path += "/" + url.PathEscape(completion.TenantID)
	}
	destination, parseErr := url.Parse(base + path)
	if parseErr != nil {
		http.Error(w, "Exchange authorization finished. Return to RTM.", http.StatusBadRequest)
		return
	}
	query := destination.Query()
	query.Set("exchangeAuthorization", status)
	if completion.Created {
		query.Set("assignment", "created")
	} else if err == nil {
		query.Set("assignment", "existing")
	}
	destination.RawQuery = query.Encode()
	http.Redirect(w, r, destination.String(), http.StatusSeeOther)
}
