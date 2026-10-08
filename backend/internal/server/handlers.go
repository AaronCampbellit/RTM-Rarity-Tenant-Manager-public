package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/seed"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
	"github.com/rarity/rtm/internal/worker"
)

// writeErr maps domain errors to the standard envelope.
func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *graph.APIError
	var exchangeErr *graph.ExchangeAPIError
	var tlErr *threatlocker.APIError
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, httpx.CodeObjectNotFound, "The requested object was not found.")
	case errors.Is(err, threatlocker.ErrNotSupported):
		httpx.WriteError(w, r, http.StatusNotImplemented, httpx.CodeNotImplemented,
			"This ThreatLocker action isn't available through the portal API (lockdown, isolation, and tamper-protection toggles are not exposed).")
	case errors.Is(err, threatlocker.ErrNotConnected):
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeNotConnected,
			"ThreatLocker is not configured — add the MSP parent connection in Admin Settings.")
	case errors.As(err, &tlErr):
		// ThreatLocker said no — pass its reason through so the operator can
		// fix the token/permissions without reading server logs.
		s.log.Warn("threatlocker api error", "path", tlErr.Path, "status", tlErr.Status,
			"message", tlErr.Message, "correlation_id", httpx.CorrelationID(r.Context()))
		switch tlErr.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeThreatLockerFailed,
				"ThreatLocker rejected the API credentials — check the API token, its organization permissions, and the organization ID. "+threatLockerDetail(tlErr))
		case http.StatusTooManyRequests:
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeThreatLockerFailed,
				"ThreatLocker is throttling requests. Please retry shortly.")
		default:
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeThreatLockerFailed,
				"ThreatLocker request failed. "+threatLockerDetail(tlErr))
		}
	case errors.Is(err, graph.ErrLiveNotImplemented):
		httpx.WriteError(w, r, http.StatusNotImplemented, httpx.CodeNotImplemented, "Live Microsoft Graph is not yet wired for this data.")
	case errors.Is(err, graph.ErrExchangeOnly):
		httpx.WriteError(w, r, http.StatusNotImplemented, httpx.CodeNotImplemented,
			"This operation requires Exchange Online and is not available through Microsoft Graph.")
	case errors.Is(err, graph.ErrExchangeAdminUnsupported):
		httpx.WriteError(w, r, http.StatusNotImplemented, httpx.CodeNotImplemented,
			"The Exchange Online Admin API currently supports Send on Behalf delegates only. Full Access and Send As require the controlled Exchange Online PowerShell connector.")
	case errors.Is(err, graph.ErrSharePointOnly):
		httpx.WriteError(w, r, http.StatusNotImplemented, httpx.CodeNotImplemented,
			"Microsoft Graph does not expose this SharePoint operation — it needs the SharePoint admin integration, which is not yet enabled for live tenants.")
	case errors.As(err, &exchangeErr):
		s.log.Warn("exchange online admin api error", "path", exchangeErr.Path, "status", exchangeErr.Status,
			"message", exchangeErr.Message, "correlation_id", httpx.CorrelationID(r.Context()))
		switch exchangeErr.Status {
		case http.StatusBadRequest:
			if strings.HasPrefix(exchangeErr.Path, "token") {
				httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeMicrosoftPermMissing,
					"Exchange Online could not issue the required app-only token — grant Exchange.ManageAsAppV2 admin consent for the active app registration. "+exchangeDetail(exchangeErr))
				break
			}
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeMicrosoftConnFailed,
				"Exchange Online rejected the request shape. "+exchangeDetail(exchangeErr))
		case http.StatusNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.CodeObjectNotFound,
				"Exchange Online has no such mailbox, or the Admin API preview is not enabled for this organization. "+exchangeDetail(exchangeErr))
		case http.StatusForbidden:
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeMicrosoftPermMissing,
				"Exchange Online denied the request — grant Exchange.ManageAsAppV2 admin consent and assign the app an Exchange RBAC role containing Get-Mailbox (Recipient Management). "+exchangeDetail(exchangeErr))
		case http.StatusUnauthorized:
			// The Exchange Admin API returns 401 when Entra can issue an
			// Outlook-scoped token but that app token lacks the Exchange app
			// role/RBAC assignment. Surface the same actionable remediation as
			// a 403 instead of misdiagnosing a valid client secret.
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeMicrosoftPermMissing,
				"Exchange Online denied the app-only token — grant Exchange.ManageAsAppV2 admin consent and assign the app an Exchange RBAC role containing Get-Mailbox (Recipient Management). "+exchangeDetail(exchangeErr))
		case http.StatusTooManyRequests:
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeMicrosoftThrottled,
				"Exchange Online is throttling requests. Please retry shortly.")
		default:
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeMicrosoftConnFailed,
				"Exchange Online Admin API request failed. "+exchangeDetail(exchangeErr))
		}
	case errors.As(err, &apiErr):
		// Microsoft said no — pass its reason through so the operator can fix
		// the app registration/consent without reading server logs.
		switch apiErr.Status {
		case http.StatusNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.CodeObjectNotFound,
				"Microsoft Graph has no such object. "+microsoftDetail(apiErr))
		case http.StatusForbidden:
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeMicrosoftPermMissing,
				"Microsoft Graph denied the request — the app registration is missing admin-consented application permissions. "+microsoftDetail(apiErr))
		case http.StatusUnauthorized:
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeMicrosoftConnFailed,
				"Microsoft rejected the app credentials. "+microsoftDetail(apiErr))
		case http.StatusTooManyRequests:
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeMicrosoftThrottled,
				"Microsoft Graph is throttling requests. Please retry shortly.")
		default:
			httpx.WriteError(w, r, http.StatusBadGateway, httpx.CodeMicrosoftConnFailed,
				"Microsoft Graph request failed. "+microsoftDetail(apiErr))
		}
	default:
		s.log.Error("handler", "error", err, "correlation_id", httpx.CorrelationID(r.Context()))
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.CodeInternalError, "An unexpected error occurred.")
	}
}

func exchangeDetail(e *graph.ExchangeAPIError) string {
	parts := make([]string, 0, 2)
	if e.Code != "" {
		parts = append(parts, "Microsoft error "+e.Code+".")
	}
	if e.Message != "" {
		message := strings.TrimSpace(e.Message)
		if len(message) > 500 {
			message = message[:500] + "…"
		}
		parts = append(parts, message)
	}
	return strings.Join(parts, " ")
}

// microsoftDetail renders Microsoft's own error code/message for envelopes
// (server-to-server detail; never contains tokens or secrets).
func microsoftDetail(e *graph.APIError) string {
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("Microsoft error %s: %s", e.Code, e.Message)
	case e.Code != "":
		return "Microsoft error " + e.Code + "."
	default:
		return fmt.Sprintf("Microsoft returned HTTP %d.", e.Status)
	}
}

// threatLockerDetail renders ThreatLocker's own error for envelopes (never
// contains the API token).
func threatLockerDetail(e *threatlocker.APIError) string {
	endpoint := ""
	if e.Path != "" {
		endpoint = " (endpoint " + e.Path + ")"
	}
	if e.Message != "" {
		return "ThreatLocker said: " + e.Message + endpoint
	}
	return fmt.Sprintf("ThreatLocker returned HTTP %d%s.", e.Status, endpoint)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"name": "RTM API", "version": "0.1.0-beta", "env": s.cfg.Env,
		"graph": s.graph.Mode(), "store": s.cfg.StoreMode(),
	})
}

// ---- Tenants ----

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.Tenants(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.enrichTenantUserCounts(r.Context(), ts)
	httpx.WriteJSON(w, http.StatusOK, ts)
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.Tenant(r.Context(), chi.URLParam(r, "tenantId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	t.Users = s.tenantUserCount(r.Context(), t.ID, t.Users)
	// Enrich the detail view with the hybrid identity summary (source of
	// authority is read from Graph, so this is detail-only. The list endpoint
	// performs only the lightweight user-count projection above.
	t.IdentityMode, t.SyncedUsers, t.CloudUsers, t.SyncedGroups, t.CloudGroups = s.tenantIdentity(r.Context(), t.ID)
	httpx.WriteJSON(w, http.StatusOK, t)
}

// createTenant connects a new managed tenant (admin-only). Optional per-tenant
// Entra app credentials are stored write-only: they are never echoed back in
// any response and never logged. The connection is tested immediately so the
// row lands with an honest status.
func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name              string `json:"name"`
		Domain            string `json:"domain"`
		MicrosoftTenantID string `json:"microsoftTenantId"`
		ClientID          string `json:"clientId"`
		ClientSecret      string `json:"clientSecret"`

		ExchangeClientID       string `json:"exchangeClientId"`
		ExchangeClientSecret   string `json:"exchangeClientSecret"`
		SharePointClientID     string `json:"sharePointClientId"`
		SharePointClientSecret string `json:"sharePointClientSecret"`
		SharePointAdminURL     string `json:"sharePointAdminUrl"`

		ThreatLockerInstance string `json:"threatLockerInstance"`
		ThreatLockerToken    string `json:"threatLockerToken"`
		ThreatLockerOrgID    string `json:"threatLockerOrgId"`

		HistoryWindow          string `json:"historyWindow"`
		HistoricalIncidentMode string `json:"historicalIncidentMode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if body.Name == "" || body.Domain == "" || body.MicrosoftTenantID == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Name, domain, and Microsoft tenant ID are required.")
		return
	}
	if (body.ClientID == "") != (body.ClientSecret == "") {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Provide both a client ID and a client secret, or neither to use the global app registration.")
		return
	}
	if (body.ExchangeClientID == "") != (body.ExchangeClientSecret == "") {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Provide both an Exchange Online client ID and secret, or neither to reuse the Graph app.")
		return
	}
	if (body.SharePointClientID == "") != (body.SharePointClientSecret == "") {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Provide both a SharePoint client ID and secret, or neither to reuse the Graph app.")
		return
	}
	if body.SharePointClientID != "" && strings.TrimSpace(body.SharePointAdminURL) == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"A SharePoint admin URL is required when a dedicated SharePoint app is configured.")
		return
	}
	if body.ThreatLockerToken != "" || body.ThreatLockerInstance != "" || body.ThreatLockerOrgID != "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"ThreatLocker is configured globally in Admin Settings and cannot be set on a tenant.")
		return
	}
	historyHours := map[string]int{"start_now": 0, "last_24h": 24, "last_7d": 168, "maximum_available": 168}
	if body.HistoryWindow != "" {
		if _, ok := historyHours[body.HistoryWindow]; !ok {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
				"History window must be start_now, last_24h, last_7d, or maximum_available.")
			return
		}
	}
	if body.HistoricalIncidentMode == "" {
		body.HistoricalIncidentMode = "recent_24h"
	}
	if body.HistoricalIncidentMode != "recent_24h" && body.HistoricalIncidentMode != "all" && body.HistoricalIncidentMode != "baseline_only" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Historical incident mode must be recent_24h, all, or baseline_only.")
		return
	}
	t, err := s.store.CreateTenant(r.Context(), store.NewTenant{
		Name: body.Name, Domain: body.Domain, MicrosoftTenantID: body.MicrosoftTenantID,
		ClientID: body.ClientID, ClientSecret: body.ClientSecret,
		ExchangeClientID: body.ExchangeClientID, ExchangeClientSecret: body.ExchangeClientSecret,
		SharePointClientID: body.SharePointClientID, SharePointClientSecret: body.SharePointClientSecret,
		SharePointAdminURL: strings.TrimSpace(body.SharePointAdminURL),
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	// Test the connection with the tenant's own authority/credentials so the
	// row lands with an honest status, and hand the reason back to the GUI
	// when it fails (missing consent, bad secret, …).
	status, connErr := "Connected", ""
	if err := s.graph.TestConnection(r.Context(), t.ID); err != nil {
		s.log.Warn("tenant connection test failed", "tenant", t.ID, "error", err)
		status, connErr = "Disconnected", connectionDetail(err)
	}
	if err := s.store.UpdateTenantStatus(r.Context(), t.ID, status, "just now"); err == nil {
		t.Status, t.LastGraphTest = status, "just now"
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "tenant.create", Resource: t.Name, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	var historyImport *model.SecurityHistoryImport
	if body.HistoryWindow != "" {
		requestedAt := time.Now().UTC()
		mode := body.HistoricalIncidentMode
		cutoff := requestedAt.Add(-24 * time.Hour)
		if mode == "all" {
			cutoff = time.Time{}
		} else if mode == "baseline_only" || body.HistoryWindow == "start_now" {
			cutoff = requestedAt
		}
		history := model.SecurityHistoryImport{
			TenantID: t.ID, TenantName: t.Name, RequestedWindow: body.HistoryWindow,
			WindowHours: historyHours[body.HistoryWindow], HistoricalIncidentMode: mode,
			Status: "completed", Progress: 100, RequestedAt: requestedAt,
			CompletedAt: requestedAt, IncidentCutoffAt: cutoff,
			Detail: "Monitoring starts now; no historical evidence was requested.",
		}
		if history.WindowHours > 0 {
			job, jobErr := s.store.CreateJob(r.Context(), model.Job{
				Type: "Security history import", Tenant: t.Name, Status: "Queued", Progress: 0,
				Started: requestedAt.Format("15:04"), Duration: "—", TriggeredBy: user.Name,
			})
			if jobErr == nil {
				history.JobID, history.Status, history.Progress, history.CompletedAt = job.ID, "queued", 0, time.Time{}
				history.Detail = "Waiting for the background worker; live monitoring starts independently."
			} else {
				history.Status, history.Progress, history.CompletedAt = "failed", 100, time.Now().UTC()
				history.Detail = "The history import job could not be created; live monitoring is still active."
			}
			stored, historyStoreErr := s.store.UpsertSecurityHistoryImport(r.Context(), history)
			if historyStoreErr == nil {
				history = stored
			} else {
				history.Status, history.Progress, history.CompletedAt = "failed", 100, time.Now().UTC()
				history.Detail = "The history import policy could not be saved; live monitoring is still active."
				if jobErr == nil {
					_ = s.store.CompleteJob(r.Context(), job.ID, "Failed", "—")
				}
			}
			if jobErr == nil && historyStoreErr == nil {
				raw, _ := json.Marshal(m365audit.HistoryBackfillPayload{TenantID: t.ID})
				if enqueueErr := s.jobs.Enqueue(r.Context(), m365audit.HistoryBackfillJobType, job.ID, string(raw)); enqueueErr != nil {
					history.Status, history.Progress, history.CompletedAt = "failed", 100, time.Now().UTC()
					history.Detail = "The history import could not be queued; live monitoring is still active."
					_, _ = s.store.UpsertSecurityHistoryImport(r.Context(), history)
					_ = s.store.CompleteJob(r.Context(), job.ID, "Failed", "—")
				}
			}
		} else if stored, storeErr := s.store.UpsertSecurityHistoryImport(r.Context(), history); storeErr == nil {
			history = stored
		}
		historyImport = &history
		auditResult := fmt.Sprintf("Success — %s, %s", body.HistoryWindow, mode)
		if history.Status == "failed" {
			auditResult = "Failed — " + history.Detail
		}
		_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
			Actor: user.Name, Action: "security.history_backfill.request", Resource: t.Name,
			Result:        auditResult,
			CorrelationID: httpx.CorrelationID(r.Context()),
		})
	}
	httpx.WriteJSON(w, http.StatusCreated, struct {
		model.Tenant
		ConnectionError string                       `json:"connectionError,omitempty"`
		HistoryImport   *model.SecurityHistoryImport `json:"historyImport,omitempty"`
	}{t, connErr, historyImport})
}

// connectionDetail turns a connection-test failure into an operator-facing
// explanation (Microsoft's own reason when available).
func connectionDetail(err error) string {
	var apiErr *graph.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusForbidden:
			return "Signed in, but Microsoft Graph denied the request — grant admin consent for the app's application permissions. " + microsoftDetail(apiErr)
		case http.StatusUnauthorized, http.StatusBadRequest:
			return "Microsoft rejected the app credentials — check the directory ID, client ID, and client secret. " + microsoftDetail(apiErr)
		default:
			return microsoftDetail(apiErr)
		}
	}
	return "Could not reach Microsoft: " + err.Error()
}

func threatLockerConnectionDetail(err error) string {
	var apiErr *threatlocker.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "ThreatLocker rejected the API credentials — check the API token, organization permissions, and organization ID. " + threatLockerDetail(apiErr)
		default:
			return "ThreatLocker request failed. " + threatLockerDetail(apiErr)
		}
	}
	if errors.Is(err, threatlocker.ErrNotConnected) {
		return "ThreatLocker is not connected — configure the MSP parent connection in Admin Settings."
	}
	return "Could not reach ThreatLocker: " + err.Error()
}

// deleteTenant fully removes a managed tenant and every technician grant on it
// (admin-only, audited).
func (s *Server) deleteTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "tenantId")
	t, err := s.store.Tenant(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := s.store.DeleteTenant(r.Context(), id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "tenant.delete", Resource: t.Name, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// testTenant re-runs the tenant connection tests, persists the resulting
// status, and reports provider reasons on failure so the GUI can show why a
// tenant isn't connecting.
func (s *Server) testTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "tenantId")
	_, err := s.store.Tenant(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	status, detail := "Connected", ""
	if err := s.graph.TestConnection(r.Context(), id); err != nil {
		s.log.Warn("tenant connection test failed", "tenant", id, "error", err)
		status, detail = "Disconnected", connectionDetail(err)
	}
	_ = s.store.UpdateTenantStatus(r.Context(), id, status, "just now")
	user := auth.UserFromContext(r.Context())
	result := "Success"
	if status != "Connected" {
		result = "Failed"
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "tenant.test", Resource: id, Result: result,
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": status, "error": detail})
}

// ---- Microsoft-sourced (Graph provider) ----

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	v, err := s.graph.Users(r.Context(), chi.URLParam(r, "tenantId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	v, err := s.graph.Groups(r.Context(), chi.URLParam(r, "tenantId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

// createGroup provisions a new group in the tenant (admin-only). v1 creates
// Microsoft 365 and security groups (Graph-creatable); distribution and
// mail-enabled security groups are Exchange-managed and not offered.
func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	var body struct {
		Name         string `json:"name"`
		Description  string `json:"description"`
		Type         string `json:"type"`
		MailNickname string `json:"mailNickname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Description = strings.TrimSpace(body.Description)
	if body.Name == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A group name is required.")
		return
	}
	if body.Description == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A group description is required.")
		return
	}
	if len(body.Name) > 256 || len(body.Description) > 1024 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "The group name or description is too long.")
		return
	}
	if body.Type != graph.GroupTypeM365 && body.Type != graph.GroupTypeSecurity {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Group type must be M365 or Security.")
		return
	}
	nick := mailNickname(body.MailNickname, body.Name)
	g, err := s.graph.CreateGroup(r.Context(), tenantID, graph.NewGroup{
		DisplayName: body.Name, Description: body.Description, MailNickname: nick, Type: body.Type,
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "group.create", Resource: g.Name, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusCreated, g)
}

// mailNickname derives a Graph-safe mail nickname (alphanumeric) from an
// explicit value or the group name.
func mailNickname(explicit, name string) string {
	src := explicit
	if src == "" {
		src = name
	}
	var b strings.Builder
	for _, ch := range src {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			b.WriteRune(ch)
		}
	}
	nick := b.String()
	if nick == "" {
		nick = "group"
	}
	if len(nick) > 60 {
		nick = nick[:60]
	}
	return nick
}

func (s *Server) listGroupMembers(w http.ResponseWriter, r *http.Request) {
	v, err := s.graph.GroupMembers(r.Context(), chi.URLParam(r, "tenantId"), chi.URLParam(r, "groupId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listLicenses(w http.ResponseWriter, r *http.Request) {
	v, err := s.graph.Licenses(r.Context(), chi.URLParam(r, "tenantId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listMailboxes(w http.ResponseWriter, r *http.Request) {
	v, err := s.graph.Mailboxes(r.Context(), chi.URLParam(r, "tenantId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) getMailboxSettings(w http.ResponseWriter, r *http.Request) {
	v, err := s.graph.MailboxSettings(r.Context(), chi.URLParam(r, "tenantId"), chi.URLParam(r, "mailboxId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listMailboxPermissions(w http.ResponseWriter, r *http.Request) {
	v, err := s.graph.MailboxPermissions(r.Context(), chi.URLParam(r, "tenantId"), chi.URLParam(r, "mailboxId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if v.Permissions == nil {
		v.Permissions = []model.MailboxPermission{}
	}
	if v.Coverage == nil {
		v.Coverage = []model.MailboxPermissionCoverage{}
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "exchange.mailbox_permissions.view",
		Resource: chi.URLParam(r, "tenantId") + " / " + chi.URLParam(r, "mailboxId"),
		Result:   "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listSitePermissions(w http.ResponseWriter, r *http.Request) {
	v, err := s.graph.SitePermissions(r.Context(), chi.URLParam(r, "tenantId"), chi.URLParam(r, "siteId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if v == nil {
		v = []model.SitePermission{}
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listSites(w http.ResponseWriter, r *http.Request) {
	v, err := s.graph.Sites(r.Context(), chi.URLParam(r, "tenantId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

// globalReport serves the cross-tenant read-only reports. The reports service
// fans out over every managed tenant in live mode (sample mode returns the
// seeded demo dataset).
func (s *Server) globalReport(w http.ResponseWriter, r *http.Request) {
	v, err := s.reports.Global(r.Context(), chi.URLParam(r, "type"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

// ---- Operations ----

func (s *Server) listWorkingSets(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.WorkingSets(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) getWorkingSet(w http.ResponseWriter, r *http.Request) {
	ws, err := s.store.WorkingSet(r.Context(), chi.URLParam(r, "workingSetId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ws)
}

func (s *Server) createWorkingSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		TenantID    string   `json:"tenantId"`
		UserIDs     []string `json:"userIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "The working set request is invalid.")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Description = strings.TrimSpace(body.Description)
	body.TenantID = strings.TrimSpace(body.TenantID)
	if body.Name == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A working set name is required.")
		return
	}
	if len(body.Name) > 120 || len(body.Description) > 500 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "The working set name or description is too long.")
		return
	}
	if body.TenantID == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A working set tenant is required.")
		return
	}
	tenant, err := s.store.Tenant(r.Context(), body.TenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	userIDs := normalizeWorkingSetUserIDs(body.UserIDs)
	if len(userIDs) == 0 || len(userIDs) > 5000 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Select between 1 and 5,000 users for the working set.")
		return
	}
	user := auth.UserFromContext(r.Context())
	ws, err := s.store.CreateWorkingSet(r.Context(), store.NewWorkingSet{
		Name: body.Name, Description: body.Description, TenantID: tenant.ID, Tenant: tenant.Name,
		UserIDs: userIDs, CreatedBy: user.Name,
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "working_set.create", Resource: ws.Name, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusCreated, ws)
}

func (s *Server) updateWorkingSet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "workingSetId"))
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		UserIDs     []string `json:"userIds"`
	}
	if id == "" || json.NewDecoder(r.Body).Decode(&body) != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "The working set request is invalid.")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Description = strings.TrimSpace(body.Description)
	if body.Name == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A working set name is required.")
		return
	}
	if len(body.Name) > 120 || len(body.Description) > 500 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "The working set name or description is too long.")
		return
	}
	userIDs := normalizeWorkingSetUserIDs(body.UserIDs)
	if len(userIDs) == 0 || len(userIDs) > 5000 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Select between 1 and 5,000 users for the working set.")
		return
	}
	ws, err := s.store.UpdateWorkingSet(r.Context(), id, store.WorkingSetUpdate{
		Name: body.Name, Description: body.Description, UserIDs: userIDs,
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "working_set.update", Resource: ws.Name, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, ws)
}

func normalizeWorkingSetUserIDs(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	userIDs := make([]string, 0, len(input))
	for _, id := range input {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		userIDs = append(userIDs, id)
	}
	return userIDs
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.Jobs(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) acknowledgeJob(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	if jobID == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A job id is required.")
		return
	}
	if err := s.store.AcknowledgeJob(r.Context(), jobID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "jobs.acknowledge", Resource: jobID, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

func (s *Server) listChanges(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.Changes(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) getChange(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.Change(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

// ---- Workflow actions ----

// changeRequest is the payload for What-If preview and execute. Directory and
// site-access actions target users (userIds); Exchange actions target
// mailboxes (mailboxIds); set_site_sharing targets sites (siteIds). Group
// actions carry a groupId, license actions a skuId, site-access actions a
// siteId + role, mailbox-permission actions a delegateId + permission.
type changeRequest struct {
	ApprovalToken string   `json:"approvalToken,omitempty"`
	Action        string   `json:"action"`
	TenantID      string   `json:"tenantId"`
	GroupID       string   `json:"groupId"`
	SkuID         string   `json:"skuId"`
	UserIDs       []string `json:"userIds"`

	MailboxIDs       []string `json:"mailboxIds"`
	ForwardTo        string   `json:"forwardTo"`
	AutoReplyMessage string   `json:"autoReplyMessage"`
	Permission       string   `json:"permission"`
	DelegateID       string   `json:"delegateId"`

	SiteIDs      []string `json:"siteIds"`
	SiteID       string   `json:"siteId"`
	Role         string   `json:"role"`
	SharingLevel string   `json:"sharingLevel"`

	// ThreatLocker: device actions target devices; approval actions target
	// approval requests.
	DeviceIDs          []string `json:"deviceIds"`
	MaintenanceType    string   `json:"maintenanceType"`
	DurationMinutes    int      `json:"durationMinutes"`
	ApprovalRequestIDs []string `json:"approvalRequestIds"`
	Scope              string   `json:"scope"`
	ExpiresAt          string   `json:"expiresAt"`
	Reason             string   `json:"reason"`
}

func isGroupAction(a string) bool {
	return a == worker.ActionAddToGroup || a == worker.ActionRemoveFromGroup
}

func isLicenseAction(a string) bool {
	return a == worker.ActionAssignLicense || a == worker.ActionRemoveLicense
}

// isMailboxAction: Exchange actions whose targets are mailboxes.
func isMailboxAction(a string) bool {
	switch a {
	case worker.ActionSetForwarding, worker.ActionClearForwarding,
		worker.ActionEnableAutoReply, worker.ActionDisableAutoReply,
		worker.ActionGrantMailboxPerm, worker.ActionRevokeMailboxPerm:
		return true
	}
	return false
}

// isSiteAccessAction: SharePoint grants targeting users on one site.
func isSiteAccessAction(a string) bool {
	return a == worker.ActionGrantSiteAccess || a == worker.ActionRevokeSiteAccess
}

// isDeviceAction: ThreatLocker actions whose targets are devices.
func isDeviceAction(a string) bool {
	switch a {
	case worker.ActionEnterMaintenanceMode, worker.ActionSecureDevice,
		worker.ActionLockdownDevice, worker.ActionReleaseLockdown,
		worker.ActionIsolateDevice, worker.ActionReleaseIsolation,
		worker.ActionEnableTamper, worker.ActionDisableTamper,
		worker.ActionRestartAgent:
		return true
	}
	return false
}

// isApprovalAction: ThreatLocker actions whose targets are approval requests.
func isApprovalAction(a string) bool {
	return a == worker.ActionApproveRequest || a == worker.ActionDenyRequest
}

func isThreatLockerAction(a string) bool {
	return isDeviceAction(a) || isApprovalAction(a)
}

// targetNoun is the plural object type the action iterates over, for UI
// labels ("2 mailboxes", "3 sites", "5 users").
func targetNoun(a string) string {
	switch {
	case isMailboxAction(a):
		return "mailboxes"
	case a == worker.ActionSetSiteSharing:
		return "sites"
	case isDeviceAction(a):
		return "devices"
	case isApprovalAction(a):
		return "approval requests"
	default:
		return "users"
	}
}

func requiredPermission(a string) string {
	switch {
	case isThreatLockerAction(a):
		return "ThreatLocker API token (organization access)"
	case isGroupAction(a):
		return "GroupMember.ReadWrite.All"
	case a == worker.ActionSetForwarding, a == worker.ActionClearForwarding,
		a == worker.ActionEnableAutoReply, a == worker.ActionDisableAutoReply:
		return "MailboxSettings.ReadWrite"
	case a == worker.ActionGrantMailboxPerm, a == worker.ActionRevokeMailboxPerm:
		return "Exchange Online — Exchange.ManageAsAppV2 + Recipient Management RBAC"
	case a == worker.ActionResetPassword:
		return "User-PasswordProfile.ReadWrite.All + applicable Entra directory role"
	case a == worker.ActionRevokeSessions:
		return "User.RevokeSessions.All"
	case a == worker.ActionRevokeUserAccess:
		return "User-PasswordProfile.ReadWrite.All + UserAuthenticationMethod.ReadWrite.All + User.RevokeSessions.All + applicable Entra directory role"
	case isSiteAccessAction(a), a == worker.ActionSetSiteSharing:
		return "Sites.FullControl.All"
	default:
		return "User.ReadWrite.All"
	}
}

// changeContext is everything resolved from live tenant state that preview
// and execute share.
type changeContext struct {
	tenantName   string
	groupName    string
	groupOnPrem  bool // target group is synced from on-prem AD (group actions)
	skuName      string
	siteName     string          // site-access actions
	delegateName string          // mailbox-permission actions
	available    int             // license units still free (assign warnings)
	members      map[string]bool // current group membership (group actions)
	users        map[string]model.User
	mailboxes    map[string]model.Mailbox         // Exchange actions
	sites        map[string]model.Site            // SharePoint actions
	devices      map[string]model.Device          // ThreatLocker device actions
	requests     map[string]model.ApprovalRequest // ThreatLocker approval actions
}

// targetIDs returns the id list the action operates on (users, mailboxes, or
// sites, per the action family).
func (body *changeRequest) targetIDs() []string {
	switch {
	case isMailboxAction(body.Action):
		return body.MailboxIDs
	case body.Action == worker.ActionSetSiteSharing:
		return body.SiteIDs
	case isDeviceAction(body.Action):
		return body.DeviceIDs
	case isApprovalAction(body.Action):
		return body.ApprovalRequestIDs
	default:
		return body.UserIDs
	}
}

// resolveChange validates a change request and resolves the live state it
// needs. A non-empty errMsg is a 400; a non-nil err is a Graph/store failure.
func (s *Server) resolveChange(r *http.Request, body *changeRequest) (changeContext, string, error) {
	cc := changeContext{}
	switch body.Action {
	case worker.ActionAddToGroup, worker.ActionRemoveFromGroup,
		worker.ActionBlockSignIn, worker.ActionUnblockSignIn,
		worker.ActionAssignLicense, worker.ActionRemoveLicense,
		worker.ActionRevokeSessions, worker.ActionResetPassword, worker.ActionRevokeUserAccess,
		worker.ActionSetForwarding, worker.ActionClearForwarding,
		worker.ActionEnableAutoReply, worker.ActionDisableAutoReply,
		worker.ActionGrantMailboxPerm, worker.ActionRevokeMailboxPerm,
		worker.ActionGrantSiteAccess, worker.ActionRevokeSiteAccess,
		worker.ActionSetSiteSharing,
		worker.ActionEnterMaintenanceMode, worker.ActionSecureDevice,
		worker.ActionLockdownDevice, worker.ActionReleaseLockdown,
		worker.ActionIsolateDevice, worker.ActionReleaseIsolation,
		worker.ActionEnableTamper, worker.ActionDisableTamper,
		worker.ActionRestartAgent,
		worker.ActionApproveRequest, worker.ActionDenyRequest:
	default:
		return cc, "Unsupported action.", nil
	}
	if len(body.targetIDs()) == 0 || (body.TenantID == "" && !isThreatLockerAction(body.Action)) {
		switch {
		case isMailboxAction(body.Action):
			return cc, "tenantId and at least one mailbox are required.", nil
		case body.Action == worker.ActionSetSiteSharing:
			return cc, "tenantId and at least one site are required.", nil
		case isDeviceAction(body.Action):
			return cc, "At least one device is required.", nil
		case isApprovalAction(body.Action):
			return cc, "At least one approval request is required.", nil
		default:
			return cc, "tenantId and at least one user are required.", nil
		}
	}
	if (body.Action == worker.ActionResetPassword || body.Action == worker.ActionRevokeUserAccess) && len(body.UserIDs) > 10 {
		return cc, "Password-bearing actions are limited to 10 users at a time so one-time credentials can be returned safely.", nil
	}
	// ThreatLocker actions resolve against live device / approval-request
	// state and need nothing from Graph.
	if isThreatLockerAction(body.Action) {
		cc.tenantName = "ThreatLocker MSP workspace"
		errMsg, err := s.resolveThreatLocker(r, body, &cc)
		return cc, errMsg, err
	}

	t, err := s.store.Tenant(r.Context(), body.TenantID)
	if err != nil {
		return cc, "Unknown tenant.", nil
	}
	cc.tenantName = t.Name

	// Users are the target set for directory + site-access actions and the
	// delegate lookup for mailbox-permission actions.
	if !isMailboxAction(body.Action) && body.Action != worker.ActionSetSiteSharing ||
		body.Action == worker.ActionGrantMailboxPerm || body.Action == worker.ActionRevokeMailboxPerm {
		users, err := s.graph.Users(r.Context(), body.TenantID)
		if err != nil {
			return cc, "", err
		}
		cc.users = make(map[string]model.User, len(users))
		for _, u := range users {
			cc.users[u.ID] = u
		}
	}

	if isMailboxAction(body.Action) {
		switch body.Action {
		case worker.ActionSetForwarding:
			if !strings.Contains(body.ForwardTo, "@") {
				return cc, "A valid forwarding email address is required.", nil
			}
		case worker.ActionEnableAutoReply:
			if strings.TrimSpace(body.AutoReplyMessage) == "" {
				return cc, "An auto-reply message is required.", nil
			}
		case worker.ActionGrantMailboxPerm, worker.ActionRevokeMailboxPerm:
			switch body.Permission {
			case graph.MailboxPermFullAccess, graph.MailboxPermSendAs, graph.MailboxPermSendOnBehalf:
			default:
				return cc, "Permission must be Full Access, Send As, or Send on Behalf.", nil
			}
			d, known := cc.users[body.DelegateID]
			if !known {
				return cc, "Unknown delegate user for this tenant.", nil
			}
			cc.delegateName = d.Name
		}
		boxes, err := s.graph.Mailboxes(r.Context(), body.TenantID)
		if err != nil {
			return cc, "", err
		}
		cc.mailboxes = make(map[string]model.Mailbox, len(boxes))
		for _, m := range boxes {
			cc.mailboxes[m.ID] = m
		}
	}

	if isSiteAccessAction(body.Action) || body.Action == worker.ActionSetSiteSharing {
		if isSiteAccessAction(body.Action) {
			if body.SiteID == "" {
				return cc, "A siteId is required for site access actions.", nil
			}
			switch body.Role {
			case graph.SiteRoleRead, graph.SiteRoleEdit, graph.SiteRoleFullControl:
			default:
				return cc, "Role must be Read, Edit, or Full Control.", nil
			}
		} else {
			switch body.SharingLevel {
			case graph.SharingInternal, graph.SharingExternal, graph.SharingAnyone:
			default:
				return cc, "Sharing level must be Internal, External, or Anyone.", nil
			}
		}
		sites, err := s.graph.Sites(r.Context(), body.TenantID)
		if err != nil {
			return cc, "", err
		}
		cc.sites = make(map[string]model.Site, len(sites))
		for _, st := range sites {
			cc.sites[st.ID] = st
		}
		if isSiteAccessAction(body.Action) {
			st, known := cc.sites[body.SiteID]
			if !known {
				return cc, "Unknown site for this tenant.", nil
			}
			cc.siteName = st.Name
		}
	}

	if isGroupAction(body.Action) {
		if body.GroupID == "" {
			return cc, "A groupId is required for group actions.", nil
		}
		groups, err := s.graph.Groups(r.Context(), body.TenantID)
		if err != nil {
			return cc, "", err
		}
		for _, g := range groups {
			if g.ID == body.GroupID {
				cc.groupName = g.Name
				cc.groupOnPrem = g.Source == "On-prem sync"
			}
		}
		if cc.groupName == "" {
			return cc, "Unknown group for this tenant.", nil
		}
		current, err := s.graph.GroupMembers(r.Context(), body.TenantID, body.GroupID)
		if err != nil {
			return cc, "", err
		}
		cc.members = make(map[string]bool, len(current))
		for _, m := range current {
			cc.members[m.ID] = true
		}
	}

	if isLicenseAction(body.Action) {
		if body.SkuID == "" {
			return cc, "A skuId is required for license actions.", nil
		}
		licenses, err := s.graph.Licenses(r.Context(), body.TenantID)
		if err != nil {
			return cc, "", err
		}
		for _, l := range licenses {
			if l.SkuID == body.SkuID {
				cc.skuName = l.Product
				cc.available = l.Available
			}
		}
		if cc.skuName == "" {
			return cc, "Unknown license SKU for this tenant.", nil
		}
	}
	return cc, "", nil
}

// planTarget is one object an action will really touch: the id the worker
// operates on plus the name/detail shown in the preview rows.
type planTarget struct {
	id     string
	name   string
	detail string
}

// planTargets splits the requested targets (users, mailboxes, or sites) into
// real targets, skips (no-ops), and blocks (refused because the object is
// mastered on-prem AD), based on current tenant state. Blocks are never
// executed — the write gate fails closed on synced objects.
func planTargets(body *changeRequest, cc changeContext) (targets []planTarget, skipped []model.WhatIfSkip, blocked []model.WhatIfBlock) {
	action := body.Action
	// Group membership is mastered on-prem for a synced group: every add/remove
	// against it is refused regardless of which user is targeted.
	groupBlocked := isGroupAction(action) && cc.groupOnPrem
	for _, id := range body.targetIDs() {
		switch {
		case isDeviceAction(action):
			d, known := cc.devices[id]
			switch {
			case !known:
				skipped = append(skipped, model.WhatIfSkip{Object: id, Reason: "Device not found in this tenant"})
			case action == worker.ActionSecureDevice && d.Mode == threatlocker.ModeSecured:
				skipped = append(skipped, model.WhatIfSkip{Object: d.Hostname, Reason: "Already secured"})
			case action == worker.ActionEnterMaintenanceMode && d.Mode == threatlocker.ModeForMaintenance(body.MaintenanceType):
				skipped = append(skipped, model.WhatIfSkip{Object: d.Hostname, Reason: "Already in this maintenance mode"})
			case action == worker.ActionLockdownDevice && d.Mode == threatlocker.ModeLockdown:
				skipped = append(skipped, model.WhatIfSkip{Object: d.Hostname, Reason: "Already locked down"})
			case action == worker.ActionReleaseLockdown && d.Mode != threatlocker.ModeLockdown:
				skipped = append(skipped, model.WhatIfSkip{Object: d.Hostname, Reason: "Not locked down"})
			case action == worker.ActionIsolateDevice && d.Mode == threatlocker.ModeIsolated:
				skipped = append(skipped, model.WhatIfSkip{Object: d.Hostname, Reason: "Already isolated"})
			case action == worker.ActionReleaseIsolation && d.Mode != threatlocker.ModeIsolated:
				skipped = append(skipped, model.WhatIfSkip{Object: d.Hostname, Reason: "Not isolated"})
			case action == worker.ActionEnableTamper && d.TamperProtection:
				skipped = append(skipped, model.WhatIfSkip{Object: d.Hostname, Reason: "Tamper protection is already enabled"})
			case action == worker.ActionDisableTamper && !d.TamperProtection:
				skipped = append(skipped, model.WhatIfSkip{Object: d.Hostname, Reason: "Tamper protection is already disabled"})
			default:
				targets = append(targets, planTarget{id: d.ID, name: d.Hostname, detail: d.Group})
			}
		case isApprovalAction(action):
			q, known := cc.requests[id]
			switch {
			case !known:
				skipped = append(skipped, model.WhatIfSkip{Object: id, Reason: "Approval request not found in this tenant"})
			case q.Status != threatlocker.RequestPending:
				skipped = append(skipped, model.WhatIfSkip{Object: q.Application, Reason: "Request is no longer pending"})
			default:
				targets = append(targets, planTarget{id: q.ID, name: q.Application, detail: q.DeviceName + " · " + q.Requester})
			}
		case isMailboxAction(action):
			m, known := cc.mailboxes[id]
			if !known {
				skipped = append(skipped, model.WhatIfSkip{Object: id, Reason: "Mailbox not found in this tenant"})
				continue
			}
			targets = append(targets, planTarget{id: m.ID, name: m.Name, detail: m.Email})
		case action == worker.ActionSetSiteSharing:
			st, known := cc.sites[id]
			switch {
			case !known:
				skipped = append(skipped, model.WhatIfSkip{Object: id, Reason: "Site not found in this tenant"})
			case st.ExternalSharing == body.SharingLevel:
				skipped = append(skipped, model.WhatIfSkip{Object: st.Name, Reason: "Already at this sharing level"})
			default:
				targets = append(targets, planTarget{id: st.ID, name: st.Name, detail: st.URL})
			}
		default:
			u, known := cc.users[id]
			switch {
			case !known:
				skipped = append(skipped, model.WhatIfSkip{Object: id, Reason: "User not found in this tenant"})
			case groupBlocked:
				blocked = append(blocked, model.WhatIfBlock{
					Object:     u.Name,
					Reason:     fmt.Sprintf("“%s” is synced from on-prem AD — its membership is mastered in Active Directory.", cc.groupName),
					Resolution: onPremResolution,
				})
			case blockUserDirectory(action) && userOnPrem(u):
				blocked = append(blocked, model.WhatIfBlock{
					Object:     u.Name,
					Reason:     "This user is synced from on-prem AD — sign-in state is mastered in Active Directory.",
					Resolution: onPremResolution,
				})
			case action == worker.ActionAddToGroup && cc.members[id]:
				skipped = append(skipped, model.WhatIfSkip{Object: u.Name, Reason: "Already a member"})
			case action == worker.ActionRemoveFromGroup && !cc.members[id]:
				skipped = append(skipped, model.WhatIfSkip{Object: u.Name, Reason: "Not a member of this group"})
			case action == worker.ActionBlockSignIn && u.Status == "Disabled":
				skipped = append(skipped, model.WhatIfSkip{Object: u.Name, Reason: "Sign-in is already blocked"})
			case action == worker.ActionUnblockSignIn && u.Status != "Disabled":
				skipped = append(skipped, model.WhatIfSkip{Object: u.Name, Reason: "Sign-in is not blocked"})
			default:
				targets = append(targets, planTarget{id: u.ID, name: u.Name, detail: u.UPN})
			}
		}
	}
	return targets, skipped, blocked
}

// previewTitle renders the What-If headline for an action.
func previewTitle(body *changeRequest, cc changeContext, n int) string {
	switch body.Action {
	case worker.ActionAddToGroup:
		return fmt.Sprintf("Add %d members to “%s”", n, cc.groupName)
	case worker.ActionRemoveFromGroup:
		return fmt.Sprintf("Remove %d members from “%s”", n, cc.groupName)
	case worker.ActionBlockSignIn:
		return fmt.Sprintf("Block sign-in for %d users", n)
	case worker.ActionUnblockSignIn:
		return fmt.Sprintf("Unblock sign-in for %d users", n)
	case worker.ActionAssignLicense:
		return fmt.Sprintf("Assign %s to %d users", cc.skuName, n)
	case worker.ActionRemoveLicense:
		return fmt.Sprintf("Remove %s from %d users", cc.skuName, n)
	case worker.ActionResetPassword:
		return fmt.Sprintf("Reset passwords for %d users", n)
	case worker.ActionRevokeUserAccess:
		return fmt.Sprintf("Contain %d compromised user account(s)", n)
	case worker.ActionSetForwarding:
		return fmt.Sprintf("Forward %d mailbox(es) to %s", n, body.ForwardTo)
	case worker.ActionClearForwarding:
		return fmt.Sprintf("Clear forwarding on %d mailbox(es)", n)
	case worker.ActionEnableAutoReply:
		return fmt.Sprintf("Enable auto-reply on %d mailbox(es)", n)
	case worker.ActionDisableAutoReply:
		return fmt.Sprintf("Disable auto-reply on %d mailbox(es)", n)
	case worker.ActionGrantMailboxPerm:
		return fmt.Sprintf("Grant %s to %s on %d mailbox(es)", body.Permission, cc.delegateName, n)
	case worker.ActionRevokeMailboxPerm:
		return fmt.Sprintf("Revoke %s from %s on %d mailbox(es)", body.Permission, cc.delegateName, n)
	case worker.ActionGrantSiteAccess:
		return fmt.Sprintf("Grant %s on “%s” to %d users", body.Role, cc.siteName, n)
	case worker.ActionRevokeSiteAccess:
		return fmt.Sprintf("Revoke %s on “%s” from %d users", body.Role, cc.siteName, n)
	case worker.ActionSetSiteSharing:
		return fmt.Sprintf("Set external sharing to %s on %d site(s)", body.SharingLevel, n)
	case worker.ActionEnterMaintenanceMode:
		return fmt.Sprintf("Enter %s maintenance on %d device(s)", body.MaintenanceType, n)
	case worker.ActionSecureDevice:
		return fmt.Sprintf("Secure %d device(s)", n)
	case worker.ActionLockdownDevice:
		return fmt.Sprintf("Lock down %d device(s)", n)
	case worker.ActionReleaseLockdown:
		return fmt.Sprintf("Release lockdown on %d device(s)", n)
	case worker.ActionIsolateDevice:
		return fmt.Sprintf("Isolate %d device(s)", n)
	case worker.ActionReleaseIsolation:
		return fmt.Sprintf("Release isolation on %d device(s)", n)
	case worker.ActionEnableTamper:
		return fmt.Sprintf("Enable tamper protection on %d device(s)", n)
	case worker.ActionDisableTamper:
		return fmt.Sprintf("Disable tamper protection on %d device(s)", n)
	case worker.ActionRestartAgent:
		return fmt.Sprintf("Restart the ThreatLocker agent on %d device(s)", n)
	case worker.ActionApproveRequest:
		return fmt.Sprintf("Approve %d application request(s) at %s scope", n, body.Scope)
	case worker.ActionDenyRequest:
		return fmt.Sprintf("Deny %d application request(s)", n)
	default: // revoke_sessions
		return fmt.Sprintf("Revoke sessions for %d users", n)
	}
}

// changeLabel is the per-row badge in the preview's expected-changes list.
func changeLabel(action string) string {
	switch action {
	case worker.ActionAddToGroup:
		return "Add as Member"
	case worker.ActionRemoveFromGroup:
		return "Remove as Member"
	case worker.ActionBlockSignIn:
		return "Block sign-in"
	case worker.ActionUnblockSignIn:
		return "Unblock sign-in"
	case worker.ActionAssignLicense:
		return "Assign license"
	case worker.ActionRemoveLicense:
		return "Remove license"
	case worker.ActionResetPassword:
		return "Reset password"
	case worker.ActionRevokeUserAccess:
		return "Reset password + MFA + sessions"
	case worker.ActionSetForwarding:
		return "Set forwarding"
	case worker.ActionClearForwarding:
		return "Clear forwarding"
	case worker.ActionEnableAutoReply:
		return "Enable auto-reply"
	case worker.ActionDisableAutoReply:
		return "Disable auto-reply"
	case worker.ActionGrantMailboxPerm:
		return "Grant permission"
	case worker.ActionRevokeMailboxPerm:
		return "Revoke permission"
	case worker.ActionGrantSiteAccess:
		return "Grant site access"
	case worker.ActionRevokeSiteAccess:
		return "Revoke site access"
	case worker.ActionSetSiteSharing:
		return "Change sharing level"
	case worker.ActionEnterMaintenanceMode:
		return "Enter maintenance"
	case worker.ActionSecureDevice:
		return "Secure device"
	case worker.ActionLockdownDevice:
		return "Lock down"
	case worker.ActionReleaseLockdown:
		return "Release lockdown"
	case worker.ActionIsolateDevice:
		return "Isolate"
	case worker.ActionReleaseIsolation:
		return "Release isolation"
	case worker.ActionEnableTamper:
		return "Enable tamper protection"
	case worker.ActionDisableTamper:
		return "Disable tamper protection"
	case worker.ActionRestartAgent:
		return "Restart agent"
	case worker.ActionApproveRequest:
		return "Approve request"
	case worker.ActionDenyRequest:
		return "Deny request"
	default:
		return "Revoke sessions"
	}
}

// riskFor sizes the risk from the action's blast radius. Destructive or
// exposure-widening actions (blocking people out, killing sessions, mail
// forwarding, opening external sharing, granting Full Access / Full Control)
// start at Medium.
func riskFor(action string, n int, body *changeRequest) string {
	destructive := action == worker.ActionBlockSignIn || action == worker.ActionRevokeSessions ||
		action == worker.ActionResetPassword || action == worker.ActionRevokeUserAccess ||
		action == worker.ActionRemoveLicense ||
		action == worker.ActionSetForwarding || // mail exfiltration path — treat with care
		(action == worker.ActionSetSiteSharing && body.SharingLevel != graph.SharingInternal) ||
		(action == worker.ActionGrantMailboxPerm && body.Permission == graph.MailboxPermFullAccess) ||
		(action == worker.ActionGrantSiteAccess && body.Role == graph.SiteRoleFullControl) ||
		// Cutting devices off (lockdown/isolation) or reducing protection.
		action == worker.ActionLockdownDevice || action == worker.ActionIsolateDevice ||
		action == worker.ActionDisableTamper ||
		(action == worker.ActionEnterMaintenanceMode && body.MaintenanceType == threatlocker.MaintenanceDisableProtection) ||
		(action == worker.ActionApproveRequest && body.Scope == threatlocker.ScopeOrganization)
	switch {
	case n >= 25 || (destructive && n >= 10):
		return "High"
	case n >= 5 || destructive:
		return "Medium"
	default:
		return "Low"
	}
}

// previewChange computes the What-If preview from live tenant state: which
// users the action would really touch, which are skipped, and why.
func (s *Server) previewChange(w http.ResponseWriter, r *http.Request) {
	var body changeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	cc, errMsg, err := s.resolveChange(r, &body)
	if errMsg != "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, errMsg)
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}

	targets, skipped, blocked := planTargets(&body, cc)
	preview := model.WhatIfPreview{
		Action:             previewTitle(&body, cc, len(targets)),
		Tenant:             cc.tenantName,
		Risk:               riskFor(body.Action, len(targets), &body),
		RequiredPermission: requiredPermission(body.Action),
		TargetCount:        len(targets),
		TargetNoun:         targetNoun(body.Action),
		Warnings:           []string{},
		Skipped:            skipped,
		Blocked:            blocked,
		Changes:            []model.WhatIfChange{},
	}
	if preview.Skipped == nil {
		preview.Skipped = []model.WhatIfSkip{}
	}
	if preview.Blocked == nil {
		preview.Blocked = []model.WhatIfBlock{}
	}
	for i, t := range targets {
		if i < 5 {
			preview.Changes = append(preview.Changes, model.WhatIfChange{Object: t.name, Detail: t.detail, Change: changeLabel(body.Action)})
		} else {
			preview.MoreCount++
		}
	}

	switch body.Action {
	case worker.ActionAssignLicense:
		if cc.available < len(targets) {
			preview.Warnings = append(preview.Warnings,
				fmt.Sprintf("Only %d %s license(s) available for %d assignment(s) — Microsoft will reject the overflow.", cc.available, cc.skuName, len(targets)))
		}
		preview.Warnings = append(preview.Warnings,
			"Users without a usage location set in Microsoft 365 will fail individually.")
	case worker.ActionRemoveLicense:
		preview.Warnings = append(preview.Warnings, "Users who do not hold this license fail individually and are otherwise unaffected.")
	case worker.ActionBlockSignIn:
		preview.Warnings = append(preview.Warnings, "Blocked users cannot sign in to any Microsoft 365 service until unblocked.")
	case worker.ActionRevokeSessions:
		preview.Warnings = append(preview.Warnings, "This cannot be reverted — users must sign in again on every device.")
	case worker.ActionResetPassword:
		preview.Warnings = append(preview.Warnings,
			"This cannot be reverted. A random one-time password is shown only after execution and must be changed at the next sign-in.")
		preview.Warnings = append(preview.Warnings,
			"Synced or federated identities can be rejected by Microsoft; those failures are reported per user without exposing the generated password.")
	case worker.ActionRevokeUserAccess:
		preview.Warnings = append(preview.Warnings,
			"Compromised-account containment resets the password, removes registered authentication methods, and revokes sign-in sessions. It cannot be reverted.")
		preview.Warnings = append(preview.Warnings,
			"Users must receive the one-time password and register MFA again before normal access can resume. Microsoft can take several minutes to invalidate every session.")
	case worker.ActionSetForwarding:
		preview.Warnings = append(preview.Warnings,
			fmt.Sprintf("All new mail arriving in these mailboxes will be forwarded to %s.", body.ForwardTo))
		preview.Warnings = append(preview.Warnings,
			"Verify the forwarding address — forwarding to an external mailbox can exfiltrate mail.")
	case worker.ActionClearForwarding:
		preview.Warnings = append(preview.Warnings,
			"The previous forwarding address is not snapshotted — this cannot be reverted automatically.")
	case worker.ActionDisableAutoReply:
		preview.Warnings = append(preview.Warnings,
			"The previous auto-reply message is not snapshotted — this cannot be reverted automatically.")
	case worker.ActionGrantMailboxPerm:
		if body.Permission == graph.MailboxPermFullAccess {
			preview.Warnings = append(preview.Warnings,
				fmt.Sprintf("%s will be able to open these mailboxes and read all content.", cc.delegateName))
		}
	case worker.ActionGrantSiteAccess:
		if body.Role == graph.SiteRoleFullControl {
			preview.Warnings = append(preview.Warnings, "Full Control includes permission management on the site.")
		}
	case worker.ActionSetSiteSharing:
		switch body.SharingLevel {
		case graph.SharingAnyone:
			preview.Warnings = append(preview.Warnings,
				"“Anyone” enables anonymous sharing links — content can be accessed without signing in.")
		case graph.SharingExternal:
			preview.Warnings = append(preview.Warnings, "External guests will be able to access shared content on these sites.")
		}
		preview.Warnings = append(preview.Warnings,
			"The previous sharing level is not snapshotted — this cannot be reverted automatically.")
	case worker.ActionEnterMaintenanceMode:
		preview.Warnings = append(preview.Warnings,
			fmt.Sprintf("Protection is reduced while these devices are in %s maintenance (ends after %d minutes).", body.MaintenanceType, body.DurationMinutes))
		if body.MaintenanceType == threatlocker.MaintenanceDisableProtection {
			preview.Warnings = append(preview.Warnings,
				"Disable Protection turns ThreatLocker enforcement off entirely — the highest-risk maintenance state.")
		}
	case worker.ActionSecureDevice:
		preview.Warnings = append(preview.Warnings,
			"The previous mode and its scheduled end are not snapshotted — this cannot be reverted automatically.")
	case worker.ActionLockdownDevice:
		preview.Warnings = append(preview.Warnings,
			"Locked-down devices can only communicate with ThreatLocker — users cannot run anything until the lockdown is released.")
	case worker.ActionReleaseLockdown, worker.ActionReleaseIsolation:
		preview.Warnings = append(preview.Warnings,
			"Releasing clears the device's active alerts in ThreatLocker.")
	case worker.ActionIsolateDevice:
		preview.Warnings = append(preview.Warnings,
			"Isolated devices lose all network access except to ThreatLocker until the isolation is released.")
	case worker.ActionDisableTamper:
		preview.Warnings = append(preview.Warnings,
			"With tamper protection off, the ThreatLocker agent can be modified or removed locally.")
	case worker.ActionRestartAgent:
		preview.Warnings = append(preview.Warnings, "This cannot be reverted — the agent service restarts on each device.")
	case worker.ActionApproveRequest:
		preview.Warnings = append(preview.Warnings,
			fmt.Sprintf("Approving creates a ThreatLocker permit policy at %s scope — it cannot be reverted from RTM (manage the policy in ThreatLocker).", body.Scope))
		if body.ExpiresAt != "" {
			preview.Warnings = append(preview.Warnings, "The permit is temporary and expires at "+body.ExpiresAt+".")
		}
	case worker.ActionDenyRequest:
		preview.Warnings = append(preview.Warnings, "This cannot be reverted — the requester must submit a new request.")
	}
	if isDeviceAction(body.Action) {
		offline := 0
		for _, t := range targets {
			if d, ok := cc.devices[t.id]; ok && !d.Online {
				offline++
			}
		}
		if offline > 0 {
			preview.Warnings = append(preview.Warnings,
				fmt.Sprintf("%d device(s) are offline — the change applies when they next check in.", offline))
		}
	}
	if n := len(skipped); n > 0 {
		noun := "targets are"
		if n == 1 {
			noun = "target is"
		}
		preview.Warnings = append(preview.Warnings, fmt.Sprintf("%d %s skipped and will not be changed.", n, noun))
	}
	if n := len(blocked); n > 0 {
		noun := "targets are"
		if n == 1 {
			noun = "target is"
		}
		preview.Warnings = append(preview.Warnings,
			fmt.Sprintf("%d %s mastered by on-prem Active Directory and cannot be changed from RTM — make the change in on-prem AD.", n, noun))
		if body.Action == worker.ActionBlockSignIn {
			preview.Warnings = append(preview.Warnings,
				"To stop cloud access for synced users immediately without editing on-prem AD, revoke their sessions instead.")
		}
	}
	if len(targets) == 0 {
		preview.Warnings = append(preview.Warnings, "Nothing to do — no changes would be applied.")
	}
	preview.ApprovalToken = s.issueChangeApproval(r, body)
	httpx.WriteJSON(w, http.StatusOK, preview)
}

// executeChange queues the real write as a job (asynchronous per the API
// spec); the worker performs the Graph mutations and records the change.
func (s *Server) executeChange(w http.ResponseWriter, r *http.Request) {
	var body changeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if !s.consumeChangeApproval(w, r, body) {
		return
	}
	cc, errMsg, err := s.resolveChange(r, &body)
	if errMsg != "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, errMsg)
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	// Execute exactly what the preview showed: skips and on-prem blocks are
	// filtered here too, so a synced object can never reach the job queue.
	targets, _, blocked := planTargets(&body, cc)
	if len(blocked) > 0 {
		// Fail closed AND leave an audit trail: the attempt to change an
		// on-prem-mastered object is recorded as denied (framework §9), whether
		// or not any cloud-writable targets remain.
		user := auth.UserFromContext(r.Context())
		_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
			Actor:  user.Name,
			Action: "changes.blocked",
			Resource: fmt.Sprintf("%s — %s blocked %d on-prem-mastered target(s)",
				cc.tenantName, body.Action, len(blocked)),
			Result:        "Denied",
			CorrelationID: httpx.CorrelationID(r.Context()),
		})
	}
	if len(targets) == 0 {
		msg := "Nothing to do — every selected target is skipped for this action."
		if len(blocked) > 0 {
			msg = "Nothing to do — every selected target is either skipped or mastered by on-prem Active Directory. Make on-prem changes in Active Directory."
		}
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, msg)
		return
	}
	ids := make([]string, len(targets))
	for i, t := range targets {
		ids[i] = t.id
	}
	if body.Action == worker.ActionResetPassword || body.Action == worker.ActionRevokeUserAccess {
		s.executeSensitiveUserAction(w, r, body, cc, targets)
		return
	}
	user := auth.UserFromContext(r.Context())
	s.enqueueWrite(w, r, worker.JobType(body.Action, false), "changes.execute", cc.tenantName, worker.Payload{
		Action: body.Action, TenantID: body.TenantID, TenantName: cc.tenantName,
		GroupID: body.GroupID, GroupName: cc.groupName,
		SkuID: body.SkuID, SkuName: cc.skuName,
		UserIDs: ids, Technician: user.Name,
		ForwardTo: body.ForwardTo, AutoReplyMessage: body.AutoReplyMessage,
		Permission: body.Permission, DelegateID: body.DelegateID, DelegateName: cc.delegateName,
		SiteID: body.SiteID, SiteName: cc.siteName, Role: body.Role, SharingLevel: body.SharingLevel,
		MaintenanceType: body.MaintenanceType, DurationMinutes: body.DurationMinutes,
		Scope: body.Scope, ExpiresAt: body.ExpiresAt, Reason: body.Reason,
	})
}

// revertChange queues the stored revert payload of an earlier change.
func (s *Server) revertChange(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A change id is required.")
		return
	}
	detail, err := s.store.Change(r.Context(), body.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if !detail.RevertEligible || detail.RevertPayload == "" {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeRevertConflict, "This change does not support revert.")
		return
	}
	if detail.Revert == "Reverted" {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeRevertConflict, "This change has already been reverted.")
		return
	}
	var payload worker.Payload
	if err := json.Unmarshal([]byte(detail.RevertPayload), &payload); err != nil {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeRevertConflict, "The revert snapshot is unreadable.")
		return
	}
	user := auth.UserFromContext(r.Context())
	payload.Technician = user.Name
	payload.RevertOf = detail.ID
	s.enqueueWrite(w, r, worker.JobType(payload.Action, true), "changes.revert", payload.TenantName, payload)
}

// enqueueWrite records a queued job, audits it, and hands the payload to the
// job system (River in Postgres deployments, inline executor in memory mode).
func (s *Server) enqueueWrite(w http.ResponseWriter, r *http.Request, jobType, action, tenantName string, payload worker.Payload) {
	user := auth.UserFromContext(r.Context())
	job, err := s.store.CreateJob(r.Context(), model.Job{
		Type: jobType, Tenant: tenantName, Status: "Queued", Progress: 0,
		Started: time.Now().Format("15:04"), Duration: "—", TriggeredBy: user.Name,
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: action, Resource: tenantName, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	if err := s.jobs.Enqueue(r.Context(), jobType, job.ID, string(raw)); err != nil {
		s.log.Error("enqueue", "error", err, "job", job.ID)
		_ = s.store.CompleteJob(r.Context(), job.ID, "Failed", "—")
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.CodeChangeFailed, "The change could not be queued.")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, model.JobRef{JobID: job.ID, Status: "queued"})
}

// ---- Governance / Admin ----

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.Audit(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) adminTechnicians(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.Technicians(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

// createTechnician invites a new operator: a real login account with a
// one-time temp password (returned exactly once) and forced rotation.
func (s *Server) createTechnician(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	if body.Name == "" || body.Email == "" || !strings.Contains(body.Email, "@") {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A name and a valid email are required.")
		return
	}
	if body.Role == "" {
		body.Role = seed.RoleTechnician
	}
	if body.Role != seed.RoleAdmin && body.Role != seed.RoleTechnician {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Role must be Admin or Technician.")
		return
	}
	temp := auth.TempPassword()
	hash, err := auth.HashPassword(temp)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	acct, err := s.store.CreateAccount(r.Context(), store.NewAccount{
		Name: body.Name, Email: body.Email, Role: body.Role, IsAdmin: body.Role == seed.RoleAdmin,
		PasswordHash: hash, MustChange: true,
	})
	if errors.Is(err, store.ErrConflict) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "An account with this email already exists.")
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "technician.create", Resource: acct.Email, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"technician": model.Technician{
			ID: acct.ID, Name: acct.Name, Email: acct.Email, Role: acct.Role,
			Tenants: "All", Status: acct.Status, LastActive: "—", MustChangePassword: true,
		},
		// Shown once so the admin can hand it over; first login forces rotation.
		"tempPassword": temp,
	})
}

func (s *Server) updateTechnician(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user := auth.UserFromContext(r.Context())
	if id == user.ID {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "You cannot modify your own account.")
		return
	}
	var body struct {
		Role   *string `json:"role"`
		Status *string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	// isAdmin is derived from the role — Admin and Technician are the only two.
	var isAdmin *bool
	if body.Role != nil {
		if *body.Role != seed.RoleAdmin && *body.Role != seed.RoleTechnician {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Role must be Admin or Technician.")
			return
		}
		admin := *body.Role == seed.RoleAdmin
		isAdmin = &admin
	}
	if err := s.store.UpdateAccount(r.Context(), id, store.AccountUpdate{Role: body.Role, Status: body.Status, IsAdmin: isAdmin}); err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "technician.update", Resource: id, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// resetTechnicianPassword replaces another local RTM account's credential
// with a one-time random password. The store atomically marks it for forced
// rotation and revokes every previously issued session.
func (s *Server) resetTechnicianPassword(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user := auth.UserFromContext(r.Context())
	if id == user.ID {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Use Change password in your account menu to update your own password.")
		return
	}
	acct, err := s.store.AccountByID(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	temp := auth.TempPassword()
	hash, err := auth.HashPassword(temp)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := s.store.ResetPassword(r.Context(), id, hash); err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "technician.password.reset", Resource: acct.Email, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"status": "reset", "tempPassword": temp,
	})
}

func (s *Server) deleteTechnician(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user := auth.UserFromContext(r.Context())
	if id == user.ID {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "You cannot delete your own account.")
		return
	}
	acct, err := s.store.AccountByID(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := s.store.DeleteAccount(r.Context(), id); err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "technician.delete", Resource: acct.Email, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// updateSetting persists a platform toggle or the bounded session-timeout
// value. Locked settings are structural guarantees and cannot be changed.
func (s *Server) updateSetting(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	var body struct {
		Enabled *bool   `json:"enabled"`
		Value   *string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	settings, err := s.store.AppSettings(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var current *model.AppSetting
	for i := range settings {
		if settings[i].Key == key {
			current = &settings[i]
		}
		if settings[i].Key == key && settings[i].Locked {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "This setting is locked by policy.")
			return
		}
	}
	if current == nil {
		s.writeErr(w, r, store.ErrNotFound)
		return
	}
	resource := key
	if key == auth.SessionTimeoutSettingKey {
		if body.Value == nil {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Select a session timeout.")
			return
		}
		if _, ok := auth.SessionTimeoutDuration(*body.Value); !ok {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Session timeout must be 30 minutes, 1 hour, 4 hours, 8 hours, 12 hours, or 24 hours.")
			return
		}
		if err := s.store.UpdateAppSettingValue(r.Context(), key, *body.Value); err != nil {
			s.writeErr(w, r, err)
			return
		}
		resource += "=" + *body.Value + "_minutes"
	} else if body.Enabled == nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "The enabled value is required.")
		return
	} else if err := s.store.UpdateAppSetting(r.Context(), key, *body.Enabled); err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "settings.update", Resource: resource, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) adminRoles(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.Roles(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	decorateRoles(v)
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name != seed.RoleAdmin && name != seed.RoleTechnician {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Role must be Admin or Technician.")
		return
	}
	var body struct {
		Description    string   `json:"description"`
		PermissionKeys []string `json:"permissionKeys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	body.Description = strings.TrimSpace(body.Description)
	if len(body.Description) < 10 || len(body.Description) > 500 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Role description must be between 10 and 500 characters.")
		return
	}
	permissions, ok := normalizeRolePermissions(body.PermissionKeys)
	if !ok {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "The role contains an unsupported permission.")
		return
	}
	if name == seed.RoleAdmin && len(permissions) != len(seed.ElevatedPermissions) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Admin must retain every elevated capability.")
		return
	}
	if err := s.store.UpdateRole(r.Context(), name, body.Description, permissions); err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "role.update", Resource: name, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	role, err := s.store.Role(r.Context(), name)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	roles := []model.Role{role}
	decorateRoles(roles)
	httpx.WriteJSON(w, http.StatusOK, roles[0])
}

func normalizeRolePermissions(requested []string) ([]string, bool) {
	wanted := make(map[string]bool, len(requested))
	for _, permission := range requested {
		wanted[permission] = true
	}
	normalized := make([]string, 0, len(wanted))
	for _, permission := range seed.ElevatedPermissions {
		if wanted[permission] {
			normalized = append(normalized, permission)
			delete(wanted, permission)
		}
	}
	return normalized, len(wanted) == 0
}

func decorateRoles(roles []model.Role) {
	for i := range roles {
		count := len(roles[i].PermissionKeys)
		switch {
		case count == len(seed.ElevatedPermissions):
			roles[i].Permissions = "All permissions"
			roles[i].Level = "Privileged"
			roles[i].LevelTone = "danger"
		case count == 0:
			roles[i].Permissions = "Read across all tenants"
			roles[i].Level = "Read"
			roles[i].LevelTone = "warning"
		case count == 1:
			roles[i].Permissions = "1 elevated capability"
			roles[i].Level = "Custom"
			roles[i].LevelTone = "info"
		default:
			roles[i].Permissions = fmt.Sprintf("%d elevated capabilities", count)
			roles[i].Level = "Custom"
			roles[i].LevelTone = "info"
		}
		if roles[i].Name == seed.RoleAdmin {
			roles[i].LockedPermissionKeys = append([]string(nil), seed.ElevatedPermissions...)
		}
	}
}

func (s *Server) adminSettings(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.AppSettings(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

// dashboardStats is computed from real platform state on every request.
func (s *Server) dashboardStats(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.store.Tenants(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	jobs, err := s.store.Jobs(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	changes, err := s.store.Changes(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	approvals, _ := s.store.Approvals(r.Context())

	connected := 0
	for _, t := range tenants {
		if t.Status == "Connected" {
			connected++
		}
	}
	tenantsTone, tenantsDelta := "success", fmt.Sprintf("%d connected", connected)
	if connected < len(tenants) {
		tenantsTone, tenantsDelta = "warning", fmt.Sprintf("%d of %d connected", connected, len(tenants))
	}

	running, queued, failed := 0, 0, 0
	for _, j := range jobs {
		switch j.Status {
		case "Running":
			running++
		case "Queued":
			queued++
		case "Failed":
			failed++
		}
	}
	failedTone, failedDelta := "success", "All healthy"
	if failed > 0 {
		failedTone, failedDelta = "danger", "Needs attention"
	}

	today := time.Now().Format("2006-01-02")
	changesToday := 0
	for _, c := range changes {
		if strings.HasPrefix(c.Timestamp, today) {
			changesToday++
		}
	}

	httpx.WriteJSON(w, http.StatusOK, []model.DashboardStat{
		{Label: "Managed Tenants", Value: strconv.Itoa(len(tenants)), Delta: tenantsDelta, Tone: tenantsTone},
		{Label: "Active Jobs", Value: strconv.Itoa(running + queued), Delta: fmt.Sprintf("%d running · %d queued", running, queued), Tone: "info"},
		{Label: "Pending Approvals", Value: strconv.Itoa(len(approvals)), Delta: "None waiting", Tone: "neutral"},
		{Label: "Failed Jobs", Value: strconv.Itoa(failed), Delta: failedDelta, Tone: failedTone},
		{Label: "Changes Today", Value: strconv.Itoa(changesToday), Delta: "Across all tenants", Tone: "neutral"},
	})
}

func (s *Server) dashboardApprovals(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.Approvals(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}
