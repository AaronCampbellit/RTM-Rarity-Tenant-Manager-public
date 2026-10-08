package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	access, refresh, p, err := s.auth.Login(r.Context(), body.Email, body.Password)
	if err != nil {
		_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
			Actor: body.Email, Action: "auth.login", Resource: "—", Result: "Denied",
			CorrelationID: httpx.CorrelationID(r.Context()),
		})
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeAuthenticationFailed, "Incorrect email or password.")
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: p.Name, Action: "auth.login", Resource: "—", Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken": access, "refreshToken": refresh, "user": p,
	})
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	access, refresh, p, err := s.auth.Refresh(r.Context(), body.RefreshToken)
	if err != nil {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeAuthenticationFailed, "Your session has expired. Please sign in again.")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"accessToken": access, "refreshToken": refresh, "user": p})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, auth.UserFromContext(r.Context()))
}

// changePassword rotates the caller's password (required on first login for
// accounts seeded with default credentials) and returns a fresh token pair
// without the must-change marker.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	user := auth.UserFromContext(r.Context())
	access, refresh, p, err := s.auth.ChangePassword(r.Context(), user.ID, body.CurrentPassword, body.NewPassword)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
			Actor: user.Name, Action: "auth.password.change", Resource: "—", Result: "Denied",
			CorrelationID: httpx.CorrelationID(r.Context()),
		})
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeAuthenticationFailed, "The current password is incorrect.")
		return
	case errors.Is(err, auth.ErrWeakPassword):
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			fmt.Sprintf("The new password must be at least %d characters and different from the current one.", auth.MinPasswordLength))
		return
	case err != nil:
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: p.Name, Action: "auth.password.change", Resource: "—", Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"accessToken": access, "refreshToken": refresh, "user": p})
}
