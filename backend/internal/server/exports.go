package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
)

const maxExportRows = 1_000_000

var (
	exportKinds = map[string]struct{}{
		"users":                     {},
		"group-members":             {},
		"mailboxes":                 {},
		"change-history":            {},
		"global-report":             {},
		"share-detective":           {},
		"threatlocker-applications": {},
		"threatlocker-devices":      {},
	}
)

type exportGenerateRequest struct {
	Kind     string `json:"kind"`
	Filename string `json:"filename"`
	RowCount int    `json:"rowCount"`
	TenantID string `json:"tenantId,omitempty"`
}

func (s *Server) generateExport(w http.ResponseWriter, r *http.Request) {
	var body exportGenerateRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}

	body.Kind = strings.TrimSpace(body.Kind)
	body.Filename = strings.TrimSpace(body.Filename)
	body.TenantID = strings.TrimSpace(body.TenantID)
	if _, ok := exportKinds[body.Kind]; !ok ||
		!validExportFilename(body.Filename) ||
		body.RowCount < 0 || body.RowCount > maxExportRows {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Export metadata is invalid.")
		return
	}

	scope := "global"
	if body.TenantID != "" {
		tenant, err := s.store.Tenant(r.Context(), body.TenantID)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		scope = tenant.Name
	}

	user := auth.UserFromContext(r.Context())
	if err := s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor:         user.Name,
		Action:        "exports.generate",
		Resource:      fmt.Sprintf("%s export · %s · %s · %d rows", body.Kind, scope, body.Filename, body.RowCount),
		Result:        "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	}); err != nil {
		s.writeErr(w, r, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

func validExportFilename(filename string) bool {
	if len(filename) <= len(".csv") || len(filename) > 128 ||
		!strings.HasSuffix(strings.ToLower(filename), ".csv") ||
		strings.ContainsAny(filename, `/\`) {
		return false
	}
	for _, r := range filename {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
