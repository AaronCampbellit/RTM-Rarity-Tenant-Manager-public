package server_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/seed"
)

func exportAuditEntries(t *testing.T, entries []model.AuditEntry) []model.AuditEntry {
	t.Helper()
	var exports []model.AuditEntry
	for _, entry := range entries {
		if entry.Action == "exports.generate" {
			exports = append(exports, entry)
		}
	}
	return exports
}

func TestExportGenerateAuditsAuthenticatedDownload(t *testing.T) {
	h, st := newTestAPI(t)
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken

	rec := call(t, h, http.MethodPost, "/api/v1/exports/generate", token,
		`{"kind":"users","filename":"users.csv","rowCount":3,"tenantId":"ten_1"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	entries, err := st.Audit(t.Context())
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	exports := exportAuditEntries(t, entries)
	if len(exports) != 1 {
		t.Fatalf("export audits = %+v", exports)
	}
	entry := exports[0]
	if entry.Actor != "Aisha Rivera" || entry.Result != "Success" || entry.CorrelationID == "" {
		t.Fatalf("export audit identity = %+v", entry)
	}
	for _, want := range []string{"users", "Contoso Ltd", "users.csv", "3 rows"} {
		if !strings.Contains(entry.Resource, want) {
			t.Fatalf("resource %q does not contain %q", entry.Resource, want)
		}
	}
}

func TestExportGenerateAuditsGlobalDownloadWithoutTenant(t *testing.T) {
	h, st := newTestAPI(t)
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken

	rec := call(t, h, http.MethodPost, "/api/v1/exports/generate", token,
		`{"kind":"global-report","filename":"report-mfa.csv","rowCount":0}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	entries, _ := st.Audit(t.Context())
	exports := exportAuditEntries(t, entries)
	if len(exports) != 1 || !strings.Contains(exports[0].Resource, "global") {
		t.Fatalf("global export audit = %+v", exports)
	}
}

func TestExportGenerateAcceptsSafeUPNFilenameCharacters(t *testing.T) {
	h, _ := newTestAPI(t)
	token := login(t, h, techEmail, seed.DemoPassword).AccessToken

	rec := call(t, h, http.MethodPost, "/api/v1/exports/generate", token,
		`{"kind":"share-detective","filename":"share-detective-o'connor%ops@example.com.csv","rowCount":1,"tenantId":"ten_1"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestExportGenerateRejectsInvalidRequestsWithoutSuccessAudit(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "unknown kind", body: `{"kind":"secrets","filename":"users.csv","rowCount":1}`, want: http.StatusBadRequest},
		{name: "path filename", body: `{"kind":"users","filename":"../users.csv","rowCount":1}`, want: http.StatusBadRequest},
		{name: "wrong suffix", body: `{"kind":"users","filename":"users.txt","rowCount":1}`, want: http.StatusBadRequest},
		{name: "negative rows", body: `{"kind":"users","filename":"users.csv","rowCount":-1}`, want: http.StatusBadRequest},
		{name: "too many rows", body: `{"kind":"users","filename":"users.csv","rowCount":1000001}`, want: http.StatusBadRequest},
		{name: "unknown tenant", body: `{"kind":"users","filename":"users.csv","rowCount":1,"tenantId":"missing"}`, want: http.StatusNotFound},
		{name: "unknown field", body: `{"kind":"users","filename":"users.csv","rowCount":1,"actor":"forged"}`, want: http.StatusBadRequest},
		{name: "malformed json", body: `{"kind":`, want: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, st := newTestAPI(t)
			token := login(t, h, techEmail, seed.DemoPassword).AccessToken
			rec := call(t, h, http.MethodPost, "/api/v1/exports/generate", token, tt.body, nil)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
			entries, _ := st.Audit(t.Context())
			if exports := exportAuditEntries(t, entries); len(exports) != 0 {
				t.Fatalf("rejected request created audit: %+v", exports)
			}
		})
	}
}

func TestExportGenerateRequiresAuthentication(t *testing.T) {
	h, st := newTestAPI(t)
	rec := call(t, h, http.MethodPost, "/api/v1/exports/generate", "",
		`{"kind":"users","filename":"users.csv","rowCount":1,"tenantId":"ten_1"}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	entries, _ := st.Audit(t.Context())
	if exports := exportAuditEntries(t, entries); len(exports) != 0 {
		t.Fatalf("unauthenticated request created audit: %+v", exports)
	}
}
