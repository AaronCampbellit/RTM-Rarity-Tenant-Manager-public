package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/httpx"
)

func TestWriteErrExplainsExchangeUnauthorizedPermissionSetup(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/ten_1/exchange/mailboxes/user/permissions", nil)
	rec := httptest.NewRecorder()

	s.writeErr(rec, req, &graph.ExchangeAPIError{
		Status: http.StatusUnauthorized,
		Path:   "POST Mailbox",
	})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Error.Code != httpx.CodeMicrosoftPermMissing {
		t.Fatalf("code = %q, want %q", body.Error.Code, httpx.CodeMicrosoftPermMissing)
	}
	for _, want := range []string{"Exchange.ManageAsAppV2", "Recipient Management"} {
		if !strings.Contains(body.Error.Message, want) {
			t.Fatalf("message %q does not contain %q", body.Error.Message, want)
		}
	}
}
