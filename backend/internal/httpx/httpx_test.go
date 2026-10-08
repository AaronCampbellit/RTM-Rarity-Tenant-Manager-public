package httpx

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) ErrorEnvelope {
	t.Helper()
	var env ErrorEnvelope
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decoding error envelope: %v", err)
	}
	return env
}

func TestWriteErrorEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)

	// Without the Correlation middleware the id falls back to "unknown".
	WriteError(rec, req, http.StatusNotFound, CodeObjectNotFound, "Missing.")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	env := decodeEnvelope(t, rec)
	if env.Error.Code != CodeObjectNotFound || env.Error.Message != "Missing." {
		t.Fatalf("envelope = %+v", env.Error)
	}
	if env.Error.CorrelationID != "unknown" {
		t.Fatalf("correlation id = %q, want unknown fallback", env.Error.CorrelationID)
	}
}

func TestCorrelationGeneratesAndEchoes(t *testing.T) {
	var seen string
	h := Correlation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = CorrelationID(r.Context())
	}))

	// No inbound header: an id is generated, stored in context, echoed back.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if seen == "" || seen == "unknown" {
		t.Fatalf("generated correlation id = %q", seen)
	}
	if got := rec.Header().Get("X-Correlation-ID"); got != seen {
		t.Fatalf("response header = %q, context id = %q", got, seen)
	}

	// Inbound header is respected end-to-end.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Correlation-ID", "cor_test123")
	h.ServeHTTP(rec, req)
	if seen != "cor_test123" || rec.Header().Get("X-Correlation-ID") != "cor_test123" {
		t.Fatalf("inbound id not propagated: context=%q header=%q", seen, rec.Header().Get("X-Correlation-ID"))
	}
}

func TestRecoverTurnsPanicIntoEnvelope(t *testing.T) {
	h := Recover(discardLogger())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if env := decodeEnvelope(t, rec); env.Error.Code != CodeInternalError {
		t.Fatalf("code = %q, want %q", env.Error.Code, CodeInternalError)
	}
}

func TestCORSPreflightAndHeaders(t *testing.T) {
	h := CORS("http://localhost:5173")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	if o := rec.Header().Get("Access-Control-Allow-Origin"); o != "http://localhost:5173" {
		t.Fatalf("allow-origin = %q", o)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("passthrough status = %d, want 200", rec.Code)
	}
}

func TestRateLimitPerIP(t *testing.T) {
	h := RateLimit(3, time.Hour)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(remote string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = remote
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 3; i++ {
		if code := do("10.0.0.1:1234"); code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i+1, code)
		}
	}
	if code := do("10.0.0.1:1234"); code != http.StatusTooManyRequests {
		t.Fatalf("over-limit request = %d, want 429", code)
	}
	// A different client is unaffected.
	if code := do("10.0.0.2:1234"); code != http.StatusOK {
		t.Fatalf("other-ip request = %d, want 200", code)
	}
}

func TestRateLimitWindowResets(t *testing.T) {
	h := RateLimit(1, 30*time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	do := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "10.0.0.9:1"
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if do() != http.StatusOK || do() != http.StatusTooManyRequests {
		t.Fatal("expected 200 then 429 inside the window")
	}
	time.Sleep(50 * time.Millisecond)
	if code := do(); code != http.StatusOK {
		t.Fatalf("after window reset = %d, want 200", code)
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		{"remote addr", "192.0.2.7:5555", "", "192.0.2.7"},
		{"xff single", "10.0.0.1:1", "203.0.113.9", "203.0.113.9"},
		{"xff chain takes first", "10.0.0.1:1", " 203.0.113.9 , 10.1.1.1", "203.0.113.9"},
		{"bad remote falls through", "not-a-hostport", "", "not-a-hostport"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := clientIP(req); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}
