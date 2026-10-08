// Package httpx holds the shared HTTP plumbing: the standard error envelope,
// JSON helpers, and middleware. These enforce the cross-cutting rules from the
// specs (correlation IDs everywhere, technician-friendly errors, no secrets in
// responses).
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// ---- Error envelope (Coding Standards → Error Response Shape) ----

type ErrorBody struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	CorrelationID string `json:"correlation_id"`
}

type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

// Standard error codes (API Spec → Error categories).
const (
	CodeAuthenticationFailed   = "AUTHENTICATION_FAILED"
	CodeAuthorizationDenied    = "AUTHORIZATION_DENIED"
	CodePasswordChangeRequired = "PASSWORD_CHANGE_REQUIRED"
	CodeTenantAccessDenied     = "TENANT_ACCESS_DENIED"
	CodeMicrosoftConnFailed    = "MICROSOFT_CONNECTION_FAILED"
	CodeMicrosoftThrottled     = "MICROSOFT_THROTTLED"
	CodeMicrosoftPermMissing   = "MICROSOFT_PERMISSION_MISSING"
	CodeObjectNotFound         = "OBJECT_NOT_FOUND"
	CodeValidationFailed       = "VALIDATION_FAILED"
	CodeWhatIfFailed           = "WHAT_IF_FAILED"
	CodeChangeFailed           = "CHANGE_FAILED"
	CodeRevertConflict         = "REVERT_CONFLICT"
	CodePartialSuccess         = "PARTIAL_SUCCESS"
	CodeNotImplemented         = "NOT_IMPLEMENTED"
	CodeNotConnected           = "NOT_CONNECTED"
	CodeThreatLockerFailed     = "THREATLOCKER_CONNECTION_FAILED"
	CodeInternalError          = "INTERNAL_ERROR"
)

// WriteJSON writes v as JSON with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes the standard error envelope, always including the
// request's correlation ID. The raw cause belongs in logs, never the body.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	WriteJSON(w, status, ErrorEnvelope{Error: ErrorBody{
		Code:          code,
		Message:       message,
		CorrelationID: CorrelationID(r.Context()),
	}})
}

// ---- Correlation IDs ----

type ctxKey int

const correlationKey ctxKey = 0

func CorrelationID(ctx context.Context) string {
	if v, ok := ctx.Value(correlationKey).(string); ok {
		return v
	}
	return "unknown"
}

func newCorrelationID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "cor_" + hex.EncodeToString(b)
}

// ---- Middleware ----

// Chain applies middleware in order (outermost first).
func Chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// Correlation attaches a correlation ID to the context and echoes it back on
// the response (API Principles → "Correlation IDs on requests and errors").
func Correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Correlation-ID")
		if id == "" {
			id = newCorrelationID()
		}
		w.Header().Set("X-Correlation-ID", id)
		ctx := context.WithValue(r.Context(), correlationKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logger emits structured application logs (no tokens/secrets — ADR-016).
func Logger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)
			log.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"correlation_id", CorrelationID(r.Context()),
			)
		})
	}
}

// Recover turns panics into a safe INTERNAL_ERROR envelope.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic", "error", rec, "path", r.URL.Path,
						"correlation_id", CorrelationID(r.Context()))
					WriteError(w, r, http.StatusInternalServerError,
						CodeInternalError, "An unexpected error occurred.")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// CORS allows the configured frontend origin (Security Spec → strict CORS).
func CORS(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Correlation-ID")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
