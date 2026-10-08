package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rarity/rtm/internal/seed"
	"github.com/rarity/rtm/internal/store"
)

const techEmail = "aisha.rivera@rarity.io" // seeded technician (tech_2: ten_1)

func newTestService(t *testing.T) (*Service, *store.Mem) {
	t.Helper()
	st := store.NewMem()
	log := slog.New(slog.NewTextHandler(nopWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 4}))
	return NewService(st, []byte("test-signing-key"), log), st
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestLoginIssuesTokens(t *testing.T) {
	svc, _ := newTestService(t)
	access, refresh, p, err := svc.Login(context.Background(), techEmail, seed.DemoPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("expected both tokens")
	}
	if p.IsAdmin || p.ID != "tech_2" || p.MustChangePassword {
		t.Fatalf("principal = %+v", p)
	}

	// Email matching is case-insensitive and whitespace-tolerant.
	if _, _, _, err := svc.Login(context.Background(), "  Aisha.Rivera@Rarity.IO ", seed.DemoPassword); err != nil {
		t.Fatalf("normalized login: %v", err)
	}
}

func TestConfiguredSessionTimeoutAppliesToNewAndRefreshedAccessTokens(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	if err := st.UpdateAppSettingValue(ctx, SessionTimeoutSettingKey, "240"); err != nil {
		t.Fatalf("set four-hour timeout: %v", err)
	}
	access, refresh, _, err := svc.Login(ctx, techEmail, seed.DemoPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if got := tokenLifetime(t, access); got != 4*time.Hour {
		t.Fatalf("access lifetime = %v, want 4h", got)
	}

	if err := st.UpdateAppSettingValue(ctx, SessionTimeoutSettingKey, "720"); err != nil {
		t.Fatalf("set twelve-hour timeout: %v", err)
	}
	access, _, _, err = svc.Refresh(ctx, refresh)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := tokenLifetime(t, access); got != 12*time.Hour {
		t.Fatalf("refreshed access lifetime = %v, want 12h", got)
	}
}

func tokenLifetime(t *testing.T, token string) time.Duration {
	t.Helper()
	var parsed claims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &parsed); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return parsed.ExpiresAt.Time.Sub(parsed.IssuedAt.Time)
}

func TestLoginDefaultAdminMustChangePassword(t *testing.T) {
	svc, _ := newTestService(t)
	_, _, p, err := svc.Login(context.Background(), seed.DefaultAdminEmail, seed.DefaultAdminPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !p.IsAdmin || !p.MustChangePassword {
		t.Fatalf("default admin principal = %+v, want admin with forced change", p)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	svc, _ := newTestService(t)
	if _, _, _, err := svc.Login(context.Background(), techEmail, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, _, _, err := svc.Login(context.Background(), "nobody@rarity.io", seed.DemoPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown email: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	_, _, p, err := svc.Login(ctx, seed.DefaultAdminEmail, seed.DefaultAdminPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Wrong current password.
	if _, _, _, err := svc.ChangePassword(ctx, p.ID, "wrong", "a-long-enough-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current: %v", err)
	}
	// Policy: too short, or unchanged.
	if _, _, _, err := svc.ChangePassword(ctx, p.ID, seed.DefaultAdminPassword, "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("short password: %v", err)
	}
	if _, _, _, err := svc.ChangePassword(ctx, p.ID, seed.DefaultAdminPassword, seed.DefaultAdminPassword); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("unchanged password: %v", err)
	}

	// Successful rotation clears the must-change flag on the new pair.
	access, refresh, rotated, err := svc.ChangePassword(ctx, p.ID, seed.DefaultAdminPassword, "correct-horse-battery")
	if err != nil {
		t.Fatalf("change: %v", err)
	}
	if access == "" || refresh == "" || rotated.MustChangePassword {
		t.Fatalf("rotated = %+v", rotated)
	}

	// The old password is dead; the new one logs in without the flag.
	if _, _, _, err := svc.Login(ctx, seed.DefaultAdminEmail, seed.DefaultAdminPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password still accepted: %v", err)
	}
	_, _, again, err := svc.Login(ctx, seed.DefaultAdminEmail, "correct-horse-battery")
	if err != nil || again.MustChangePassword {
		t.Fatalf("re-login = %+v, %v", again, err)
	}
}

// inactiveStore serves a single non-Active account.
type inactiveStore struct {
	store.Store
}

func (inactiveStore) AccountByEmail(context.Context, string) (store.Account, error) {
	return store.Account{ID: "x", Email: "x@x", Status: "Suspended", PasswordHash: "$2a$10$abcdefghijklmnopqrstuv"}, nil
}

func TestLoginRejectsInactiveAccount(t *testing.T) {
	log := slog.New(slog.NewTextHandler(nopWriter{}, nil))
	svc := NewService(inactiveStore{}, []byte("k"), log)
	if _, _, _, err := svc.Login(context.Background(), "x@x", "anything"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("inactive account: %v", err)
	}
}

func TestRefreshRotatesAndRejectsReuse(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	access, refresh1, _, err := svc.Login(ctx, techEmail, seed.DemoPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Rotation: the first refresh works and issues a new pair.
	_, refresh2, _, err := svc.Refresh(ctx, refresh1)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refresh2 == refresh1 {
		t.Fatal("refresh token was not rotated")
	}

	// Reuse of the rotated-out token is rejected (Security Spec).
	if _, _, _, err := svc.Refresh(ctx, refresh1); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reuse of rotated token: %v", err)
	}

	// The current token still works after a reuse attempt.
	if _, _, _, err := svc.Refresh(ctx, refresh2); err != nil {
		t.Fatalf("current refresh after reuse attempt: %v", err)
	}

	// An access token is not accepted as a refresh token.
	if _, _, _, err := svc.Refresh(ctx, access); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("access token as refresh: %v", err)
	}
}

func TestLogoutRevokesRefreshToken(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	_, refresh, p, err := svc.Login(ctx, techEmail, seed.DemoPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := svc.Logout(ctx, p.ID); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, _, _, err := svc.Refresh(ctx, refresh); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("refresh after logout: %v", err)
	}
}

func TestMiddleware(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	access, refresh, _, err := svc.Login(ctx, techEmail, seed.DemoPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	var got Principal
	h := svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	do := func(authz string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do("Bearer " + access); code != http.StatusOK {
		t.Fatalf("valid token = %d, want 200", code)
	}
	if got.Email != techEmail {
		t.Fatalf("principal in context = %+v", got)
	}
	if code := do(""); code != http.StatusUnauthorized {
		t.Fatalf("missing header = %d, want 401", code)
	}
	if code := do("Bearer garbage"); code != http.StatusUnauthorized {
		t.Fatalf("garbage token = %d, want 401", code)
	}
	// A refresh token must not authenticate API requests.
	if code := do("Bearer " + refresh); code != http.StatusUnauthorized {
		t.Fatalf("refresh as access = %d, want 401", code)
	}

	// Expired access token.
	expired, err := svc.issue(Principal{ID: "tech_2", Email: techEmail}, "access", -time.Minute, "")
	if err != nil {
		t.Fatalf("issuing expired token: %v", err)
	}
	if code := do("Bearer " + expired); code != http.StatusUnauthorized {
		t.Fatalf("expired token = %d, want 401", code)
	}

	// Token signed with a different key.
	other := NewService(store.NewMem(), []byte("other-key"), slog.New(slog.NewTextHandler(nopWriter{}, nil)))
	forged, err := other.issue(Principal{ID: "tech_1"}, "access", time.Minute, "")
	if err != nil {
		t.Fatalf("issuing forged token: %v", err)
	}
	if code := do("Bearer " + forged); code != http.StatusUnauthorized {
		t.Fatalf("wrong-key token = %d, want 401", code)
	}
}

func TestMiddlewareRejectsAccountDisabledAfterTokenIssue(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	access, _, _, err := svc.Login(ctx, techEmail, seed.DemoPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	status := "Suspended"
	if err := st.UpdateAccount(ctx, "tech_2", store.AccountUpdate{Status: &status}); err != nil {
		t.Fatalf("disable account: %v", err)
	}

	h := svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled account token = %d, want 401", rec.Code)
	}
}

func TestRefreshUsesCurrentAccountRole(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	_, refresh, _, err := svc.Login(ctx, techEmail, seed.DemoPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	role := seed.RoleAdmin
	isAdmin := true
	if err := st.UpdateAccount(ctx, "tech_2", store.AccountUpdate{Role: &role, IsAdmin: &isAdmin}); err != nil {
		t.Fatalf("promote account: %v", err)
	}
	_, _, p, err := svc.Refresh(ctx, refresh)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !p.IsAdmin {
		t.Fatalf("refresh principal = %+v, want current admin role", p)
	}
}

func TestRequireAdmin(t *testing.T) {
	svc, _ := newTestService(t)
	h := svc.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	do := func(p Principal) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), principalKey, p))
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do(Principal{ID: "tech_1", IsAdmin: true}); code != http.StatusOK {
		t.Fatalf("admin = %d, want 200", code)
	}
	if code := do(Principal{ID: "tech_2"}); code != http.StatusForbidden {
		t.Fatalf("non-admin = %d, want 403", code)
	}
}
