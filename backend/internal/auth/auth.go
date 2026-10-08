// Package auth implements RTM-native authentication (API Spec → Authentication):
// JWT bearer tokens (short-lived access + longer refresh), bcrypt password
// verification, and the layered authorization middleware. OIDC/Entra as an
// external IdP is a future addition; RTM still issues its own JWT either way.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrWeakPassword       = errors.New("password does not meet the policy")
)

// MinPasswordLength is the operator password policy (Security Spec: strong
// credentials; forced rotation of defaults).
const MinPasswordLength = 12

const SessionTimeoutSettingKey = "session_timeout"

var sessionTimeouts = map[string]time.Duration{
	"30":   30 * time.Minute,
	"60":   time.Hour,
	"240":  4 * time.Hour,
	"480":  8 * time.Hour,
	"720":  12 * time.Hour,
	"1440": 24 * time.Hour,
}

// SessionTimeoutDuration resolves the persisted minute value shared by the
// Admin Settings API and token issuer. Values outside the supported policy
// set are rejected instead of permitting arbitrary long-lived bearer tokens.
func SessionTimeoutDuration(value string) (time.Duration, bool) {
	duration, ok := sessionTimeouts[value]
	return duration, ok
}

// Principal is the authenticated operator carried in the request context.
type Principal struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	IsAdmin     bool     `json:"isAdmin"`
	// MustChangePassword forces a rotation before the rest of the API opens up
	// (seeded/default credentials). Carried in the token so every instance can
	// enforce it without a store lookup per request.
	MustChangePassword bool `json:"mustChangePassword"`
	// CredentialVersion is internal token state. It changes whenever a
	// password changes or is reset, invalidating every previously issued token.
	CredentialVersion int `json:"-"`
}

type Service struct {
	store      store.Store
	key        []byte
	log        *slog.Logger
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewService(st store.Store, signingKey []byte, log *slog.Logger) *Service {
	return &Service{
		store:      st,
		key:        signingKey,
		log:        log,
		accessTTL:  30 * time.Minute, // short-lived (Security Spec)
		refreshTTL: 7 * 24 * time.Hour,
	}
}

type claims struct {
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Role              string   `json:"role"`
	Permissions       []string `json:"permissions"`
	IsAdmin           bool     `json:"admin"`
	Kind              string   `json:"kind"` // "access" | "refresh"
	MustChange        bool     `json:"pwd_change,omitempty"`
	CredentialVersion int      `json:"cred_version,omitempty"`
	jwt.RegisteredClaims
}

// Login verifies credentials and issues an access token plus a rotating
// refresh token (its id is recorded so the next refresh can detect reuse).
func (s *Service) Login(ctx context.Context, email, password string) (access, refresh string, p Principal, err error) {
	email = strings.ToLower(strings.TrimSpace(email))
	acct, err := s.store.AccountByEmail(ctx, email)
	if err != nil {
		return "", "", Principal{}, ErrInvalidCredentials
	}
	if acct.Status != "Active" {
		return "", "", Principal{}, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(acct.PasswordHash), []byte(password)) != nil {
		return "", "", Principal{}, ErrInvalidCredentials
	}
	p = s.principalFromAccount(ctx, acct)
	access, refresh, err = s.issuePair(ctx, p)
	return access, refresh, p, err
}

// ChangePassword verifies the current password, applies the policy, stores the
// new hash (clearing the must-change flag), and issues a fresh token pair so
// the caller immediately holds tokens without the must-change marker.
func (s *Service) ChangePassword(ctx context.Context, accountID, currentPassword, newPassword string) (access, refresh string, p Principal, err error) {
	acct, err := s.store.AccountByID(ctx, accountID)
	if err != nil {
		return "", "", Principal{}, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(acct.PasswordHash), []byte(currentPassword)) != nil {
		return "", "", Principal{}, ErrInvalidCredentials
	}
	if len(newPassword) < MinPasswordLength || newPassword == currentPassword {
		return "", "", Principal{}, ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", "", Principal{}, err
	}
	if err := s.store.SetPassword(ctx, acct.ID, string(hash)); err != nil {
		return "", "", Principal{}, err
	}
	acct, err = s.store.AccountByID(ctx, acct.ID)
	if err != nil {
		return "", "", Principal{}, err
	}
	p = s.principalFromAccount(ctx, acct)
	p.MustChangePassword = false
	access, refresh, err = s.issuePair(ctx, p)
	return access, refresh, p, err
}

// Refresh validates the refresh token, rejects reuse of a rotated token, then
// issues a fresh access + refresh pair (rotation).
func (s *Service) Refresh(ctx context.Context, refreshToken string) (access, refresh string, p Principal, err error) {
	p, kind, jti, err := s.parse(refreshToken)
	if err != nil || kind != "refresh" {
		return "", "", Principal{}, ErrInvalidToken
	}
	current, err := s.store.CurrentRefreshToken(ctx, p.ID)
	if err != nil {
		return "", "", Principal{}, err
	}
	if current == "" || current != jti {
		// Presented token isn't the current one — treat as reuse/revoked.
		return "", "", Principal{}, ErrInvalidToken
	}
	acct, err := s.store.AccountByID(ctx, p.ID)
	if err != nil || acct.Status != "Active" || acct.CredentialVersion != p.CredentialVersion {
		return "", "", Principal{}, ErrInvalidToken
	}
	p = s.principalFromAccount(ctx, acct)
	access, refresh, err = s.issuePair(ctx, p)
	return access, refresh, p, err
}

// Logout revokes the account's refresh token.
func (s *Service) Logout(ctx context.Context, accountID string) error {
	return s.store.ClearRefreshToken(ctx, accountID)
}

// issuePair mints an access token and a rotating refresh token, recording the
// refresh jti as the account's current one.
func (s *Service) issuePair(ctx context.Context, p Principal) (access, refresh string, err error) {
	access, err = s.issue(p, "access", s.configuredAccessTTL(ctx), "")
	if err != nil {
		return "", "", err
	}
	jti := newID()
	refresh, err = s.issue(p, "refresh", s.refreshTTL, jti)
	if err != nil {
		return "", "", err
	}
	if err := s.store.SetRefreshToken(ctx, p.ID, jti); err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

func (s *Service) configuredAccessTTL(ctx context.Context) time.Duration {
	settings, err := s.store.AppSettings(ctx)
	if err != nil {
		s.log.Warn("auth: session timeout lookup failed; using default", "error", err)
		return s.accessTTL
	}
	for _, setting := range settings {
		if setting.Key != SessionTimeoutSettingKey {
			continue
		}
		if duration, ok := SessionTimeoutDuration(setting.Value); ok {
			return duration
		}
		s.log.Warn("auth: unsupported persisted session timeout; using default", "value", setting.Value)
		return s.accessTTL
	}
	return s.accessTTL
}

func (s *Service) issue(p Principal, kind string, ttl time.Duration, jti string) (string, error) {
	now := time.Now()
	c := claims{
		Name: p.Name, Email: p.Email, Role: p.Role, Permissions: p.Permissions,
		IsAdmin: p.IsAdmin, Kind: kind, MustChange: p.MustChangePassword, CredentialVersion: p.CredentialVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   p.ID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			Issuer:    "rtm",
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(s.key)
}

func (s *Service) parse(token string) (Principal, string, string, error) {
	var c claims
	t, err := jwt.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return s.key, nil
	}, jwt.WithIssuer("rtm"), jwt.WithExpirationRequired())
	if err != nil || !t.Valid {
		return Principal{}, "", "", ErrInvalidToken
	}
	return Principal{ID: c.Subject, Name: c.Name, Email: c.Email, Role: c.Role, Permissions: c.Permissions, IsAdmin: c.IsAdmin, MustChangePassword: c.MustChange, CredentialVersion: c.CredentialVersion}, c.Kind, c.ID, nil
}

func (s *Service) principalFromAccount(ctx context.Context, a store.Account) Principal {
	p := Principal{ID: a.ID, Name: a.Name, Email: a.Email, Role: a.Role, IsAdmin: a.IsAdmin, MustChangePassword: a.MustChange, CredentialVersion: a.CredentialVersion}
	if role, err := s.store.Role(ctx, a.Role); err == nil {
		p.Permissions = append([]string(nil), role.PermissionKeys...)
	}
	return p
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// HashPassword bcrypt-hashes a password for storage (technician invites).
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

// TempPassword generates a random one-time password that satisfies the
// policy; it is returned to the inviting admin exactly once.
func TempPassword() string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return "Rtm-" + hex.EncodeToString(b) // 22 chars
}

// ---- Middleware ----

type ctxKey int

const principalKey ctxKey = 0

// Middleware requires a valid access token and stores the principal in context.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(authz, "Bearer ")
		if !ok || token == "" {
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeAuthenticationFailed, "Authentication required.")
			return
		}
		p, kind, _, err := s.parse(token)
		if err != nil || kind != "access" {
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeAuthenticationFailed, "Your session is invalid or has expired.")
			return
		}
		acct, err := s.store.AccountByID(r.Context(), p.ID)
		if err != nil || acct.Status != "Active" || acct.CredentialVersion != p.CredentialVersion {
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.CodeAuthenticationFailed, "Your session is invalid or has expired.")
			return
		}
		mustChange := p.MustChangePassword || acct.MustChange
		p = s.principalFromAccount(r.Context(), acct)
		p.MustChangePassword = mustChange
		ctx := context.WithValue(r.Context(), principalKey, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePasswordChanged blocks accounts still holding a must-change (default)
// password. Applied to every authed route except /auth/me and
// /auth/change-password so the only path forward is rotating the password.
func (s *Service) RequirePasswordChanged(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFromContext(r.Context()).MustChangePassword {
			httpx.WriteError(w, r, http.StatusForbidden, httpx.CodePasswordChangeRequired,
				"You must change your password before continuing.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin allows only admin principals (v1 write/admin gate — ADR-015).
func (s *Service) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !UserFromContext(r.Context()).IsAdmin {
			httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeAuthorizationDenied, "You do not have permission to perform this action.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePermission evaluates the persisted role policy loaded for this
// request, so role edits take effect without waiting for token expiry.
func (s *Service) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasPermission(UserFromContext(r.Context()), permission) {
				httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeAuthorizationDenied, "You do not have permission to perform this action.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func HasPermission(principal Principal, permission string) bool {
	for _, granted := range principal.Permissions {
		if granted == permission {
			return true
		}
	}
	return false
}

// UserFromContext returns the authenticated principal (zero value if none).
func UserFromContext(ctx context.Context) Principal {
	if p, ok := ctx.Value(principalKey).(Principal); ok {
		return p
	}
	return Principal{}
}
