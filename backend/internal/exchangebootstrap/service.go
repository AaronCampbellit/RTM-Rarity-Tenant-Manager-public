// Package exchangebootstrap performs RTM's one-time Exchange RBAC bootstrap.
// A tenant administrator grants a short delegated Graph session, RTM creates
// one exact Recipient Management assignment for the runtime service principal,
// and the delegated token is discarded. No refresh token is requested.
package exchangebootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	delegatedScope = "https://graph.microsoft.com/RoleManagement.ReadWrite.Exchange"
	runtimeScope   = "https://outlook.office365.com/.default"
	roleName       = "Recipient Management"
	stateTTL       = 10 * time.Minute
	maxBodyBytes   = 2 << 20
)

var (
	ErrInvalidState = errors.New("exchange bootstrap state is invalid or expired")
)

type Config struct {
	LoginBase, GraphBase string
	HTTPClient           *http.Client
	StateTTL             time.Duration
}

type RuntimeAuth struct {
	DirectoryID, ClientID, ClientSecret string
}

type Resolver func(context.Context, string) (RuntimeAuth, error)

type StartInput struct {
	TenantID, TenantName, DirectoryID string
	ActorID, ActorName                string
	BootstrapClientID                 string
	BootstrapClientSecret             []byte
	RedirectURL                       string
}

type StartResult struct {
	AuthorizationURL string    `json:"authorizationUrl"`
	ExpiresAt        time.Time `json:"expiresAt"`
	Preview          Preview   `json:"preview"`
}

type Preview struct {
	DelegatedPermission string `json:"delegatedPermission"`
	RuntimePermission   string `json:"runtimePermission"`
	ExchangeRole        string `json:"exchangeRole"`
	Scope               string `json:"scope"`
	TokenRetention      string `json:"tokenRetention"`
	APIVersion          string `json:"apiVersion"`
}

func AuthorizationPreview() Preview {
	return Preview{DelegatedPermission: "RoleManagement.ReadWrite.Exchange", RuntimePermission: "Exchange.ManageAsAppV2", ExchangeRole: roleName, Scope: "All mailboxes in this tenant", TokenRetention: "Discarded immediately after authorization", APIVersion: "Microsoft Graph beta"}
}

type Completion struct {
	TenantID, TenantName, ActorName string
	Created                         bool
}

type pending struct {
	StartInput
	Verifier  string
	ExpiresAt time.Time
	timer     *time.Timer
}

type Service struct {
	cfg      Config
	resolve  Resolver
	mu       sync.Mutex
	pending  map[string]*pending
	now      func() time.Time
	stateTTL time.Duration
}

func New(cfg Config, resolve Resolver) *Service {
	if cfg.LoginBase == "" {
		cfg.LoginBase = "https://login.microsoftonline.com"
	}
	if cfg.GraphBase == "" {
		cfg.GraphBase = "https://graph.microsoft.com"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.StateTTL <= 0 {
		cfg.StateTTL = stateTTL
	}
	return &Service{cfg: cfg, resolve: resolve, pending: map[string]*pending{}, now: time.Now, stateTTL: cfg.StateTTL}
}

func (s *Service) Start(in StartInput) (StartResult, error) {
	if in.TenantID == "" || in.DirectoryID == "" || in.ActorID == "" {
		return StartResult{}, fmt.Errorf("exchange bootstrap: incomplete start context")
	}
	if strings.TrimSpace(in.BootstrapClientID) == "" || len(in.BootstrapClientSecret) == 0 || strings.TrimSpace(in.RedirectURL) == "" {
		return StartResult{}, fmt.Errorf("exchange bootstrap: one-time bootstrap credentials and redirect URL are required")
	}
	state, err := randomURLString(32)
	if err != nil {
		return StartResult{}, err
	}
	verifier, err := randomURLString(48)
	if err != nil {
		return StartResult{}, err
	}
	expires := s.now().Add(s.stateTTL)
	in.BootstrapClientSecret = append([]byte(nil), in.BootstrapClientSecret...)
	item := &pending{StartInput: in, Verifier: verifier, ExpiresAt: expires}
	s.mu.Lock()
	for key, item := range s.pending {
		if s.now().After(item.ExpiresAt) {
			item.destroy()
			delete(s.pending, key)
		}
	}
	s.pending[state] = item
	item.timer = time.AfterFunc(s.stateTTL, func() { s.expire(state) })
	s.mu.Unlock()

	challenge := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"client_id":             {in.BootstrapClientID},
		"response_type":         {"code"},
		"redirect_uri":          {in.RedirectURL},
		"response_mode":         {"form_post"},
		"scope":                 {"openid profile " + delegatedScope},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	}
	return StartResult{
		AuthorizationURL: strings.TrimRight(s.cfg.LoginBase, "/") + "/" + url.PathEscape(in.DirectoryID) + "/oauth2/v2.0/authorize?" + values.Encode(),
		ExpiresAt:        expires,
		Preview:          AuthorizationPreview(),
	}, nil
}

func (s *Service) Complete(ctx context.Context, state, code string) (Completion, error) {
	item, err := s.consume(state)
	if err != nil {
		return Completion{}, err
	}
	defer item.destroy()
	completion := Completion{TenantID: item.TenantID, TenantName: item.TenantName, ActorName: item.ActorName}
	if code == "" {
		return completion, fmt.Errorf("exchange bootstrap: authorization code missing")
	}
	auth, err := s.resolve(ctx, item.TenantID)
	if err != nil {
		return completion, fmt.Errorf("exchange bootstrap: resolve runtime app: %w", err)
	}
	if !strings.EqualFold(auth.DirectoryID, item.DirectoryID) || auth.ClientID == "" || auth.ClientSecret == "" {
		return completion, fmt.Errorf("exchange bootstrap: runtime app configuration changed or is incomplete")
	}
	delegatedToken, err := s.exchangeCode(ctx, item, code)
	if err != nil {
		return completion, err
	}
	runtimeToken, err := s.clientToken(ctx, auth)
	if err != nil {
		return completion, err
	}
	servicePrincipalID, err := runtimePrincipal(runtimeToken, auth)
	if err != nil {
		return completion, err
	}
	created, err := s.ensureAssignment(ctx, delegatedToken, servicePrincipalID)
	// Both token strings become unreachable when this method returns. The
	// service never requests a refresh token and never writes either to store.
	if err != nil {
		return completion, err
	}
	completion.Created = created
	return completion, nil
}

func (s *Service) consume(state string) (*pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.pending[state]
	delete(s.pending, state)
	if !ok || s.now().After(item.ExpiresAt) {
		if ok {
			item.destroy()
		}
		return nil, ErrInvalidState
	}
	if item.timer != nil {
		item.timer.Stop()
	}
	return item, nil
}

func (s *Service) exchangeCode(ctx context.Context, item *pending, code string) (string, error) {
	values := url.Values{"client_id": {item.BootstrapClientID}, "client_secret": {string(item.BootstrapClientSecret)}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {item.RedirectURL}, "code_verifier": {item.Verifier}, "scope": {delegatedScope}}
	return s.token(ctx, item.DirectoryID, values, delegatedScope)
}

func (s *Service) expire(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if item, ok := s.pending[state]; ok && !s.now().Before(item.ExpiresAt) {
		item.destroy()
		delete(s.pending, state)
	}
}

func (p *pending) destroy() {
	for i := range p.BootstrapClientSecret {
		p.BootstrapClientSecret[i] = 0
	}
	p.BootstrapClientSecret = nil
	p.BootstrapClientID = ""
	p.RedirectURL = ""
	p.Verifier = ""
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
}

func (s *Service) clientToken(ctx context.Context, auth RuntimeAuth) (string, error) {
	values := url.Values{"client_id": {auth.ClientID}, "client_secret": {auth.ClientSecret}, "grant_type": {"client_credentials"}, "scope": {runtimeScope}}
	return s.token(ctx, auth.DirectoryID, values, runtimeScope)
}

func (s *Service) token(ctx context.Context, directoryID string, values url.Values, expectedScope string) (string, error) {
	endpoint := strings.TrimRight(s.cfg.LoginBase, "/") + "/" + url.PathEscape(directoryID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("exchange bootstrap: token request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxBodyBytes {
		return "", fmt.Errorf("exchange bootstrap: token response too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("exchange bootstrap: Microsoft token endpoint rejected %s authorization (%d)", expectedScope, resp.StatusCode)
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &result) != nil || result.AccessToken == "" {
		return "", fmt.Errorf("exchange bootstrap: Microsoft token response was invalid")
	}
	return result.AccessToken, nil
}

func runtimePrincipal(token string, auth RuntimeAuth) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("exchange bootstrap: runtime token was not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("exchange bootstrap: runtime token claims were invalid")
	}
	var claims struct{ ObjectID, TenantID, AppID, AuthorizedParty string }
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return "", fmt.Errorf("exchange bootstrap: runtime token claims were invalid")
	}
	claims.ObjectID, _ = raw["oid"].(string)
	claims.TenantID, _ = raw["tid"].(string)
	claims.AppID, _ = raw["appid"].(string)
	claims.AuthorizedParty, _ = raw["azp"].(string)
	clientID := claims.AppID
	if clientID == "" {
		clientID = claims.AuthorizedParty
	}
	if claims.ObjectID == "" || !strings.EqualFold(claims.TenantID, auth.DirectoryID) || !strings.EqualFold(clientID, auth.ClientID) {
		return "", fmt.Errorf("exchange bootstrap: runtime token identity did not match the managed tenant app")
	}
	return claims.ObjectID, nil
}

func (s *Service) ensureAssignment(ctx context.Context, token, principalObjectID string) (bool, error) {
	definitionURL := strings.TrimRight(s.cfg.GraphBase, "/") + "/beta/roleManagement/exchange/roleDefinitions?$filter=" + url.QueryEscape("displayName eq '"+roleName+"'")
	var definitions struct {
		Value []struct {
			ID, DisplayName      string
			IsBuiltIn, IsEnabled *bool
		} `json:"value"`
	}
	if err := s.graph(ctx, http.MethodGet, definitionURL, token, nil, &definitions); err != nil {
		return false, err
	}
	matches := make([]string, 0, 1)
	for _, d := range definitions.Value {
		if d.DisplayName == roleName && d.ID != "" && (d.IsBuiltIn == nil || *d.IsBuiltIn) && (d.IsEnabled == nil || *d.IsEnabled) {
			matches = append(matches, d.ID)
		}
	}
	if len(matches) != 1 {
		return false, fmt.Errorf("exchange bootstrap: expected exactly one enabled built-in %s role, found %d", roleName, len(matches))
	}
	principalID := "/ServicePrincipals/" + principalObjectID
	assignmentsURL := strings.TrimRight(s.cfg.GraphBase, "/") + "/beta/roleManagement/exchange/roleAssignments?$filter=" + url.QueryEscape("principalId eq '"+principalID+"' and roleDefinitionId eq '"+matches[0]+"'")
	var assignments struct {
		Value []struct{ RoleDefinitionID, PrincipalID, DirectoryScopeID string } `json:"value"`
	}
	if err := s.graph(ctx, http.MethodGet, assignmentsURL, token, nil, &assignments); err != nil {
		return false, err
	}
	for _, a := range assignments.Value {
		if a.RoleDefinitionID == matches[0] && strings.EqualFold(a.PrincipalID, principalID) && a.DirectoryScopeID == "/" {
			return false, nil
		}
	}
	payload := map[string]any{"@odata.type": "#microsoft.graph.unifiedRoleAssignment", "principalId": principalID, "roleDefinitionId": matches[0], "directoryScopeId": "/", "appScopeId": nil}
	assignmentURL := strings.TrimRight(s.cfg.GraphBase, "/") + "/beta/roleManagement/exchange/roleAssignments"
	if err := s.graph(ctx, http.MethodPost, assignmentURL, token, payload, nil); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) graph(ctx context.Context, method, endpoint, token string, payload, out any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("exchange bootstrap: Graph request failed: %w", err)
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return err
	}
	if len(response) > maxBodyBytes {
		return fmt.Errorf("exchange bootstrap: Graph response too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("exchange bootstrap: Microsoft Graph rejected the role operation (%d)", resp.StatusCode)
	}
	if out != nil && len(response) > 0 && json.Unmarshal(response, out) != nil {
		return fmt.Errorf("exchange bootstrap: Microsoft Graph response was invalid")
	}
	return nil
}

func randomURLString(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
