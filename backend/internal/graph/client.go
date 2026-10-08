package graph

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rarity/rtm/internal/model"
)

// ErrLiveNotImplemented marks entities not yet mapped for live Graph mode. The
// token flow and read plumbing below are real; the remaining entity mappings
// are the next Graph task (see backend/README.md → intended build order).
var ErrLiveNotImplemented = errors.New("graph: live mode not yet implemented for this entity")

// ErrExchangeOnly marks operations Microsoft Graph does not expose — mailbox
// permissions (Full Access / Send As / Send on Behalf) require Exchange
// Online (REST-backed cmdlets or controlled PowerShell, per the Graph guide).
var ErrExchangeOnly = errors.New("graph: this operation requires Exchange Online — Microsoft Graph does not expose it")

// ErrExchangeAdminUnsupported marks mailbox permission families that the
// supported Exchange Online Admin REST API does not expose. It is distinct
// from a missing connector or missing consent.
var ErrExchangeAdminUnsupported = errors.New("exchange: this mailbox permission is not supported by the Exchange Online Admin API")

// ErrSharePointOnly marks operations that need SharePoint REST / admin APIs:
// user-level site permission grants and per-site sharing capability are not
// writable through Graph app-only calls.
var ErrSharePointOnly = errors.New("graph: this operation requires the SharePoint admin API — Microsoft Graph does not expose it")

// APIError is a non-2xx answer from Microsoft (token endpoint or Graph),
// carrying Microsoft's own error code/message so operators can see *why* a
// call failed (e.g. Authorization_RequestDenied → missing admin consent).
type APIError struct {
	Status  int    // HTTP status from Microsoft
	Code    string // Microsoft error code (AADSTS…, Authorization_RequestDenied, …)
	Message string // Microsoft's human-readable description
	Path    string // what was called
}

// ExchangeAPIError carries a non-2xx response from the supported Exchange
// Online Admin API. Keeping it distinct from APIError lets the HTTP layer give
// operators the correct resource, permission, and RBAC remediation.
type ExchangeAPIError struct {
	Status  int
	Code    string
	Message string
	Path    string
}

func (e *ExchangeAPIError) Error() string {
	msg := fmt.Sprintf("exchange %s: status %d", e.Path, e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("graph %s: status %d", e.Path, e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

const (
	defaultGraphBase    = "https://graph.microsoft.com/v1.0"
	defaultLoginBase    = "https://login.microsoftonline.com"
	defaultExchangeBase = "https://outlook.office365.com"
)

type graphClient struct {
	cfg     Config
	log     *slog.Logger
	http    *http.Client
	resolve AuthorityResolver

	// Endpoint bases; overridden in tests to point at a fake Graph server.
	base         string
	loginBase    string
	exchangeBase string

	mu     sync.Mutex
	tokens map[string]cachedToken // keyed by authority tenant

	spCert    *x509.Certificate
	spKey     *rsa.PrivateKey
	spLoadErr error
}

type cachedToken struct {
	value   string
	expires time.Time
}

func newGraphClient(cfg Config, log *slog.Logger, resolve AuthorityResolver) *graphClient {
	c := &graphClient{
		cfg:          cfg,
		log:          log,
		http:         &http.Client{Timeout: 30 * time.Second},
		resolve:      resolve,
		base:         defaultGraphBase,
		loginBase:    defaultLoginBase,
		exchangeBase: defaultExchangeBase,
		tokens:       map[string]cachedToken{},
	}
	c.spCert, c.spKey, c.spLoadErr = loadSharePointCertificate(cfg)
	return c
}

// tenantAuth resolves an RTM tenant id to the authority + app credentials to
// token with. Without a resolver (or when the tenant record leaves fields
// empty) it falls back to the app's home tenant / global app. A resolver error
// is propagated rather than falling back so data is never silently read from
// (or attributed to) the wrong tenant.
func (c *graphClient) tenantAuth(ctx context.Context, tenantID string) (TenantAuth, error) {
	auth := TenantAuth{
		Authority: c.cfg.TenantID, ClientID: c.cfg.ClientID, ClientSecret: c.cfg.ClientSecret,
		ExchangeClientID: c.cfg.ClientID, ExchangeClientSecret: c.cfg.ClientSecret,
	}
	if c.resolve == nil || tenantID == "" {
		return auth, nil
	}
	resolved, err := c.resolve(ctx, tenantID)
	if err != nil {
		return TenantAuth{}, fmt.Errorf("graph: resolving authority for tenant %s: %w", tenantID, err)
	}
	if resolved.Authority != "" {
		auth.Authority = resolved.Authority
	}
	// Per-tenant app credentials come as a pair; a lone client id is ignored.
	if resolved.ClientID != "" && resolved.ClientSecret != "" {
		auth.ClientID, auth.ClientSecret = resolved.ClientID, resolved.ClientSecret
	}
	if resolved.ExchangeClientID != "" && resolved.ExchangeClientSecret != "" {
		auth.ExchangeClientID, auth.ExchangeClientSecret = resolved.ExchangeClientID, resolved.ExchangeClientSecret
	}
	if auth.ExchangeClientID == "" || auth.ExchangeClientSecret == "" {
		auth.ExchangeClientID, auth.ExchangeClientSecret = auth.ClientID, auth.ClientSecret
	}
	auth.SharePointAdminURL = resolved.SharePointAdminURL
	return auth, nil
}

func (c *graphClient) Mode() string { return "graph" }

// token acquires (and caches) an app-only token via the client-credentials
// flow, one per authority + app pair so every managed tenant gets its own
// token (and, when configured, its own app registration).
func (c *graphClient) token(ctx context.Context, auth TenantAuth) (string, error) {
	return c.appToken(ctx, auth.Authority, auth.ClientID, auth.ClientSecret,
		"https://graph.microsoft.com/.default", "graph")
}

func (c *graphClient) exchangeToken(ctx context.Context, auth TenantAuth) (string, error) {
	return c.appToken(ctx, auth.Authority, auth.ExchangeClientID, auth.ExchangeClientSecret,
		"https://outlook.office365.com/.default", "exchange")
}

func tokenCacheKey(authority, clientID, scope string) string {
	return authority + "|" + clientID + "|" + scope
}

func (c *graphClient) appToken(ctx context.Context, authority, clientID, clientSecret, scope, resource string) (string, error) {
	key := tokenCacheKey(authority, clientID, scope)
	c.mu.Lock()
	if t, ok := c.tokens[key]; ok && time.Until(t.expires) > time.Minute {
		c.mu.Unlock()
		return t.value, nil
	}
	c.mu.Unlock()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {scope},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.loginBase, authority)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s token request: %w", resource, err)
	}
	defer resp.Body.Close()

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		if resource == "exchange" {
			return "", &ExchangeAPIError{Status: resp.StatusCode, Code: out.Error, Message: out.ErrorDesc, Path: "token (" + authority + ")"}
		}
		return "", &APIError{Status: resp.StatusCode, Code: out.Error, Message: out.ErrorDesc, Path: "token (" + authority + ")"}
	}

	c.mu.Lock()
	c.tokens[key] = cachedToken{value: out.AccessToken, expires: time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)}
	c.mu.Unlock()
	return out.AccessToken, nil
}

// get performs an authenticated Graph GET against the given managed tenant
// (RTM tenant id; empty means the app's home tenant) and decodes into out.
func (c *graphClient) get(ctx context.Context, tenantID, path string, out any) error {
	return c.getWithHeaders(ctx, tenantID, path, nil, out)
}

func (c *graphClient) getWithHeaders(ctx context.Context, tenantID, path string, headers map[string]string, out any) error {
	body, err := c.getBytesWithHeaders(ctx, tenantID, path, headers)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// getBytes performs an authenticated Graph GET without assuming a JSON
// response. Microsoft 365 usage reports return CSV (sometimes after a
// download redirect), while the rest of RTM's Graph reads use get above.
func (c *graphClient) getBytes(ctx context.Context, tenantID, path string) ([]byte, error) {
	return c.getBytesWithHeaders(ctx, tenantID, path, nil)
}

func (c *graphClient) getBytesWithHeaders(ctx context.Context, tenantID, path string, headers map[string]string) ([]byte, error) {
	auth, err := c.tenantAuth(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	tok, err := c.token(ctx, auth)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	const maxGraphResponseBytes = 32 << 20
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxGraphResponseBytes+1))
	if readErr != nil {
		return nil, readErr
	}
	if len(body) > maxGraphResponseBytes {
		return nil, fmt.Errorf("graph %s: response exceeded %d MiB", path, maxGraphResponseBytes>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Graph error bodies carry the reason (e.g. Authorization_RequestDenied
		// when application permissions lack admin consent) — surface it.
		var ge struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &ge)
		return nil, &APIError{Status: resp.StatusCode, Code: ge.Error.Code, Message: ge.Error.Message, Path: path}
	}
	return body, nil
}

// UserCount uses Graph's advanced-query count projection, avoiding the MFA
// enrichment and full directory payload required by Users().
func (c *graphClient) UserCount(ctx context.Context, tenantID string) (int, error) {
	var out struct {
		Count int `json:"@odata.count"`
	}
	err := c.getWithHeaders(ctx, tenantID, "/users?$count=true&$top=1&$select=id", map[string]string{
		"ConsistencyLevel": "eventual",
	}, &out)
	return out.Count, err
}

// send performs an authenticated Graph mutation (POST/DELETE) against the
// given managed tenant. Success statuses are 2xx (Graph returns 204 for both
// $ref member operations).
func (c *graphClient) send(ctx context.Context, method, tenantID, path string, body any) error {
	auth, err := c.tenantAuth(ctx, tenantID)
	if err != nil {
		return err
	}
	tok, err := c.token(ctx, auth)
	if err != nil {
		return err
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var ge struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&ge)
		return &APIError{Status: resp.StatusCode, Code: ge.Error.Code, Message: ge.Error.Message, Path: method + " " + path}
	}
	return nil
}

// postJSON performs an authenticated Graph POST and decodes its JSON answer.
// It is used for read-only Graph batches; mutations continue through send so
// their empty 204 responses do not need special handling.
func (c *graphClient) postJSON(ctx context.Context, tenantID, path string, body, out any) error {
	auth, err := c.tenantAuth(ctx, tenantID)
	if err != nil {
		return err
	}
	tok, err := c.token(ctx, auth)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	const maxGraphJSONBytes = 32 << 20
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxGraphJSONBytes+1))
	if readErr != nil {
		return readErr
	}
	if len(responseBody) > maxGraphJSONBytes {
		return fmt.Errorf("graph %s: response exceeded %d MiB", path, maxGraphJSONBytes>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var ge struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(responseBody, &ge)
		return &APIError{Status: resp.StatusCode, Code: ge.Error.Code, Message: ge.Error.Message, Path: http.MethodPost + " " + path}
	}
	return json.Unmarshal(responseBody, out)
}

// AddGroupMembers adds users to a group one $ref at a time (counts here are
// What-If-gated and small; Graph's $batch is the scale-up path).
func (c *graphClient) AddGroupMembers(ctx context.Context, tenantID, groupID string, userIDs []string) error {
	for _, uid := range userIDs {
		body := map[string]string{"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/" + uid}
		if err := c.send(ctx, http.MethodPost, tenantID, "/groups/"+groupID+"/members/$ref", body); err != nil {
			return fmt.Errorf("adding member %s: %w", uid, err)
		}
	}
	return nil
}

// RemoveGroupMembers removes users from a group (used by revert).
func (c *graphClient) RemoveGroupMembers(ctx context.Context, tenantID, groupID string, userIDs []string) error {
	for _, uid := range userIDs {
		if err := c.send(ctx, http.MethodDelete, tenantID, "/groups/"+groupID+"/members/"+uid+"/$ref", nil); err != nil {
			return fmt.Errorf("removing member %s: %w", uid, err)
		}
	}
	return nil
}

// SetAccountEnabled blocks or unblocks sign-in (PATCH /users/{id}).
func (c *graphClient) SetAccountEnabled(ctx context.Context, tenantID, userID string, enabled bool) error {
	return c.send(ctx, http.MethodPatch, tenantID, "/users/"+userID,
		map[string]bool{"accountEnabled": enabled})
}

// AssignLicense adds or removes one license SKU for a user. Microsoft rejects
// assignment for users without a usage location — that surfaces per user as
// an APIError the worker records.
func (c *graphClient) AssignLicense(ctx context.Context, tenantID, userID, skuID string, remove bool) error {
	body := map[string]any{"addLicenses": []any{}, "removeLicenses": []any{}}
	if remove {
		body["removeLicenses"] = []string{skuID}
	} else {
		body["addLicenses"] = []map[string]string{{"skuId": skuID}}
	}
	return c.send(ctx, http.MethodPost, tenantID, "/users/"+userID+"/assignLicense", body)
}

// RevokeSessions invalidates every refresh/session token for a user, forcing
// re-authentication on all devices.
func (c *graphClient) RevokeSessions(ctx context.Context, tenantID, userID string) error {
	return c.send(ctx, http.MethodPost, tenantID, "/users/"+userID+"/revokeSignInSessions", nil)
}

// ResetPassword uses the app-only user update flow. Microsoft requires the
// dedicated User-PasswordProfile.ReadWrite.All application permission (and,
// for sensitive/admin targets, an appropriate Entra directory role).
func (c *graphClient) ResetPassword(ctx context.Context, tenantID, userID, temporaryPassword string) error {
	return c.send(ctx, http.MethodPatch, tenantID, "/users/"+userID, map[string]any{
		"passwordProfile": map[string]any{
			"password":                      temporaryPassword,
			"forceChangePasswordNextSignIn": true,
		},
	})
}

// ResetMFA removes every registered non-password authentication method that
// the v1.0 API exposes. Deletions are attempted independently so one provider
// restriction (for example, a default phone method) cannot hide the others.
func (c *graphClient) ResetMFA(ctx context.Context, tenantID, userID string) error {
	var page struct {
		Value []struct {
			ID        string `json:"id"`
			ODataType string `json:"@odata.type"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/users/"+userID+"/authentication/methods", &page); err != nil {
		return fmt.Errorf("listing authentication methods: %w", err)
	}
	paths := map[string]string{
		"#microsoft.graph.emailAuthenticationMethod":                              "emailMethods",
		"#microsoft.graph.fido2AuthenticationMethod":                              "fido2Methods",
		"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":             "microsoftAuthenticatorMethods",
		"#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod": "passwordlessMicrosoftAuthenticatorMethods",
		"#microsoft.graph.phoneAuthenticationMethod":                              "phoneMethods",
		"#microsoft.graph.platformCredentialAuthenticationMethod":                 "platformCredentialMethods",
		"#microsoft.graph.softwareOathAuthenticationMethod":                       "softwareOathMethods",
		"#microsoft.graph.temporaryAccessPassAuthenticationMethod":                "temporaryAccessPassMethods",
		"#microsoft.graph.windowsHelloForBusinessAuthenticationMethod":            "windowsHelloForBusinessMethods",
	}
	var failures []error
	for _, method := range page.Value {
		collection, removable := paths[method.ODataType]
		if method.ODataType == "#microsoft.graph.passwordAuthenticationMethod" {
			continue // The newly reset password method must be retained.
		}
		if !removable || method.ID == "" {
			failures = append(failures, fmt.Errorf("unsupported authentication method %q", method.ODataType))
			continue
		}
		path := "/users/" + userID + "/authentication/" + collection + "/" + url.PathEscape(method.ID)
		if err := c.send(ctx, http.MethodDelete, tenantID, path, nil); err != nil {
			failures = append(failures, fmt.Errorf("removing %s: %w", strings.TrimPrefix(method.ODataType, "#microsoft.graph."), err))
		}
	}
	return errors.Join(failures...)
}

// CreateGroup provisions a Microsoft 365 or security group (POST /groups) and
// returns the created group. mailNickname is required by Graph for both types.
func (c *graphClient) CreateGroup(ctx context.Context, tenantID string, in NewGroup) (model.Group, error) {
	body := map[string]any{
		"displayName":     in.DisplayName,
		"description":     in.Description,
		"mailNickname":    in.MailNickname,
		"mailEnabled":     in.Type == GroupTypeM365,
		"securityEnabled": in.Type == GroupTypeSecurity,
		"groupTypes":      []string{},
	}
	if in.Type == GroupTypeM365 {
		body["groupTypes"] = []string{"Unified"}
	}
	auth, err := c.tenantAuth(ctx, tenantID)
	if err != nil {
		return model.Group{}, err
	}
	tok, err := c.token(ctx, auth)
	if err != nil {
		return model.Group{}, err
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/groups", bytes.NewReader(b))
	if err != nil {
		return model.Group{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return model.Group{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var ge struct {
			Error struct {
				Code, Message string
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&ge)
		return model.Group{}, &APIError{Status: resp.StatusCode, Code: ge.Error.Code, Message: ge.Error.Message, Path: "POST /groups"}
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return model.Group{}, err
	}
	typ := "Security"
	mail := "No"
	if in.Type == GroupTypeM365 {
		typ, mail = "M365", "Yes"
	}
	return model.Group{
		ID: out.ID, Name: in.DisplayName, Type: typ, Membership: "Assigned",
		Members: 0, Mail: mail, Source: "Cloud",
	}, nil
}

// TestConnection verifies the tenant end-to-end with a *fresh* token. The
// token cache is dropped first: consent/permission changes in Entra only show
// up on newly issued tokens, so a diagnostic retry must never reuse a token
// minted before the operator fixed the app registration.
func (c *graphClient) TestConnection(ctx context.Context, tenantID string) error {
	auth, err := c.tenantAuth(ctx, tenantID)
	if err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.tokens, tokenCacheKey(auth.Authority, auth.ClientID, "https://graph.microsoft.com/.default"))
	c.mu.Unlock()

	var out struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	return c.get(ctx, tenantID, "/organization?$select=id", &out)
}

// DirectorySyncEnabled reads the tenant-level Entra Connect flag from the
// organization object. Microsoft returns null when directory sync was never
// configured — that maps to nil (treated as cloud-only by the caller).
func (c *graphClient) DirectorySyncEnabled(ctx context.Context, tenantID string) (*bool, error) {
	var out struct {
		Value []struct {
			OnPremisesSyncEnabled *bool `json:"onPremisesSyncEnabled"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/organization?$select=onPremisesSyncEnabled", &out); err != nil {
		return nil, err
	}
	if len(out.Value) == 0 {
		return nil, nil
	}
	return out.Value[0].OnPremisesSyncEnabled, nil
}

type graphDirectoryUser struct {
	ID                         string   `json:"id"`
	DisplayName                string   `json:"displayName"`
	GivenName                  string   `json:"givenName"`
	Surname                    string   `json:"surname"`
	UserPrincipalName          string   `json:"userPrincipalName"`
	Mail                       string   `json:"mail"`
	UserType                   string   `json:"userType"`
	Department                 string   `json:"department"`
	JobTitle                   string   `json:"jobTitle"`
	CompanyName                string   `json:"companyName"`
	OfficeLocation             string   `json:"officeLocation"`
	EmployeeID                 string   `json:"employeeId"`
	EmployeeType               string   `json:"employeeType"`
	BusinessPhones             []string `json:"businessPhones"`
	MobilePhone                string   `json:"mobilePhone"`
	StreetAddress              string   `json:"streetAddress"`
	City                       string   `json:"city"`
	State                      string   `json:"state"`
	PostalCode                 string   `json:"postalCode"`
	Country                    string   `json:"country"`
	UsageLocation              string   `json:"usageLocation"`
	PreferredLanguage          string   `json:"preferredLanguage"`
	CreatedDateTime            string   `json:"createdDateTime"`
	AccountEnabled             bool     `json:"accountEnabled"`
	OnPremisesSyncEnabled      *bool    `json:"onPremisesSyncEnabled"`
	OnPremisesSAMAccountName   string   `json:"onPremisesSamAccountName"`
	OnPremisesLastSyncDateTime string   `json:"onPremisesLastSyncDateTime"`
	AssignedLicenses           []struct {
		SkuID string `json:"skuId"`
	} `json:"assignedLicenses"`
	SignInActivity *struct {
		LastSuccessfulSignInDateTime string `json:"lastSuccessfulSignInDateTime"`
		LastSignInDateTime           string `json:"lastSignInDateTime"`
	} `json:"signInActivity"`
}

const userDirectorySelect = "id,displayName,givenName,surname,userPrincipalName,mail,userType,department,jobTitle," +
	"companyName,officeLocation,employeeId,employeeType,businessPhones,mobilePhone,streetAddress,city,state," +
	"postalCode,country,usageLocation,preferredLanguage,createdDateTime,accountEnabled,onPremisesSyncEnabled," +
	"onPremisesSamAccountName,onPremisesLastSyncDateTime,assignedLicenses"

// Users pulls a column-ready directory projection and enriches it with MFA
// registration and friendly tenant SKU names. signInActivity is optional:
// tenants without Entra ID P1/P2 are retried without it so inventory remains
// usable and the response can state that the signal is unavailable.
func (c *graphClient) Users(ctx context.Context, tenantID string) ([]model.User, error) {
	rows, signInsAvailable, err := c.directoryUsers(ctx, tenantID, true)
	if err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			return nil, err
		}
		c.log.Warn("graph: user sign-in activity unavailable, listing users without it", "tenant", tenantID, "error", err)
		rows, signInsAvailable, err = c.directoryUsers(ctx, tenantID, false)
		if err != nil {
			return nil, err
		}
	}

	mfa := c.mfaStates(ctx, tenantID) // best-effort; empty on permission error
	licenseNames := map[string]string{}
	if licenses, licenseErr := c.Licenses(ctx, tenantID); licenseErr != nil {
		c.log.Warn("graph: user license names unavailable", "tenant", tenantID, "error", licenseErr)
	} else {
		for _, license := range licenses {
			licenseNames[strings.ToLower(license.SkuID)] = license.Product
		}
	}

	users := make([]model.User, 0, len(rows))
	for _, u := range rows {
		status := "Active"
		if u.UserType == "Guest" {
			status = "Guest"
		} else if !u.AccountEnabled {
			status = "Disabled"
		}
		state := mfa[u.ID]
		if state == "" {
			state = "Unknown"
		}
		source := model.SourceCloud
		if u.OnPremisesSyncEnabled != nil && *u.OnPremisesSyncEnabled {
			source = model.SourceOnPrem
		}
		assigned := make([]string, 0, len(u.AssignedLicenses))
		for _, license := range u.AssignedLicenses {
			if name := licenseNames[strings.ToLower(license.SkuID)]; name != "" {
				assigned = append(assigned, name)
			}
		}
		licenseSummary := "Unlicensed"
		if len(assigned) > 0 {
			licenseSummary = strings.Join(assigned, ", ")
		} else if count := len(u.AssignedLicenses); count > 0 {
			licenseSummary = fmt.Sprintf("%d assigned", count)
		}
		lastSignIn := ""
		if signInsAvailable && u.SignInActivity != nil {
			lastSignIn = u.SignInActivity.LastSuccessfulSignInDateTime
			if lastSignIn == "" {
				lastSignIn = u.SignInActivity.LastSignInDateTime
			}
		}
		users = append(users, model.User{
			ID: u.ID, Name: u.DisplayName, GivenName: u.GivenName, Surname: u.Surname,
			UPN: u.UserPrincipalName, Mail: u.Mail, UserType: u.UserType,
			Department: u.Department, JobTitle: u.JobTitle, CompanyName: u.CompanyName,
			OfficeLocation: u.OfficeLocation, EmployeeID: u.EmployeeID, EmployeeType: u.EmployeeType,
			BusinessPhones: u.BusinessPhones, MobilePhone: u.MobilePhone, StreetAddress: u.StreetAddress,
			City: u.City, State: u.State, PostalCode: u.PostalCode, Country: u.Country,
			UsageLocation: u.UsageLocation, PreferredLanguage: u.PreferredLanguage,
			CreatedDateTime: u.CreatedDateTime, OnPremisesSAMAccountName: u.OnPremisesSAMAccountName,
			OnPremisesLastSyncDateTime: u.OnPremisesLastSyncDateTime,
			License:                    licenseSummary, Licenses: assigned, MFA: state, Status: status,
			LastSignIn: lastSignIn, LastSignInAvailable: signInsAvailable, SourceOfAuthority: source,
		})
	}
	return users, nil
}

func (c *graphClient) directoryUsers(ctx context.Context, tenantID string, includeSignIns bool) ([]graphDirectoryUser, bool, error) {
	selectFields := userDirectorySelect
	if includeSignIns {
		selectFields += ",signInActivity"
	}
	path := "/users?$select=" + selectFields + "&$top=500"
	rows := make([]graphDirectoryUser, 0, 500)
	for path != "" {
		var page struct {
			Value    []graphDirectoryUser `json:"value"`
			NextLink string               `json:"@odata.nextLink"`
		}
		if err := c.get(ctx, tenantID, path, &page); err != nil {
			return nil, false, err
		}
		rows = append(rows, page.Value...)
		path = graphNextPath(page.NextLink)
	}
	return rows, includeSignIns, nil
}

// mfaStates maps user id → "Enabled"/"Disabled" from the authentication-methods
// registration report (needs AuditLog.Read.All). Returns empty on error so
// callers degrade gracefully.
func (c *graphClient) mfaStates(ctx context.Context, tenantID string) map[string]string {
	type mfaRow struct {
		ID              string `json:"id"`
		IsMfaRegistered bool   `json:"isMfaRegistered"`
	}
	m := map[string]string{}
	path := "/reports/authenticationMethods/userRegistrationDetails?$top=999"
	for path != "" {
		var page graphPage[mfaRow]
		if err := c.get(ctx, tenantID, path, &page); err != nil {
			c.log.Warn("graph: mfa registration report unavailable", "error", err)
			return map[string]string{}
		}
		for _, user := range page.Value {
			if user.IsMfaRegistered {
				m[user.ID] = "Enabled"
			} else {
				m[user.ID] = "Disabled"
			}
		}
		path = graphNextPath(page.NextLink)
	}
	return m
}

func (c *graphClient) Groups(ctx context.Context, tenantID string) ([]model.Group, error) {
	var out struct {
		Value []struct {
			ID                    string   `json:"id"`
			DisplayName           string   `json:"displayName"`
			MailEnabled           bool     `json:"mailEnabled"`
			SecurityEnabled       bool     `json:"securityEnabled"`
			GroupTypes            []string `json:"groupTypes"`
			OnPremisesSyncEnabled *bool    `json:"onPremisesSyncEnabled"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/groups?$select=id,displayName,mailEnabled,securityEnabled,groupTypes,onPremisesSyncEnabled&$top=200", &out); err != nil {
		return nil, err
	}
	groups := make([]model.Group, 0, len(out.Value))
	for _, g := range out.Value {
		typ := "Distribution"
		membership := "Assigned"
		for _, t := range g.GroupTypes {
			if t == "Unified" {
				typ = "M365"
			}
			if t == "DynamicMembership" {
				membership = "Dynamic"
			}
		}
		if typ == "Distribution" && g.SecurityEnabled && g.MailEnabled {
			typ = "Mail-enabled Sec."
		} else if typ == "Distribution" && g.SecurityEnabled {
			typ = "Security"
		}
		mail := "No"
		if g.MailEnabled {
			mail = "Yes"
		}
		// Groups synced from on-prem AD have their membership mastered there;
		// the write gate refuses membership changes against them.
		source := "Cloud"
		if g.OnPremisesSyncEnabled != nil && *g.OnPremisesSyncEnabled {
			source = "On-prem sync"
		}
		groups = append(groups, model.Group{
			ID: g.ID, Name: g.DisplayName, Type: typ, Membership: membership, Mail: mail, Service: "Graph", Source: source,
		})
	}
	return groups, nil
}

// GroupMembers lists a group's members and marks owners (two calls: members +
// owners). "Added" date isn't exposed on the membership edge in Graph v1.0.
func (c *graphClient) GroupMembers(ctx context.Context, tenantID, groupID string) ([]model.GroupMember, error) {
	type dirObj struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	var owners struct {
		Value []dirObj `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/groups/"+groupID+"/owners?$select=id", &owners); err != nil {
		return nil, err
	}
	isOwner := make(map[string]bool, len(owners.Value))
	for _, o := range owners.Value {
		isOwner[o.ID] = true
	}
	var members struct {
		Value []dirObj `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/groups/"+groupID+"/members?$select=id,displayName,userPrincipalName&$top=200", &members); err != nil {
		return nil, err
	}
	out := make([]model.GroupMember, 0, len(members.Value))
	for _, m := range members.Value {
		role := "Member"
		if isOwner[m.ID] {
			role = "Owner"
		}
		out = append(out, model.GroupMember{ID: m.ID, Name: m.DisplayName, UPN: m.UserPrincipalName, Role: role, Added: "—"})
	}
	return out, nil
}

// Licenses summarizes tenant subscriptions from /subscribedSkus.
func (c *graphClient) Licenses(ctx context.Context, tenantID string) ([]model.License, error) {
	var out struct {
		Value []struct {
			SkuID         string `json:"skuId"`
			SkuPartNumber string `json:"skuPartNumber"`
			ConsumedUnits int    `json:"consumedUnits"`
			PrepaidUnits  struct {
				Enabled int `json:"enabled"`
			} `json:"prepaidUnits"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/subscribedSkus", &out); err != nil {
		return nil, err
	}
	licenses := make([]model.License, 0, len(out.Value))
	for _, s := range out.Value {
		total := s.PrepaidUnits.Enabled
		avail := total - s.ConsumedUnits
		pool := "OK"
		if avail <= 0 {
			pool = "Full"
		} else if avail < 5 {
			pool = "Low"
		}
		util := 0
		if total > 0 {
			util = s.ConsumedUnits * 100 / total
		}
		licenses = append(licenses, model.License{
			SkuID: s.SkuID, SKU: s.SkuPartNumber, Product: skuProductName(s.SkuPartNumber),
			Assigned: s.ConsumedUnits, Available: avail, Total: total, Utilization: util, Pool: pool,
		})
	}
	return licenses, nil
}

type graphMailboxDirectoryUser struct {
	ID                    string   `json:"id"`
	DisplayName           string   `json:"displayName"`
	UserPrincipalName     string   `json:"userPrincipalName"`
	Mail                  string   `json:"mail"`
	AccountEnabled        bool     `json:"accountEnabled"`
	CreatedDateTime       string   `json:"createdDateTime"`
	OnPremisesSyncEnabled *bool    `json:"onPremisesSyncEnabled"`
	ProxyAddresses        []string `json:"proxyAddresses"`
	AssignedLicenses      []struct {
		SkuID string `json:"skuId"`
	} `json:"assignedLicenses"`
}

// Mailboxes uses the directory as the authoritative mailbox inventory and
// optionally enriches matching rows from Microsoft's mailbox-usage report.
// The report needs Reports.Read.All and can conceal identities; either case
// degrades to explicit unknown values rather than failing the inventory.
func (c *graphClient) Mailboxes(ctx context.Context, tenantID string) ([]model.Mailbox, error) {
	var out struct {
		Value []graphMailboxDirectoryUser `json:"value"`
	}
	path := "/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,onPremisesSyncEnabled,proxyAddresses,assignedLicenses&$top=200"
	if err := c.get(ctx, tenantID, path, &out); err != nil {
		return nil, err
	}
	usage, usageErr := c.mailboxUsage(ctx, tenantID)
	usageDetail := "Mailbox usage requires admin-consented Reports.Read.All."
	if usageErr == nil && usage.Concealed {
		usageDetail = "Microsoft 365 is concealing identities in usage reports, so RTM cannot safely match size, item count, archive, or quota data. In Microsoft 365 admin center, go to Settings → Org settings → Reports, clear 'Display concealed user, group, and site names in all reports', save, wait a few minutes, then Sync RTM."
	} else if usageErr == nil && usage.Rows == 0 {
		usageDetail = "Microsoft's mailbox usage report returned no mailbox rows yet. Usage reports can take 24–72 hours to populate."
	} else if usageErr == nil {
		usageDetail = "Microsoft's usage report did not expose a matching mailbox identity. Check the report privacy setting."
	} else {
		c.log.Warn("graph: mailbox usage enrichment unavailable", "tenant", tenantID, "error", usageErr)
	}
	purposes := c.mailboxPurposes(ctx, tenantID, out.Value)
	boxes := make([]model.Mailbox, 0, len(out.Value))
	for _, u := range out.Value {
		if u.Mail == "" {
			continue // no mailbox
		}
		aliases := make([]string, 0, len(u.ProxyAddresses))
		for _, proxy := range u.ProxyAddresses {
			if strings.HasPrefix(proxy, "smtp:") {
				aliases = append(aliases, strings.TrimPrefix(proxy, "smtp:"))
			}
		}
		source := model.SourceUnknown
		if u.OnPremisesSyncEnabled != nil {
			source = model.SourceCloud
			if *u.OnPremisesSyncEnabled {
				source = model.SourceOnPrem
			}
		}
		status := "Disabled"
		if u.AccountEnabled {
			status = "Enabled"
		}
		box := model.Mailbox{
			ID: u.ID, Name: u.DisplayName, Email: u.Mail, UserPrincipalName: u.UserPrincipalName,
			Aliases: aliases, Type: "Unknown", AccountStatus: status, SourceOfAuthority: source,
			CreatedAt: u.CreatedDateTime, LicenseCount: len(u.AssignedLicenses), Size: "—",
			Archive: "—", LitigationHold: "—", UsageDetail: usageDetail,
		}
		if purposeType := mailboxTypeFromPurpose(purposes[u.ID]); purposeType != "" {
			box.Type = purposeType
		}
		if report, ok := usage.ByUPN[strings.ToLower(u.UserPrincipalName)]; ok {
			report.apply(&box)
		} else if report, ok := usage.ByUPN[strings.ToLower(u.Mail)]; ok {
			report.apply(&box)
		} else {
			for _, alias := range aliases {
				if report, ok := usage.ByUPN[strings.ToLower(alias)]; ok {
					report.apply(&box)
					break
				}
			}
		}
		boxes = append(boxes, box)
	}
	return boxes, nil
}

// mailboxPurposes uses Graph JSON batching so mailbox type remains accurate
// even when the tenant conceals identities in usage reports.
// Microsoft allows at most 20 requests per batch.
func (c *graphClient) mailboxPurposes(ctx context.Context, tenantID string, users []graphMailboxDirectoryUser) map[string]string {
	result := make(map[string]string, len(users))
	for start := 0; start < len(users); start += 20 {
		end := min(start+20, len(users))
		requests := make([]map[string]string, 0, end-start)
		requestToUser := make(map[string]string, end-start)
		for i, user := range users[start:end] {
			if user.ID == "" || user.Mail == "" {
				continue
			}
			requestID := strconv.Itoa(i)
			requestToUser[requestID] = user.ID
			requests = append(requests, map[string]string{
				"id": requestID, "method": http.MethodGet,
				"url": "/users/" + url.PathEscape(user.ID) + "/mailboxSettings?$select=userPurpose",
			})
		}
		if len(requests) == 0 {
			continue
		}
		var response struct {
			Responses []struct {
				ID     string `json:"id"`
				Status int    `json:"status"`
				Body   struct {
					UserPurpose string `json:"userPurpose"`
				} `json:"body"`
			} `json:"responses"`
		}
		if err := c.postJSON(ctx, tenantID, "/$batch", map[string]any{"requests": requests}, &response); err != nil {
			c.log.Warn("graph: mailbox purpose enrichment unavailable", "tenant", tenantID, "error", err)
			return result
		}
		for _, item := range response.Responses {
			if item.Status >= 200 && item.Status <= 299 && item.Body.UserPurpose != "" {
				result[requestToUser[item.ID]] = item.Body.UserPurpose
			}
		}
	}
	return result
}

func mailboxTypeFromPurpose(value string) string {
	switch strings.ToLower(value) {
	case "user", "linked":
		return "User"
	case "shared":
		return "Shared"
	case "room":
		return "Room"
	case "equipment":
		return "Equipment"
	default:
		return ""
	}
}

type mailboxUsageRow struct {
	RefreshDate, LastActivityDate, Size, DeletedSize, WarningQuota, SendQuota, SendReceiveQuota, Archive, MailboxType string
	Items, DeletedItems                                                                                               int
}

type mailboxUsageResult struct {
	ByUPN     map[string]mailboxUsageRow
	Rows      int
	Concealed bool
}

func (u mailboxUsageRow) apply(box *model.Mailbox) {
	box.UsageAvailable = true
	box.UsageAsOf = u.RefreshDate
	box.LastActivityAt = u.LastActivityDate
	box.Size = u.Size
	box.Items = u.Items
	box.DeletedItems = u.DeletedItems
	box.DeletedSize = u.DeletedSize
	box.WarningQuota = u.WarningQuota
	box.SendQuota = u.SendQuota
	box.SendReceiveQuota = u.SendReceiveQuota
	box.Archive = u.Archive
	if u.MailboxType != "" {
		box.Type = u.MailboxType
	}
	box.UsageDetail = "Mailbox usage report matched this directory identity."
}

func (c *graphClient) mailboxUsage(ctx context.Context, tenantID string) (mailboxUsageResult, error) {
	const path = "/reports/getMailboxUsageDetail(period='D7')"
	body, err := c.getBytes(ctx, tenantID, path)
	if err != nil {
		return mailboxUsageResult{}, err
	}
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil {
		return mailboxUsageResult{}, fmt.Errorf("parsing mailbox usage report: %w", err)
	}
	if len(rows) == 0 {
		return mailboxUsageResult{ByUPN: map[string]mailboxUsageRow{}}, nil
	}
	headers := make(map[string]int, len(rows[0]))
	for i, header := range rows[0] {
		headers[strings.TrimSpace(strings.TrimPrefix(header, "\ufeff"))] = i
	}
	value := func(row []string, name string) string {
		if i, ok := headers[name]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	result := mailboxUsageResult{ByUPN: make(map[string]mailboxUsageRow, len(rows)-1)}
	concealedIdentities := 0
	for _, row := range rows[1:] {
		upn := strings.ToLower(value(row, "User Principal Name"))
		if upn == "" {
			continue
		}
		result.Rows++
		if !strings.Contains(upn, "@") {
			concealedIdentities++
		}
		result.ByUPN[upn] = mailboxUsageRow{
			RefreshDate: value(row, "Report Refresh Date"), LastActivityDate: value(row, "Last Activity Date"),
			Size: reportBytes(value(row, "Storage Used (Byte)")), Items: intValue(value(row, "Item Count")),
			DeletedItems: intValue(value(row, "Deleted Item Count")), DeletedSize: reportBytes(value(row, "Deleted Item Size (Byte)")),
			WarningQuota: reportBytes(value(row, "Issue Warning Quota (Byte)")), SendQuota: reportBytes(value(row, "Prohibit Send Quota (Byte)")),
			SendReceiveQuota: reportBytes(value(row, "Prohibit Send/Receive Quota (Byte)")), Archive: yesNoToOnOff(value(row, "Has Archive")),
			MailboxType: mailboxTypeFromReport(value(row, "Recipient Type")),
		}
	}
	result.Concealed = result.Rows > 0 && concealedIdentities == result.Rows
	return result, nil
}

func mailboxTypeFromReport(value string) string {
	switch strings.ToLower(value) {
	case "usermailbox", "user":
		return "User"
	case "sharedmailbox", "shared":
		return "Shared"
	case "roommailbox", "room":
		return "Room"
	case "equipmentmailbox", "equipment":
		return "Equipment"
	default:
		return ""
	}
}

func intValue(value string) int {
	v, _ := strconv.ParseInt(value, 10, 64)
	return int(v)
}

func reportBytes(value string) string {
	bytes, err := strconv.ParseFloat(value, 64)
	if err != nil || bytes < 0 {
		return "—"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for bytes >= 1024 && i < len(units)-1 {
		bytes /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", bytes, units[i])
	}
	return fmt.Sprintf("%.1f %s", bytes, units[i])
}

func yesNoToOnOff(value string) string {
	if strings.EqualFold(value, "true") || strings.EqualFold(value, "yes") {
		return "On"
	}
	if strings.EqualFold(value, "false") || strings.EqualFold(value, "no") {
		return "Off"
	}
	return "—"
}

// Sites lists SharePoint sites via Graph search. Storage/file counts and
// external-sharing state require SharePoint REST (per the Graph guide) and are
// marked "—" here.
func (c *graphClient) Sites(ctx context.Context, tenantID string) ([]model.Site, error) {
	var out struct {
		Value []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
			WebURL      string `json:"webUrl"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/sites?search=*", &out); err != nil {
		return nil, err
	}
	sites := make([]model.Site, 0, len(out.Value))
	for i, s := range out.Value {
		name := s.DisplayName
		if name == "" {
			name = s.Name
		}
		// Keep Graph's composite site id so SitePermissions can address the
		// site directly.
		id := s.ID
		if id == "" {
			id = fmt.Sprintf("site_%d", i+1)
		}
		sites = append(sites, model.Site{
			ID: id, Name: name, URL: s.WebURL,
			Template: "—", Storage: "—", Files: 0, ExternalSharing: "—",
		})
	}
	return sites, nil
}

// rtmForwardRule names the RTM-managed forwarding inbox rule so reads and
// clears always address the rule RTM created (never a user's own rules).
const rtmForwardRule = "RTM Managed Forwarding"

type messageRecipient struct {
	EmailAddress struct {
		Address string `json:"address"`
	} `json:"emailAddress"`
}

// messageRule is the forwarding-relevant subset of Graph's messageRule.
type messageRule struct {
	ID          string `json:"id,omitempty"`
	DisplayName string `json:"displayName"`
	Sequence    int    `json:"sequence,omitempty"`
	IsEnabled   bool   `json:"isEnabled"`
	HasError    bool   `json:"hasError"`
	IsReadOnly  bool   `json:"isReadOnly"`
	Actions     struct {
		ForwardTo             []messageRecipient `json:"forwardTo"`
		RedirectTo            []messageRecipient `json:"redirectTo"`
		ForwardAsAttachmentTo []messageRecipient `json:"forwardAsAttachmentTo"`
		StopProcessingRules   bool               `json:"stopProcessingRules"`
	} `json:"actions"`
}

func (c *graphClient) listMessageRules(ctx context.Context, tenantID, mailboxID string) ([]messageRule, error) {
	var out struct {
		Value []messageRule `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/users/"+url.PathEscape(mailboxID)+"/mailFolders/inbox/messageRules", &out); err != nil {
		return nil, err
	}
	return out.Value, nil
}

// forwardingRule finds the RTM-managed forwarding rule on a mailbox ("" id =
// none). Needs MailboxSettings.Read.
func (c *graphClient) forwardingRule(ctx context.Context, tenantID, mailboxID string) (ruleID, forwardTo string, err error) {
	rules, err := c.listMessageRules(ctx, tenantID, mailboxID)
	if err != nil {
		return "", "", err
	}
	for _, r := range rules {
		if r.DisplayName == rtmForwardRule && len(r.Actions.ForwardTo) > 0 {
			return r.ID, r.Actions.ForwardTo[0].EmailAddress.Address, nil
		}
	}
	return "", "", nil
}

// MailboxSettings reads auto-reply state (GET mailboxSettings) plus the
// RTM-managed forwarding rule. Forwarding read failures degrade to "" rather
// than failing the whole detail view (the rules endpoint needs a mailbox that
// is provisioned and licensed).
func (c *graphClient) MailboxSettings(ctx context.Context, tenantID, mailboxID string) (model.MailboxSettings, error) {
	var out struct {
		TimeZone string `json:"timeZone"`
		Language struct {
			Locale      string `json:"locale"`
			DisplayName string `json:"displayName"`
		} `json:"language"`
		DateFormat   string `json:"dateFormat"`
		TimeFormat   string `json:"timeFormat"`
		WorkingHours struct {
			DaysOfWeek []string `json:"daysOfWeek"`
			StartTime  string   `json:"startTime"`
			EndTime    string   `json:"endTime"`
			TimeZone   struct {
				Name string `json:"name"`
			} `json:"timeZone"`
		} `json:"workingHours"`
		UserPurpose                           string `json:"userPurpose"`
		DelegateMeetingMessageDeliveryOptions string `json:"delegateMeetingMessageDeliveryOptions"`
		AutomaticReplies                      struct {
			Status           string `json:"status"` // disabled | alwaysEnabled | scheduled
			InternalMessage  string `json:"internalReplyMessage"`
			ExternalMessage  string `json:"externalReplyMessage"`
			ExternalAudience string `json:"externalAudience"`
			ScheduledStart   struct {
				DateTime string `json:"dateTime"`
				TimeZone string `json:"timeZone"`
			} `json:"scheduledStartDateTime"`
			ScheduledEnd struct {
				DateTime string `json:"dateTime"`
				TimeZone string `json:"timeZone"`
			} `json:"scheduledEndDateTime"`
		} `json:"automaticRepliesSetting"`
	}
	if err := c.get(ctx, tenantID, "/users/"+url.PathEscape(mailboxID)+"/mailboxSettings", &out); err != nil {
		return model.MailboxSettings{}, err
	}
	settings := model.MailboxSettings{
		MailboxID: mailboxID, AutoReply: out.AutomaticReplies.Status != "" && out.AutomaticReplies.Status != "disabled",
		AutoReplyStatus: out.AutomaticReplies.Status, AutoReplyMessage: out.AutomaticReplies.InternalMessage,
		ExternalAutoReplyMessage: out.AutomaticReplies.ExternalMessage, ExternalAudience: out.AutomaticReplies.ExternalAudience,
		AutoReplyStart: out.AutomaticReplies.ScheduledStart.DateTime, AutoReplyEnd: out.AutomaticReplies.ScheduledEnd.DateTime,
		TimeZone: out.TimeZone, Language: out.Language.DisplayName, DateFormat: out.DateFormat, TimeFormat: out.TimeFormat,
		WorkingDays: out.WorkingHours.DaysOfWeek, WorkingHoursStart: out.WorkingHours.StartTime,
		WorkingHoursEnd: out.WorkingHours.EndTime, WorkingHoursTimeZone: out.WorkingHours.TimeZone.Name,
		UserPurpose: out.UserPurpose, DelegateMeetingMessageDelivery: out.DelegateMeetingMessageDeliveryOptions,
		ForwardingRules: []model.MailboxForwardingRule{},
	}
	if rules, err := c.listMessageRules(ctx, tenantID, mailboxID); err == nil {
		settings.RulesAvailable = true
		for _, rule := range rules {
			for _, action := range []struct {
				mode       string
				recipients []messageRecipient
			}{{"Forward", rule.Actions.ForwardTo}, {"Redirect", rule.Actions.RedirectTo}, {"Forward as attachment", rule.Actions.ForwardAsAttachmentTo}} {
				if len(action.recipients) == 0 {
					continue
				}
				recipients := make([]string, 0, len(action.recipients))
				for _, recipient := range action.recipients {
					if recipient.EmailAddress.Address != "" {
						recipients = append(recipients, recipient.EmailAddress.Address)
					}
				}
				settings.ForwardingRules = append(settings.ForwardingRules, model.MailboxForwardingRule{
					ID: rule.ID, Name: rule.DisplayName, Enabled: rule.IsEnabled, HasError: rule.HasError,
					ReadOnly: rule.IsReadOnly, Mode: action.mode, Recipients: recipients, ManagedByRTM: rule.DisplayName == rtmForwardRule,
				})
				if rule.DisplayName == rtmForwardRule && action.mode == "Forward" && len(recipients) > 0 {
					settings.ForwardingTo = recipients[0]
				}
			}
		}
	} else {
		settings.RulesDetail = "Inbox rules could not be read for this mailbox. No forwarding conclusion was made."
		c.log.Warn("graph: forwarding rule read failed", "mailbox", mailboxID, "error", err)
	}
	return settings, nil
}

// SetMailboxForwarding creates (or clears) the RTM-managed forwarding inbox
// rule. Needs MailboxSettings.ReadWrite. An empty forwardTo deletes the rule.
func (c *graphClient) SetMailboxForwarding(ctx context.Context, tenantID, mailboxID, forwardTo string) error {
	ruleID, _, err := c.forwardingRule(ctx, tenantID, mailboxID)
	if err != nil {
		return err
	}
	base := "/users/" + url.PathEscape(mailboxID) + "/mailFolders/inbox/messageRules"
	if ruleID != "" {
		if err := c.send(ctx, http.MethodDelete, tenantID, base+"/"+ruleID, nil); err != nil {
			return err
		}
	}
	if forwardTo == "" {
		return nil
	}
	rule := map[string]any{
		"displayName": rtmForwardRule,
		"sequence":    1,
		"isEnabled":   true,
		"actions": map[string]any{
			"forwardTo": []map[string]any{
				{"emailAddress": map[string]string{"address": forwardTo}},
			},
			"stopProcessingRules": false,
		},
	}
	return c.send(ctx, http.MethodPost, tenantID, base, rule)
}

// SetAutoReply enables or disables automatic replies (PATCH mailboxSettings;
// MailboxSettings.ReadWrite). The message is used for internal and external
// senders alike — RTM v1 doesn't split the two audiences.
func (c *graphClient) SetAutoReply(ctx context.Context, tenantID, mailboxID string, enabled bool, message string) error {
	status := "disabled"
	if enabled {
		status = "alwaysEnabled"
	}
	body := map[string]any{
		"automaticRepliesSetting": map[string]any{
			"status":               status,
			"internalReplyMessage": message,
			"externalReplyMessage": message,
		},
	}
	return c.send(ctx, http.MethodPatch, tenantID, "/users/"+url.PathEscape(mailboxID)+"/mailboxSettings", body)
}

// SitePermissions lists the site's permission grants (GET /sites/{id}/
// permissions; Sites.Read.All). Graph exposes app grants and sharing-link
// grants here; site-group membership detail needs SharePoint REST.
func (c *graphClient) SitePermissions(ctx context.Context, tenantID, siteID string) ([]model.SitePermission, error) {
	var out struct {
		Value []struct {
			ID                  string   `json:"id"`
			Roles               []string `json:"roles"`
			GrantedToIdentities []struct {
				Application struct {
					DisplayName string `json:"displayName"`
					ID          string `json:"id"`
				} `json:"application"`
				User struct {
					DisplayName string `json:"displayName"`
					Email       string `json:"email"`
				} `json:"user"`
			} `json:"grantedToIdentitiesV2"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/sites/"+url.PathEscape(siteID)+"/permissions", &out); err != nil {
		return nil, err
	}
	perms := make([]model.SitePermission, 0, len(out.Value))
	for _, p := range out.Value {
		role := SiteRoleRead
		for _, r := range p.Roles {
			switch r {
			case "write":
				role = SiteRoleEdit
			case "fullControl", "owner":
				role = SiteRoleFullControl
			}
		}
		for _, g := range p.GrantedToIdentities {
			switch {
			case g.User.DisplayName != "" || g.User.Email != "":
				perms = append(perms, model.SitePermission{
					ID: p.ID, Principal: g.User.DisplayName, PrincipalUPN: g.User.Email,
					Type: "User", Role: role, Source: "Direct",
				})
			case g.Application.DisplayName != "":
				perms = append(perms, model.SitePermission{
					ID: p.ID, Principal: g.Application.DisplayName, PrincipalUPN: g.Application.ID,
					Type: "App", Role: role, Source: "Direct",
				})
			}
		}
	}
	return perms, nil
}

// SetSiteAccess: Graph's POST /sites/{id}/permissions only grants to
// applications; user-level grants need SharePoint REST (guide → SharePoint
// coverage).
func (c *graphClient) SetSiteAccess(context.Context, string, string, string, string, bool) error {
	return ErrSharePointOnly
}

// SetSiteSharing: per-site sharing capability is a SharePoint admin setting
// with no Graph write surface.
func (c *graphClient) SetSiteSharing(context.Context, string, string, string) error {
	return ErrSharePointOnly
}

// GlobalReport builds a single-tenant report for the app's home tenant (an
// empty tenant id skips the authority resolver). Cross-tenant fan-out over the
// managed-tenant list lives in internal/reports, which the API serves; this
// remains the per-tenant fallback behind the Provider interface.
func (c *graphClient) GlobalReport(ctx context.Context, reportType string) (model.GlobalReport, error) {
	tenant := c.cfg.TenantID
	switch reportType {
	case "license":
		lics, err := c.Licenses(ctx, "")
		if err != nil {
			return model.GlobalReport{}, err
		}
		rep := model.GlobalReport{Columns: []string{"Tenant", "SKU", "Product", "Assigned", "Total", "Utilization"}}
		for _, l := range lics {
			rep.Rows = append(rep.Rows, []model.GlobalReportCell{
				{Text: tenant}, {Text: l.SKU}, {Text: l.Product},
				{Text: strconv.Itoa(l.Assigned)}, {Text: strconv.Itoa(l.Total)}, {Text: strconv.Itoa(l.Utilization) + "%"},
			})
		}
		return rep, nil
	default: // "mfa", "inactive", "guests" — all derive from the directory
		users, err := c.Users(ctx, "")
		if err != nil {
			return model.GlobalReport{}, err
		}
		rep := model.GlobalReport{Columns: []string{"Tenant", "Display Name", "UPN", "MFA State", "Status", "Last Sign-in"}}
		for _, u := range users {
			if reportType == "guests" && u.Status != "Guest" {
				continue
			}
			mfaTone := "danger"
			if u.MFA == "Enabled" || u.MFA == "Enforced" {
				mfaTone = "success"
			}
			rep.Rows = append(rep.Rows, []model.GlobalReportCell{
				{Text: tenant}, {Text: u.Name}, {Text: u.UPN},
				{Badge: u.MFA, Tone: mfaTone}, {Text: u.Status}, {Text: u.LastSignIn},
			})
		}
		return rep, nil
	}
}

// skuProductName maps common SKU part numbers to friendly names.
func skuProductName(part string) string {
	names := map[string]string{
		"SPE_E5":              "Microsoft 365 E5",
		"SPE_E3":              "Microsoft 365 E3",
		"ENTERPRISEPACK":      "Office 365 E3",
		"ENTERPRISEPREMIUM":   "Office 365 E5",
		"EMSPREMIUM":          "Enterprise Mobility + Security E5",
		"EMS":                 "Enterprise Mobility + Security E3",
		"POWER_BI_PRO":        "Power BI Pro",
		"PROJECTPROFESSIONAL": "Project Plan 3",
		"VISIOCLIENT":         "Visio Plan 2",
		"MCOEV":               "Teams Phone Standard",
	}
	if n, ok := names[part]; ok {
		return n
	}
	// Microsoft adds SKU part numbers regularly. Preserve their wording while
	// removing identifier punctuation so new products remain readable before
	// RTM's curated map catches up.
	return strings.ReplaceAll(part, "_", " ")
}

// humanBytes renders a byte count as GB/MB (mailbox sizes).
func humanBytes(b int64) string {
	const gb = 1 << 30
	const mb = 1 << 20
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/gb)
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/mb)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
