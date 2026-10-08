package graph

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rarity/rtm/internal/model"
)

type SharePointCertificateStatus struct {
	Configured   bool   `json:"configured"`
	ClientID     string `json:"clientId,omitempty"`
	Thumbprint   string `json:"thumbprint,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
	DaysToExpiry int    `json:"daysToExpiry,omitempty"`
	Error        string `json:"error,omitempty"`
}

type SharePointCertificateReporter interface {
	SharePointCertificateStatus() SharePointCertificateStatus
}

type SharePointPreflightProvider interface {
	SharePointPreflight(ctx context.Context, tenantID string) []model.PreflightCheck
}

func loadSharePointCertificate(cfg Config) (*x509.Certificate, *rsa.PrivateKey, error) {
	if cfg.SharePointClientID == "" && cfg.SharePointCertificatePath == "" && cfg.SharePointPrivateKeyPath == "" {
		return nil, nil, nil
	}
	if cfg.SharePointClientID == "" || cfg.SharePointCertificatePath == "" || cfg.SharePointPrivateKeyPath == "" {
		return nil, nil, errors.New("incomplete SharePoint certificate configuration")
	}
	certBytes, err := os.ReadFile(cfg.SharePointCertificatePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read SharePoint certificate: %w", err)
	}
	if block, _ := pem.Decode(certBytes); block != nil {
		certBytes = block.Bytes
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse SharePoint certificate: %w", err)
	}
	keyBytes, err := os.ReadFile(cfg.SharePointPrivateKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read SharePoint private key: %w", err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, nil, errors.New("parse SharePoint private key: PEM block not found")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("SharePoint private key is not RSA")
			}
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse SharePoint private key: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.N) != 0 || pub.E != key.E {
		return nil, nil, errors.New("SharePoint certificate and private key do not match")
	}
	return cert, key, nil
}

func (c *graphClient) sharePointConfigured() bool {
	return c.cfg.SharePointClientID != "" && c.spCert != nil && c.spKey != nil && c.spLoadErr == nil
}

func (c *graphClient) SharePointCertificateStatus() SharePointCertificateStatus {
	status := SharePointCertificateStatus{ClientID: c.cfg.SharePointClientID}
	if c.spLoadErr != nil {
		status.Error = c.spLoadErr.Error()
		return status
	}
	if !c.sharePointConfigured() {
		return status
	}
	sum := sha1.Sum(c.spCert.Raw)
	status.Configured = true
	status.Thumbprint = strings.ToUpper(hex.EncodeToString(sum[:]))
	status.ExpiresAt = c.spCert.NotAfter.UTC().Format(time.RFC3339)
	status.DaysToExpiry = int(time.Until(c.spCert.NotAfter).Hours() / 24)
	return status
}

func (c *graphClient) sharePointAssertion(authority string) (string, error) {
	now := time.Now().UTC()
	audience := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.loginBase, authority)
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": audience,
		"iss": c.cfg.SharePointClientID,
		"sub": c.cfg.SharePointClientID,
		"jti": base64.RawURLEncoding.EncodeToString(jtiBytes),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	sum := sha1.Sum(c.spCert.Raw)
	token.Header["x5t"] = base64.RawURLEncoding.EncodeToString(sum[:])
	return token.SignedString(c.spKey)
}

func (c *graphClient) sharePointToken(ctx context.Context, tenantID, resource string) (string, error) {
	if c.spLoadErr != nil {
		return "", c.spLoadErr
	}
	if !c.sharePointConfigured() {
		return "", ErrSharePointOnly
	}
	auth, err := c.tenantAuth(ctx, tenantID)
	if err != nil {
		return "", err
	}
	key := "sp|" + auth.Authority + "|" + resource + "|" + c.cfg.SharePointClientID
	c.mu.Lock()
	if token, ok := c.tokens[key]; ok && time.Until(token.expires) > time.Minute {
		c.mu.Unlock()
		return token.value, nil
	}
	c.mu.Unlock()
	assertion, err := c.sharePointAssertion(auth.Authority)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"client_id":             {c.cfg.SharePointClientID},
		"scope":                 {strings.TrimSuffix(resource, "/") + "/.default"},
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.loginBase, auth.Authority)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("sharepoint token request: %w", err)
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
		return "", &APIError{Status: resp.StatusCode, Code: out.Error, Message: out.ErrorDesc, Path: "sharepoint token (" + auth.Authority + ")"}
	}
	c.mu.Lock()
	c.tokens[key] = cachedToken{value: out.AccessToken, expires: time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)}
	c.mu.Unlock()
	return out.AccessToken, nil
}

func (c *graphClient) certificateGet(ctx context.Context, tenantID, resource, endpoint string, out any) error {
	token, err := c.sharePointToken(ctx, tenantID, resource)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json;odata=nometadata")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message any    `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		message := ""
		switch value := body.Error.Message.(type) {
		case string:
			message = value
		case map[string]any:
			message, _ = value["value"].(string)
		}
		return &APIError{Status: resp.StatusCode, Code: body.Error.Code, Message: message, Path: endpoint}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *graphClient) certificateSend(ctx context.Context, tenantID, resource, method, endpoint string, body any, out any) error {
	token, err := c.sharePointToken(ctx, tenantID, resource)
	if err != nil {
		return err
	}
	var payload *bytes.Reader
	if body == nil {
		payload = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json;odata=nometadata")
	req.Header.Set("Content-Type", "application/json;odata=nometadata")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var errBody struct {
			Error struct {
				Code    string `json:"code"`
				Message any    `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		message := ""
		switch value := errBody.Error.Message.(type) {
		case string:
			message = value
		case map[string]any:
			message, _ = value["value"].(string)
		}
		return &APIError{Status: resp.StatusCode, Code: errBody.Error.Code, Message: message, Path: endpoint}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *graphClient) sharePointGraphGet(ctx context.Context, tenantID, path string, out any) error {
	if !c.sharePointConfigured() {
		return c.get(ctx, tenantID, path, out)
	}
	return c.certificateGet(ctx, tenantID, "https://graph.microsoft.com", c.base+path, out)
}

func (c *graphClient) SharePointPreflight(ctx context.Context, tenantID string) []model.PreflightCheck {
	status := c.SharePointCertificateStatus()
	certCheck := model.PreflightCheck{
		Area: "SharePoint certificate", Resource: "SharePoint Online",
		Permission: "Certificate credential", Status: "ok",
	}
	switch {
	case status.Error != "":
		certCheck.Status, certCheck.Detail = "error", status.Error
	case !status.Configured:
		certCheck.Status = "missing"
		certCheck.Detail = "Configure RTM_SHAREPOINT_CLIENT_ID, RTM_SHAREPOINT_CERTIFICATE_PATH, and RTM_SHAREPOINT_PRIVATE_KEY_PATH."
	default:
		certCheck.Detail = fmt.Sprintf("Thumbprint %s; expires %s (%d days).", status.Thumbprint, status.ExpiresAt, status.DaysToExpiry)
	}
	checks := []model.PreflightCheck{certCheck}
	if !status.Configured {
		return checks
	}
	graphToken, graphRoleErr := c.sharePointToken(ctx, tenantID, "https://graph.microsoft.com")
	graphRoles := map[string]struct{}{}
	if graphRoleErr == nil {
		graphRoles, graphRoleErr = tokenRoleSet(graphToken)
	}
	for _, probe := range []struct {
		area, permission, path string
	}{
		{"SharePoint workspace — sites", "Sites.Read.All", "/sites/getAllSites?$top=1"},
		{"SharePoint workspace — users and guests", "User.Read.All", "/users?$select=id&$top=1"},
		{"SharePoint workspace — group expansion", "GroupMember.Read.All", "/groups?$select=id&$top=1"},
	} {
		check := model.PreflightCheck{Area: probe.area, Resource: "Microsoft Graph", Permission: probe.permission, Status: "ok"}
		if graphRoleErr == nil {
			_, check.GrantedVia = resolveEffectiveGrant(resourceMicrosoftGraph, probe.permission, graphRoles)
		}
		var out map[string]any
		if err := c.sharePointGraphGet(ctx, tenantID, probe.path, &out); err != nil {
			check.Status, check.Detail = preflightError(err, probe.permission)
		}
		checks = append(checks, check)
	}
	graphWrite := model.PreflightCheck{
		Area: "SharePoint drive-item permission management", Resource: "Microsoft Graph",
		Permission: "Sites.ReadWrite.All",
	}
	if graphRoleErr != nil {
		graphWrite.Status, graphWrite.Detail = "error", "RTM could not inspect the central app's Graph token roles: "+graphRoleErr.Error()
	} else {
		graphWrite.Status, graphWrite.GrantedVia = resolveEffectiveGrant(resourceMicrosoftGraph, graphWrite.Permission, graphRoles)
		if graphWrite.Status == "missing" {
			graphWrite.Detail = "The central certificate app does not have this Microsoft Graph permission."
		}
	}
	checks = append(checks, graphWrite)
	auth, err := c.tenantAuth(ctx, tenantID)
	adminCheck := model.PreflightCheck{
		Area: "SharePoint role assignments and inheritance", Resource: "SharePoint Online",
		Permission: "Sites.FullControl.All", Status: "ok",
	}
	switch {
	case err != nil:
		adminCheck.Status, adminCheck.Detail = "error", err.Error()
	case auth.SharePointAdminURL == "":
		adminCheck.Status = "missing"
		adminCheck.Detail = "Add the tenant's SharePoint admin URL (for example, https://contoso-admin.sharepoint.com)."
	default:
		resource, parseErr := sharePointResource(auth.SharePointAdminURL)
		if parseErr != nil {
			adminCheck.Status, adminCheck.Detail = "error", parseErr.Error()
			break
		}
		resourceToken, tokenErr := c.sharePointToken(ctx, tenantID, resource)
		if tokenErr != nil {
			adminCheck.Status, adminCheck.Detail = "error", tokenErr.Error()
			break
		}
		roles, rolesErr := tokenRoleSet(resourceToken)
		if rolesErr != nil {
			adminCheck.Status, adminCheck.Detail = "error", rolesErr.Error()
			break
		}
		adminCheck.Status, adminCheck.GrantedVia = resolveEffectiveGrant(resourceSharePointOnline, adminCheck.Permission, roles)
		if adminCheck.Status == "missing" {
			adminCheck.Detail = "The central certificate app does not have Sites.FullControl.All on SharePoint Online."
			break
		}
		var out map[string]any
		if probeErr := c.certificateGet(ctx, tenantID, resource, strings.TrimSuffix(auth.SharePointAdminURL, "/")+"/_api/web?$select=Title", &out); probeErr != nil {
			adminCheck.Status, adminCheck.Detail = preflightError(probeErr, adminCheck.Permission)
		}
	}
	checks = append(checks, adminCheck)
	return checks
}

func preflightError(err error, permission string) (string, string) {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden {
		return "missing", "Microsoft denied the probe; grant admin consent for " + permission + ". " + apiErr.Message
	}
	return "error", err.Error()
}
