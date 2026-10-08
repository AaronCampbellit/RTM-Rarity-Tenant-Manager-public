package m365audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rarity/rtm/internal/model"
)

const (
	defaultActivityBase = "https://manage.office.com"
	defaultGraphBase    = "https://graph.microsoft.com/v1.0"
	defaultLoginBase    = "https://login.microsoftonline.com"
)

type cachedToken struct {
	value   string
	expires time.Time
}

type client struct {
	cfg       Config
	log       *slog.Logger
	resolve   AuthResolver
	http      *http.Client
	base      string
	graphBase string
	loginBase string
	mu        sync.Mutex
	tokens    map[string]cachedToken
}

func newClient(cfg Config, log *slog.Logger, resolve AuthResolver) *client {
	return &client{
		cfg: cfg, log: log, resolve: resolve,
		http: &http.Client{Timeout: 45 * time.Second},
		base: defaultActivityBase, graphBase: defaultGraphBase, loginBase: defaultLoginBase,
		tokens: map[string]cachedToken{},
	}
}

func (c *client) graphToken(ctx context.Context, auth Auth) (string, error) {
	key := "graph|" + auth.Authority + "|" + auth.ClientID
	c.mu.Lock()
	if tok, ok := c.tokens[key]; ok && time.Until(tok.expires) > time.Minute {
		c.mu.Unlock()
		return tok.value, nil
	}
	c.mu.Unlock()
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {auth.ClientID},
		"client_secret": {auth.ClientSecret}, "scope": {"https://graph.microsoft.com/.default"},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.loginBase, url.PathEscape(auth.Authority))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("graph audit token request: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", &APIError{Status: resp.StatusCode, Code: out.Error, Message: out.ErrorDesc, Path: "graph token"}
	}
	c.mu.Lock()
	c.tokens[key] = cachedToken{value: out.AccessToken, expires: time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)}
	c.mu.Unlock()
	return out.AccessToken, nil
}

func (c *client) auth(ctx context.Context, tenantID string) (Auth, error) {
	auth := Auth{Authority: c.cfg.TenantID, ClientID: c.cfg.ClientID, ClientSecret: c.cfg.ClientSecret}
	if c.resolve != nil {
		resolved, err := c.resolve(ctx, tenantID)
		if err != nil {
			return Auth{}, err
		}
		if resolved.Authority != "" {
			auth.Authority = resolved.Authority
		}
		if resolved.ClientID != "" && resolved.ClientSecret != "" {
			auth.ClientID, auth.ClientSecret = resolved.ClientID, resolved.ClientSecret
		}
	}
	if auth.Authority == "" || auth.ClientID == "" || auth.ClientSecret == "" {
		return Auth{}, ErrNotConfigured
	}
	return auth, nil
}

func (c *client) Mode(ctx context.Context, tenantID string) (string, error) {
	_, err := c.auth(ctx, tenantID)
	if errorsIsNotConfigured(err) {
		return ModeSample, nil
	}
	if err != nil {
		return "", err
	}
	return ModeLive, nil
}

func errorsIsNotConfigured(err error) bool { return err == ErrNotConfigured }

func (c *client) token(ctx context.Context, auth Auth) (string, error) {
	key := auth.Authority + "|" + auth.ClientID
	c.mu.Lock()
	if tok, ok := c.tokens[key]; ok && time.Until(tok.expires) > time.Minute {
		c.mu.Unlock()
		return tok.value, nil
	}
	c.mu.Unlock()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {auth.ClientID},
		"client_secret": {auth.ClientSecret},
		"scope":         {"https://manage.office.com/.default"},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.loginBase, url.PathEscape(auth.Authority))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("m365 audit token request: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", &APIError{Status: resp.StatusCode, Code: out.Error, Message: out.ErrorDesc, Path: "token"}
	}
	c.mu.Lock()
	c.tokens[key] = cachedToken{value: out.AccessToken, expires: time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)}
	c.mu.Unlock()
	return out.AccessToken, nil
}

func (c *client) Collect(ctx context.Context, tenantID, contentType string, start, end time.Time) ([]model.SecurityAuditEvent, error) {
	mode, err := c.Mode(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if mode == ModeSample {
		return sampleEvents(tenantID, contentType, end), nil
	}
	auth, err := c.auth(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	tok, err := c.token(ctx, auth)
	if err != nil {
		return nil, err
	}
	if err := c.ensureSubscription(ctx, tok, auth.Authority, contentType); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/api/v1.0/%s/activity/feed/subscriptions/content?contentType=%s&startTime=%s&endTime=%s",
		url.PathEscape(auth.Authority), url.QueryEscape(contentType),
		url.QueryEscape(start.UTC().Format("2006-01-02T15:04:05")),
		url.QueryEscape(end.UTC().Format("2006-01-02T15:04:05")))
	var events []model.SecurityAuditEvent
	for path != "" {
		if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
			if err := c.validateContentURL(path); err != nil {
				return nil, err
			}
		}
		var blobs []struct {
			ContentURI string `json:"contentUri"`
		}
		next, err := c.get(ctx, tok, path, &blobs)
		if err != nil {
			return nil, err
		}
		for _, blob := range blobs {
			if err := c.validateContentURL(blob.ContentURI); err != nil {
				return nil, err
			}
			var records []json.RawMessage
			if _, err := c.get(ctx, tok, blob.ContentURI, &records); err != nil {
				return nil, err
			}
			for _, raw := range records {
				event, err := normalizeEvent(tenantID, contentType, raw, end)
				if err != nil {
					c.log.Warn("m365 audit record skipped", "tenant_id", tenantID, "content_type", contentType, "error", err)
					continue
				}
				events = append(events, event)
			}
		}
		path = next
	}
	return events, nil
}

func (c *client) ensureSubscription(ctx context.Context, token, authority, contentType string) error {
	listPath := fmt.Sprintf("/api/v1.0/%s/activity/feed/subscriptions/list", url.PathEscape(authority))
	var subscriptions []struct {
		ContentType string `json:"contentType"`
		Status      string `json:"status"`
	}
	if _, err := c.get(ctx, token, listPath, &subscriptions); err != nil {
		return err
	}
	for _, subscription := range subscriptions {
		if strings.EqualFold(subscription.ContentType, contentType) && strings.EqualFold(subscription.Status, "enabled") {
			return nil
		}
	}
	startPath := fmt.Sprintf("/api/v1.0/%s/activity/feed/subscriptions/start?contentType=%s", url.PathEscape(authority), url.QueryEscape(contentType))
	return c.send(ctx, token, http.MethodPost, startPath, nil)
}

func (c *client) get(ctx context.Context, token, path string, out any) (string, error) {
	endpoint := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		endpoint = c.base + path
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", decodeAPIError(resp, path)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out); err != nil {
		return "", err
	}
	return resp.Header.Get("NextPageUri"), nil
}

func (c *client) send(ctx context.Context, token, method, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeAPIError(resp, path)
	}
	return nil
}

func decodeAPIError(resp *http.Response, path string) error {
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
	if body.Error.Code != "" {
		body.Code, body.Message = body.Error.Code, body.Error.Message
	}
	return &APIError{Status: resp.StatusCode, Code: body.Code, Message: body.Message, Path: path}
}

func (c *client) validateContentURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("m365 audit returned an invalid content URL")
	}
	base, _ := url.Parse(c.base)
	if u.Scheme == base.Scheme && strings.EqualFold(u.Hostname(), base.Hostname()) {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme != "https" || !(host == "manage.office.com" || strings.HasSuffix(host, ".manage.office.com") || host == "manage.microsoft.com" || strings.HasSuffix(host, ".manage.microsoft.com")) {
		return fmt.Errorf("m365 audit rejected an untrusted content URL host")
	}
	return nil
}

func normalizeEvent(tenantID, contentType string, raw json.RawMessage, ingestedAt time.Time) (model.SecurityAuditEvent, error) {
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		return model.SecurityAuditEvent{}, err
	}
	providerID := stringValue(record, "Id", "ID", "id")
	if providerID == "" {
		digest := sha256.Sum256(raw)
		providerID = "hash_" + hex.EncodeToString(digest[:12])
	}
	occurredAt, ok := parseAuditTime(stringValue(record, "CreationTime", "creationTime"))
	if !ok {
		return model.SecurityAuditEvent{}, fmt.Errorf("invalid CreationTime")
	}
	digest := sha256.Sum256([]byte(tenantID + "|" + providerID))
	return model.SecurityAuditEvent{
		ID: "sae_" + hex.EncodeToString(digest[:12]), TenantID: tenantID,
		ProviderRecordID: providerID, ContentType: contentType,
		Workload:     stringValue(record, "Workload", "workload"),
		Operation:    stringValue(record, "Operation", "operation"),
		Actor:        stringValue(record, "UserId", "UserID", "userId", "Actor", "actor"),
		ClientIP:     stringValue(record, "ClientIP", "ClientIp", "clientIp", "ClientIPAddress", "ActorIpAddress"),
		ObjectID:     stringValue(record, "ObjectId", "ObjectID", "objectId", "MailboxOwnerUPN", "SourceFileName"),
		ResultStatus: stringValue(record, "ResultStatus", "resultStatus"),
		OccurredAt:   occurredAt.UTC(), AvailableAt: ingestedAt.UTC(), IngestedAt: ingestedAt.UTC(),
		Sources: []string{"m365_audit"}, Raw: append([]byte(nil), raw...),
	}, nil
}

// NormalizeImportedManagementEvent applies the live Management Activity
// normalizer without persisting the event in the operational event store.
func NormalizeImportedManagementEvent(tenantID, contentType string, raw json.RawMessage, observedAt time.Time) (model.SecurityAuditEvent, error) {
	return normalizeEvent(tenantID, contentType, raw, observedAt)
}

func stringValue(record map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := record[key]; ok {
			switch typed := value.(type) {
			case string:
				return typed
			case json.Number:
				return typed.String()
			case float64:
				return fmt.Sprintf("%.0f", typed)
			}
		}
	}
	return ""
}

func sampleEvents(tenantID, contentType string, at time.Time) []model.SecurityAuditEvent {
	if contentType != "Audit.Exchange" {
		return nil
	}
	raw, _ := json.Marshal(map[string]any{
		"Id": "rtm-sample-forwarding", "CreationTime": at.Add(-20 * time.Minute).UTC().Format(time.RFC3339),
		"Operation": "Set-Mailbox", "Workload": "Exchange",
		"UserId": "alex.wilson@contoso.com", "ClientIP": "198.51.100.24",
		"ObjectId": "finance@contoso.com", "ResultStatus": "Succeeded",
		"ForwardingSmtpAddress": "external@example.net",
	})
	event, _ := normalizeEvent(tenantID, contentType, raw, at)
	event.Sample = true
	return []model.SecurityAuditEvent{event}
}

func (c *client) Preflight(ctx context.Context, tenantID string) model.PreflightCheck {
	check := model.PreflightCheck{Area: "Microsoft 365 Audit ingestion", Resource: "Office 365 Management APIs", Permission: Permission}
	mode, err := c.Mode(ctx, tenantID)
	if err != nil {
		check.Status, check.Detail = "error", "RTM could not resolve the tenant audit connection."
		return check
	}
	if mode == ModeSample {
		check.Status, check.Detail = "sample", "No live application credentials are configured; RTM audit sample data is active."
		return check
	}
	auth, err := c.auth(ctx, tenantID)
	if err != nil {
		check.Status, check.Detail = "error", "RTM could not resolve the tenant audit connection."
		return check
	}
	tok, err := c.token(ctx, auth)
	if err == nil {
		path := fmt.Sprintf("/api/v1.0/%s/activity/feed/subscriptions/list", url.PathEscape(auth.Authority))
		var subscriptions []map[string]any
		_, err = c.get(ctx, tok, path, &subscriptions)
	}
	if err == nil {
		check.Status, check.Detail, check.GrantedVia = "ok", "Management Activity subscriptions are readable.", "Application"
		return check
	}
	if apiErr, ok := err.(*APIError); ok && apiErr.Status == http.StatusForbidden {
		check.Status, check.Detail = "missing", "Grant admin consent for Office 365 Management APIs ActivityFeed.Read."
		return check
	}
	check.Status, check.Detail = "error", "The Microsoft 365 audit subscription probe failed."
	return check
}
