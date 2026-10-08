package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rarity/rtm/internal/model"
)

const exchangeSystemMailboxID = "bb558c35-97f1-4cb9-8ff7-d53741dc928c"

func (c *graphClient) exchangeAdminPreflight(ctx context.Context, tenantID string) model.PreflightCheck {
	check := model.PreflightCheck{
		Area: "Exchange delegate inventory", Resource: resourceExchangeOnline,
		Permission: "Exchange.ManageAsAppV2", Status: "ok",
	}
	auth, err := c.tenantAuth(ctx, tenantID)
	if err != nil {
		check.Status, check.Detail = "error", err.Error()
		return check
	}
	c.mu.Lock()
	delete(c.tokens, tokenCacheKey(auth.Authority, auth.ExchangeClientID, "https://outlook.office365.com/.default"))
	c.mu.Unlock()
	body := map[string]any{
		"CmdletInput": map[string]any{
			"CmdletName": "Get-Mailbox", "Parameters": map[string]any{"ResultSize": 1},
		},
	}
	var result any
	if err := c.exchangeAdminPost(ctx, tenantID, "Mailbox?$select=ExternalDirectoryObjectId", body, &result); err != nil {
		var apiErr *ExchangeAPIError
		if errors.As(err, &apiErr) && (apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden ||
			(apiErr.Status == http.StatusBadRequest && strings.HasPrefix(apiErr.Path, "token"))) {
			check.Status = "missing"
			check.Detail = "Exchange Online denied the probe. Grant admin consent for Exchange.ManageAsAppV2 and assign the app a least-privilege Exchange RBAC role that includes Get-Mailbox (Recipient Management)."
			return check
		}
		check.Status, check.Detail = "error", err.Error()
		return check
	}
	check.Detail = "Exchange Online Admin API access confirmed. Send on Behalf inventory is available; Full Access and Send As remain outside this preview API."
	return check
}

// MailboxPermissions uses Microsoft's supported Exchange Online Admin API.
// The API currently exposes Send on Behalf only. Coverage for Full Access and
// Send As is returned explicitly so an empty list is never presented as a
// complete delegate conclusion.
func (c *graphClient) MailboxPermissions(ctx context.Context, tenantID, mailboxID string) (model.MailboxPermissionFeed, error) {
	object, err := c.exchangeMailbox(ctx, tenantID, mailboxID)
	if err != nil {
		return model.MailboxPermissionFeed{}, err
	}
	delegates := exchangeSendOnBehalfDelegates(object)
	permissions := make([]model.MailboxPermission, 0, len(delegates))
	for _, delegate := range delegates {
		upn := strings.TrimSpace(delegate.UPN)
		if upn == "" {
			continue
		}
		name := strings.TrimSpace(delegate.Name)
		if name == "" {
			name = upn
		}
		permissions = append(permissions, model.MailboxPermission{
			ID: "exo-send-on-behalf:" + strings.ToLower(upn), Delegate: name,
			DelegateUPN: upn, Permission: MailboxPermSendOnBehalf,
		})
	}
	return model.MailboxPermissionFeed{
		Permissions: permissions,
		Coverage: []model.MailboxPermissionCoverage{
			{
				Permission: MailboxPermFullAccess, Status: "not_supported",
				Source: "Exchange Online PowerShell",
				Detail: "Microsoft's Exchange Online Admin API does not currently expose Full Access grants.",
			},
			{
				Permission: MailboxPermSendAs, Status: "not_supported",
				Source: "Exchange Online PowerShell",
				Detail: "Microsoft's Exchange Online Admin API does not currently expose Send As grants.",
			},
			{
				Permission: MailboxPermSendOnBehalf, Status: "collected",
				Source: "Exchange Online Admin API",
			},
		},
	}, nil
}

// SetMailboxPermission supports the one delegate family Microsoft currently
// publishes through the Admin API. Full Access and Send As continue to fail
// closed until RTM has a controlled Exchange Online PowerShell executor.
func (c *graphClient) SetMailboxPermission(ctx context.Context, tenantID, mailboxID, delegateID, permission string, remove bool) error {
	if permission != MailboxPermSendOnBehalf {
		return ErrExchangeAdminUnsupported
	}
	var delegate struct {
		UserPrincipalName string `json:"userPrincipalName"`
		Mail              string `json:"mail"`
	}
	if err := c.get(ctx, tenantID, "/users/"+url.PathEscape(delegateID)+"?$select=userPrincipalName,mail", &delegate); err != nil {
		return err
	}
	delegateAddress := delegate.UserPrincipalName
	if delegateAddress == "" {
		delegateAddress = delegate.Mail
	}
	if delegateAddress == "" {
		return fmt.Errorf("exchange: delegate %s has no mail identity", delegateID)
	}
	operation := "add"
	if remove {
		operation = "remove"
	}
	parameters := map[string]any{
		"Identity": mailboxID,
		"GrantSendOnBehalfTo": map[string]any{
			operation:     []string{delegateAddress},
			"@odata.type": "#Exchange.GenericHashTable",
		},
	}
	return c.exchangeAdminPost(ctx, tenantID, "Mailbox", map[string]any{
		"CmdletInput": map[string]any{"CmdletName": "Set-Mailbox", "Parameters": parameters},
	}, nil)
}

func (c *graphClient) exchangeMailbox(ctx context.Context, tenantID, mailboxID string) (map[string]any, error) {
	body := map[string]any{
		"CmdletInput": map[string]any{
			"CmdletName": "Get-Mailbox",
			"Parameters": map[string]any{
				"Identity": mailboxID, "IncludeGrantSendOnBehalfToWithDisplayNames": true,
			},
		},
	}
	var raw any
	if err := c.exchangeAdminPost(ctx, tenantID,
		"Mailbox?$select=GrantSendOnBehalfTo,GrantSendOnBehalfToWithDisplayNames", body, &raw); err != nil {
		return nil, err
	}
	object, ok := firstExchangeObject(raw)
	if !ok {
		return nil, fmt.Errorf("exchange: mailbox response did not contain a mailbox object")
	}
	return object, nil
}

func (c *graphClient) exchangeAdminPost(ctx context.Context, tenantID, endpoint string, body, out any) error {
	auth, err := c.tenantAuth(ctx, tenantID)
	if err != nil {
		return err
	}
	token, err := c.exchangeToken(ctx, auth)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	requestURL := c.exchangeBase + "/adminapi/v2.0/" + url.PathEscape(auth.Authority) + "/" + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AnchorMailbox", "APP:SystemMailbox{"+exchangeSystemMailboxID+"}@"+auth.Authority)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("exchange admin request: %w", err)
	}
	defer resp.Body.Close()
	const maxExchangeResponseBytes = 16 << 20
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxExchangeResponseBytes+1))
	if readErr != nil {
		return readErr
	}
	if len(responseBody) > maxExchangeResponseBytes {
		return fmt.Errorf("exchange %s: response exceeded %d MiB", endpoint, maxExchangeResponseBytes>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(responseBody, &envelope)
		message := envelope.Error.Message
		if message == "" && len(responseBody) > 0 {
			message = strings.TrimSpace(string(responseBody))
		}
		return &ExchangeAPIError{Status: resp.StatusCode, Code: envelope.Error.Code, Message: message, Path: "POST " + endpoint}
	}
	if out == nil || len(responseBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, out); err != nil {
		return fmt.Errorf("exchange %s: decoding response: %w", endpoint, err)
	}
	return nil
}

func firstExchangeObject(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if nested, ok := typed["value"]; ok {
			return firstExchangeObject(nested)
		}
		return typed, true
	case []any:
		if len(typed) == 0 {
			return nil, false
		}
		return firstExchangeObject(typed[0])
	default:
		return nil, false
	}
}

type exchangeDelegate struct {
	Name string
	UPN  string
}

func exchangeSendOnBehalfDelegates(mailbox map[string]any) []exchangeDelegate {
	plain := anyStrings(mailbox["GrantSendOnBehalfTo"])
	display := anyDelegates(mailbox["GrantSendOnBehalfToWithDisplayNames"])
	byUPN := make(map[string]exchangeDelegate, len(display))
	for _, delegate := range display {
		if delegate.UPN != "" {
			byUPN[strings.ToLower(delegate.UPN)] = delegate
		}
	}
	result := make([]exchangeDelegate, 0, max(len(plain), len(display)))
	seen := make(map[string]struct{}, max(len(plain), len(display)))
	for i, upn := range plain {
		delegate := byUPN[strings.ToLower(upn)]
		if delegate.UPN == "" {
			delegate.UPN = upn
			if i < len(display) {
				delegate.Name = display[i].Name
			}
		}
		key := strings.ToLower(delegate.UPN)
		if _, ok := seen[key]; key == "" || ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, delegate)
	}
	for _, delegate := range display {
		key := strings.ToLower(delegate.UPN)
		if _, ok := seen[key]; key == "" || ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, delegate)
	}
	return result
}

func anyStrings(value any) []string {
	items, ok := value.([]any)
	if !ok {
		if single, ok := value.(string); ok && single != "" {
			return []string{single}
		}
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
			out = append(out, strings.TrimSpace(text))
		}
	}
	return out
}

func anyDelegates(value any) []exchangeDelegate {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]exchangeDelegate, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			if upn, ok := item.(string); ok {
				out = append(out, exchangeDelegate{UPN: strings.TrimSpace(upn)})
			}
			continue
		}
		out = append(out, exchangeDelegate{
			Name: firstString(object, "DisplayName", "Name"),
			UPN:  firstString(object, "PrimarySmtpAddress", "UserPrincipalName", "SmtpAddress", "EmailAddress"),
		})
	}
	return out
}

func firstString(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := object[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
