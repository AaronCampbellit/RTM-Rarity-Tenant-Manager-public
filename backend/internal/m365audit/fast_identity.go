package m365audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/model"
)

const fastIdentityMaxPages = 50

func (c *client) CollectFastIdentity(ctx context.Context, tenantID, contentType string, start, end time.Time) ([]model.SecurityAuditEvent, error) {
	mode, err := c.Mode(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if mode == ModeSample {
		return sampleFastIdentityEvents(tenantID, contentType, end), nil
	}
	auth, err := c.auth(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	token, err := c.graphToken(ctx, auth)
	if err != nil {
		return nil, err
	}

	field := "createdDateTime"
	path := "/auditLogs/signIns"
	if contentType == ContentTypeEntraDirectoryAudit {
		field, path = "activityDateTime", "/auditLogs/directoryAudits"
	} else if contentType != ContentTypeEntraSignIn {
		return nil, fmt.Errorf("unsupported fast identity content type %q", contentType)
	}
	filter := fmt.Sprintf("%s ge %s and %s le %s", field, start.UTC().Format(time.RFC3339Nano), field, end.UTC().Format(time.RFC3339Nano))
	path += "?$filter=" + url.QueryEscape(filter) + "&$top=999"
	availableAt := end.UTC()
	var events []model.SecurityAuditEvent
	for page := 0; path != ""; page++ {
		if page >= fastIdentityMaxPages {
			return nil, fmt.Errorf("graph fast identity response exceeded %d pages", fastIdentityMaxPages)
		}
		var response struct {
			Value []json.RawMessage `json:"value"`
			Next  string            `json:"@odata.nextLink"`
		}
		if err := c.graphGet(ctx, token, path, &response); err != nil {
			return nil, err
		}
		for _, raw := range response.Value {
			event, err := normalizeFastIdentityEvent(tenantID, contentType, raw, availableAt)
			if err != nil {
				c.log.Warn("graph fast identity record skipped", "tenant_id", tenantID, "content_type", contentType, "error", err)
				continue
			}
			events = append(events, event)
		}
		path = response.Next
	}
	return events, nil
}

func (c *client) graphGet(ctx context.Context, token, path string, out any) error {
	endpoint := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		endpoint = c.graphBase + path
	}
	if err := c.validateGraphURL(endpoint); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("graph fast identity request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeAPIError(resp, path)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

func (c *client) validateGraphURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("graph returned an invalid paging URL")
	}
	base, _ := url.Parse(c.graphBase)
	if u.Scheme == base.Scheme && strings.EqualFold(u.Hostname(), base.Hostname()) {
		return nil
	}
	if u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "graph.microsoft.com") {
		return fmt.Errorf("graph fast identity rejected an untrusted paging URL host")
	}
	return nil
}

func normalizeFastIdentityEvent(tenantID, contentType string, raw json.RawMessage, availableAt time.Time) (model.SecurityAuditEvent, error) {
	var record map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&record); err != nil {
		return model.SecurityAuditEvent{}, err
	}
	providerID := stringValue(record, "id", "Id", "ID")
	if providerID == "" {
		digest := sha256.Sum256(raw)
		providerID = "hash_" + hex.EncodeToString(digest[:12])
	}
	var occurredAt time.Time
	var operation, actor, clientIP, objectID, result string
	if contentType == ContentTypeEntraSignIn {
		occurredAt = parseGraphTime(stringValue(record, "createdDateTime"))
		actor = stringValue(record, "userPrincipalName", "userDisplayName", "userId")
		clientIP = stringValue(record, "ipAddress")
		objectID = stringValue(record, "resourceDisplayName", "appDisplayName", "resourceId", "appId")
		errorCode := nestedNumber(record, "status", "errorCode")
		if errorCode == "" || errorCode == "0" {
			operation, result = "UserLoggedIn", "Succeeded"
		} else {
			operation, result = "UserLoginFailed", "Failed"
		}
	} else {
		occurredAt = parseGraphTime(stringValue(record, "activityDateTime"))
		operation = stringValue(record, "activityDisplayName", "operationType")
		result = stringValue(record, "result")
		actor = auditInitiator(record)
		clientIP = nestedString(record, "initiatedBy", "user", "ipAddress")
		objectID = firstTarget(record)
	}
	if occurredAt.IsZero() {
		return model.SecurityAuditEvent{}, fmt.Errorf("missing or invalid event timestamp")
	}
	digest := sha256.Sum256([]byte(tenantID + "|" + providerID))
	return model.SecurityAuditEvent{
		ID: "sae_" + hex.EncodeToString(digest[:12]), TenantID: tenantID, ProviderRecordID: providerID,
		ContentType: contentType, Workload: "MicrosoftEntra", Operation: operation, Actor: actor,
		ClientIP: clientIP, ObjectID: objectID, ResultStatus: result, OccurredAt: occurredAt,
		AvailableAt: availableAt.UTC(), IngestedAt: availableAt.UTC(), Sources: []string{"entra_graph"},
		Raw: append([]byte(nil), raw...),
	}, nil
}

// NormalizeImportedFastIdentityEvent applies the same field mapping used by
// live Graph polling to case-scoped evidence. Callers must supply a synthetic
// investigation tenant ID so imported records cannot collide with live data.
func NormalizeImportedFastIdentityEvent(tenantID, contentType string, raw json.RawMessage, observedAt time.Time) (model.SecurityAuditEvent, error) {
	return normalizeFastIdentityEvent(tenantID, contentType, raw, observedAt)
}

func parseGraphTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed.UTC()
}

func nestedString(record map[string]any, path ...string) string {
	var value any = record
	for _, key := range path {
		object, ok := value.(map[string]any)
		if !ok {
			return ""
		}
		value = object[key]
	}
	return scalarString(value)
}

func nestedNumber(record map[string]any, path ...string) string { return nestedString(record, path...) }

func auditInitiator(record map[string]any) string {
	for _, path := range [][]string{{"initiatedBy", "user", "userPrincipalName"}, {"initiatedBy", "user", "displayName"}, {"initiatedBy", "app", "displayName"}, {"initiatedBy", "app", "servicePrincipalId"}} {
		if value := nestedString(record, path...); value != "" {
			return value
		}
	}
	return ""
}

func firstTarget(record map[string]any) string {
	targets, _ := record["targetResources"].([]any)
	if len(targets) == 0 {
		return ""
	}
	target, _ := targets[0].(map[string]any)
	return stringValue(target, "displayName", "userPrincipalName", "id")
}

func sampleFastIdentityEvents(tenantID, contentType string, at time.Time) []model.SecurityAuditEvent {
	if contentType != ContentTypeEntraSignIn {
		return nil
	}
	raw, _ := json.Marshal(map[string]any{
		"id": "rtm-sample-fast-signin", "createdDateTime": at.Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano),
		"userPrincipalName": "alex.wilson@contoso.com", "ipAddress": "198.51.100.24",
		"resourceDisplayName": "Microsoft 365", "status": map[string]any{"errorCode": 0},
		"location": map[string]any{"countryOrRegion": "US"}, "sessionId": "sample-session",
	})
	event, _ := normalizeFastIdentityEvent(tenantID, contentType, raw, at)
	event.Sample = true
	return []model.SecurityAuditEvent{event}
}

func (c *client) FastIdentityPreflight(ctx context.Context, tenantID string) model.PreflightCheck {
	check := model.PreflightCheck{Area: "Fast identity monitoring", Resource: "Microsoft Graph", Permission: GraphPermission}
	mode, err := c.Mode(ctx, tenantID)
	if err != nil {
		check.Status, check.Detail = "error", "RTM could not resolve the tenant Graph connection."
		return check
	}
	if mode == ModeSample {
		check.Status, check.Detail = "sample", "No live application credentials are configured; RTM identity sample data is active."
		return check
	}
	auth, err := c.auth(ctx, tenantID)
	if err == nil {
		var response struct {
			Value []json.RawMessage `json:"value"`
		}
		var token string
		token, err = c.graphToken(ctx, auth)
		if err == nil {
			err = c.graphGet(ctx, token, "/auditLogs/directoryAudits?$top=1", &response)
		}
	}
	if err == nil {
		check.Status, check.Detail, check.GrantedVia = "ok", "Graph directory audit records are readable for the one-minute fast lane.", "Application"
		return check
	}
	if apiErr, ok := err.(*APIError); ok && apiErr.Status == http.StatusForbidden {
		check.Status, check.Detail = "missing", "Grant Microsoft Graph AuditLog.Read.All application permission and admin consent."
		return check
	}
	check.Status, check.Detail = "error", "The Graph fast identity probe failed."
	return check
}
