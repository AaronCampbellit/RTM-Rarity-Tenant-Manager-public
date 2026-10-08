package graph

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/rarity/rtm/internal/model"
)

// graphSecurityIncident is the subset of the Microsoft Graph incident shape
// RTM normalizes. Evidence remains raw only inside this integration boundary;
// the API receives the small SecurityEntity projection below.
type graphSecurityIncident struct {
	ID                 string               `json:"id"`
	DisplayName        string               `json:"displayName"`
	Description        string               `json:"description"`
	Severity           string               `json:"severity"`
	Status             string               `json:"status"`
	Classification     string               `json:"classification"`
	Determination      string               `json:"determination"`
	AssignedTo         string               `json:"assignedTo"`
	CreatedDateTime    string               `json:"createdDateTime"`
	LastUpdateDateTime string               `json:"lastUpdateDateTime"`
	IncidentWebURL     string               `json:"incidentWebUrl"`
	Alerts             []graphSecurityAlert `json:"alerts"`
}

type graphSecurityAlert struct {
	ID                 string            `json:"id"`
	Title              string            `json:"title"`
	Description        string            `json:"description"`
	Severity           string            `json:"severity"`
	Status             string            `json:"status"`
	ServiceSource      string            `json:"serviceSource"`
	DetectionSource    string            `json:"detectionSource"`
	CreatedDateTime    string            `json:"createdDateTime"`
	LastUpdateDateTime string            `json:"lastUpdateDateTime"`
	Evidence           []json.RawMessage `json:"evidence"`
}

func (c *graphClient) SecurityIncidents(ctx context.Context, tenantID string) (model.SecurityIncidentFeed, error) {
	var out struct {
		Value    []graphSecurityIncident `json:"value"`
		NextLink string                  `json:"@odata.nextLink"`
	}
	// The newest 100 incidents are enough for the Phase 1 queue. Truncated is
	// surfaced when Microsoft has another page so coverage is never silent.
	path := "/security/incidents?$top=100&$expand=alerts"
	if err := c.get(ctx, tenantID, path, &out); err != nil {
		return model.SecurityIncidentFeed{}, err
	}
	incidents := make([]model.SecurityIncident, 0, len(out.Value))
	for _, incident := range out.Value {
		incidents = append(incidents, normalizeSecurityIncident(incident))
	}
	return model.SecurityIncidentFeed{Mode: "live", Incidents: incidents, Truncated: out.NextLink != ""}, nil
}

func (c *graphClient) SecurityIncident(ctx context.Context, tenantID, incidentID string) (model.SecurityIncidentDetail, error) {
	var out graphSecurityIncident
	path := "/security/incidents/" + url.PathEscape(incidentID) + "?$expand=alerts"
	if err := c.get(ctx, tenantID, path, &out); err != nil {
		// The list API explicitly documents $expand=alerts; some Graph clouds
		// reject the same OData expansion on a single-incident request. Fall back
		// to the documented newest-100 list used by the queue and select the row.
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest {
			return model.SecurityIncidentDetail{}, err
		}
		var list struct {
			Value []graphSecurityIncident `json:"value"`
		}
		if listErr := c.get(ctx, tenantID, "/security/incidents?$top=100&$expand=alerts", &list); listErr != nil {
			return model.SecurityIncidentDetail{}, listErr
		}
		for _, incident := range list.Value {
			if incident.ID == incidentID {
				return normalizeSecurityIncidentDetail(incident), nil
			}
		}
		return model.SecurityIncidentDetail{}, err
	}
	return normalizeSecurityIncidentDetail(out), nil
}

func normalizeSecurityIncident(in graphSecurityIncident) model.SecurityIncident {
	entities := securityEntities(in.Alerts)
	status := model.SecurityTriageNew
	if strings.EqualFold(in.Status, "resolved") || strings.EqualFold(in.Status, "redirected") {
		status = model.SecurityTriageResolved
	}
	return model.SecurityIncident{
		ID: in.ID, Title: in.DisplayName, Description: in.Description,
		Severity: normalizeSecuritySeverity(in.Severity), Status: status,
		ProviderStatus: in.Status, Classification: readableSecurityValue(in.Classification),
		Determination: readableSecurityValue(in.Determination), ProviderOwner: in.AssignedTo,
		Source: securityIncidentSource(in.Alerts), AlertCount: len(in.Alerts),
		EntityCount: len(entities), Entities: entities,
		CreatedAt: in.CreatedDateTime, UpdatedAt: in.LastUpdateDateTime,
		IncidentWebURL: in.IncidentWebURL,
	}
}

func normalizeSecurityIncidentDetail(in graphSecurityIncident) model.SecurityIncidentDetail {
	incident := normalizeSecurityIncident(in)
	alerts := make([]model.SecurityAlert, 0, len(in.Alerts))
	timeline := make([]model.SecurityTimelineEvent, 0, len(in.Alerts)+1)
	if in.CreatedDateTime != "" {
		timeline = append(timeline, model.SecurityTimelineEvent{
			ID: "incident-created", Timestamp: in.CreatedDateTime,
			Title: "Incident created", Description: in.DisplayName, Source: "Microsoft Defender XDR",
		})
	}
	for _, alert := range in.Alerts {
		source := friendlySecuritySource(alert.ServiceSource)
		alerts = append(alerts, model.SecurityAlert{
			ID: alert.ID, Title: alert.Title, Severity: normalizeSecuritySeverity(alert.Severity),
			Status: readableSecurityValue(alert.Status), ServiceSource: source,
			DetectionSource: readableSecurityValue(alert.DetectionSource),
			CreatedAt:       alert.CreatedDateTime, UpdatedAt: alert.LastUpdateDateTime,
		})
		detail := alert.Description
		if detail == "" {
			detail = readableSecurityValue(alert.DetectionSource)
		}
		timeline = append(timeline, model.SecurityTimelineEvent{
			ID: "alert-" + alert.ID, Timestamp: alert.CreatedDateTime,
			Title: alert.Title, Description: detail, Source: source,
		})
	}
	sort.SliceStable(timeline, func(i, j int) bool { return timeline[i].Timestamp < timeline[j].Timestamp })
	return model.SecurityIncidentDetail{SecurityIncident: incident, Alerts: alerts, Timeline: timeline}
}

func normalizeSecuritySeverity(value string) string {
	switch strings.ToLower(value) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "informational":
		return "Informational"
	default:
		return "Unknown"
	}
}

func securityIncidentSource(alerts []graphSecurityAlert) string {
	unique := map[string]struct{}{}
	for _, alert := range alerts {
		if source := friendlySecuritySource(alert.ServiceSource); source != "" {
			unique[source] = struct{}{}
		}
	}
	if len(unique) == 1 {
		for source := range unique {
			return source
		}
	}
	return "Microsoft Defender XDR"
}

func friendlySecuritySource(value string) string {
	switch strings.ToLower(value) {
	case "microsoftdefenderforendpoint":
		return "Defender for Endpoint"
	case "microsoftdefenderforidentity":
		return "Defender for Identity"
	case "microsoftdefenderforoffice365":
		return "Defender for Office 365"
	case "microsoftdefenderforcloudapps":
		return "Defender for Cloud Apps"
	case "microsoftdefenderforcloud":
		return "Defender for Cloud"
	case "microsoftentraidprotection", "azureactivedirectoryidentityprotection":
		return "Entra ID Protection"
	case "microsoftappgovernance":
		return "App Governance"
	case "microsoftsentinel", "azuresecuritycenter":
		return "Microsoft Sentinel"
	case "":
		return ""
	default:
		return readableSecurityValue(value)
	}
}

func securityEntities(alerts []graphSecurityAlert) []model.SecurityEntity {
	seen := map[string]struct{}{}
	entities := make([]model.SecurityEntity, 0, 8)
	for _, alert := range alerts {
		for _, raw := range alert.Evidence {
			var evidence map[string]any
			if json.Unmarshal(raw, &evidence) != nil {
				continue
			}
			label := firstNestedString(evidence,
				"userAccount.userPrincipalName", "userAccount.displayName", "userPrincipalName",
				"mailboxPrimaryAddress", "deviceDnsName", "ipAddress", "url", "fileDetails.fileName")
			if label == "" {
				continue
			}
			typ := securityEvidenceType(stringValue(evidence["@odata.type"]))
			key := strings.ToLower(typ + "|" + label)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			entities = append(entities, model.SecurityEntity{Type: typ, Label: label})
			if len(entities) == 8 {
				return entities
			}
		}
	}
	return entities
}

func firstNestedString(value map[string]any, paths ...string) string {
	for _, path := range paths {
		var current any = value
		for _, part := range strings.Split(path, ".") {
			object, ok := current.(map[string]any)
			if !ok {
				current = nil
				break
			}
			current = object[part]
		}
		if result := stringValue(current); result != "" {
			return result
		}
	}
	return ""
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func securityEvidenceType(value string) string {
	value = strings.TrimPrefix(value, "#microsoft.graph.security.")
	value = strings.TrimSuffix(value, "Evidence")
	switch strings.ToLower(value) {
	case "user", "useraccount":
		return "User"
	case "mailbox":
		return "Mailbox"
	case "device":
		return "Device"
	case "ip":
		return "IP address"
	case "url":
		return "URL"
	case "file":
		return "File"
	default:
		if label := readableSecurityValue(value); label != "" {
			return label
		}
		return "Entity"
	}
}

func readableSecurityValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "unknownFutureValue") {
		return ""
	}
	var out []rune
	for i, r := range []rune(value) {
		if i > 0 && unicode.IsUpper(r) && !unicode.IsSpace(out[len(out)-1]) {
			out = append(out, ' ')
		}
		out = append(out, r)
	}
	if len(out) > 0 {
		out[0] = unicode.ToUpper(out[0])
	}
	return string(out)
}
