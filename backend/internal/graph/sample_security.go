package graph

import (
	"context"
	"net/http"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func (sampleProvider) SecurityIncidents(_ context.Context, tenantID string) (model.SecurityIncidentFeed, error) {
	details := sampleSecurityIncidentDetails(tenantID)
	incidents := make([]model.SecurityIncident, 0, len(details))
	for _, detail := range details {
		incidents = append(incidents, detail.SecurityIncident)
	}
	return model.SecurityIncidentFeed{Mode: "sample", Incidents: incidents}, nil
}

func (sampleProvider) SecurityIncident(_ context.Context, tenantID, incidentID string) (model.SecurityIncidentDetail, error) {
	for _, detail := range sampleSecurityIncidentDetails(tenantID) {
		if detail.ID == incidentID {
			return detail, nil
		}
	}
	return model.SecurityIncidentDetail{}, &APIError{
		Status: http.StatusNotFound, Code: "Request_ResourceNotFound",
		Message: "sample: unknown security incident " + incidentID,
		Path:    "/security/incidents/" + incidentID,
	}
}

func sampleSecurityIncidentDetails(tenantID string) []model.SecurityIncidentDetail {
	now := time.Now().UTC()
	at := func(hours int) string { return now.Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339) }
	descriptions := map[string]string{
		"sec_1001": "Unusual mailbox access was followed by a rule forwarding messages to an external address.",
		"sec_1002": "A high-risk sign-in was followed by registration of a new authentication method.",
		"sec_1003": "A policy protecting privileged roles was disabled outside the approved window.",
		"sec_1004": "Repeated failures from one network ended in a successful legacy-authentication sign-in.",
		"sec_1005": "Twelve recipients received messages sharing the same credential-phishing URL.",
		"sec_1006": "A newly consented application can read directory data across the tenant.",
		"sec_1007": "An external user accessed a finance site from a new country.",
	}
	incident := func(id, title, severity, status, providerStatus, source string, alerts int, createdHours, updatedHours int, entities []model.SecurityEntity) model.SecurityIncident {
		return model.SecurityIncident{
			ID: id, TenantID: tenantID, Title: title, Description: descriptions[id], Severity: severity,
			Status: status, ProviderStatus: providerStatus, Source: source,
			AlertCount: alerts, EntityCount: len(entities), Entities: entities,
			CreatedAt: at(createdHours), UpdatedAt: at(updatedHours), Sample: true,
		}
	}
	alert := func(id, title, severity, source string, hours int) model.SecurityAlert {
		return model.SecurityAlert{
			ID: id, Title: title, Severity: severity, Status: "Active",
			ServiceSource: source, DetectionSource: "RTM sample detection",
			CreatedAt: at(hours), UpdatedAt: at(hours),
		}
	}
	timeline := func(id, title, description, source string, hours int) model.SecurityTimelineEvent {
		return model.SecurityTimelineEvent{
			ID: id, Timestamp: at(hours), Title: title, Description: description, Source: source,
		}
	}

	forwardingEntities := []model.SecurityEntity{{Type: "User", Label: "Megan Bowen"}, {Type: "Mailbox", Label: "megan.bowen@contoso.com"}}
	riskyEntities := []model.SecurityEntity{{Type: "User", Label: "Avery Quinn"}, {Type: "IP address", Label: "198.51.100.24"}}
	caEntities := []model.SecurityEntity{{Type: "Policy", Label: "Require MFA for administrators"}}
	sprayEntities := []model.SecurityEntity{{Type: "User", Label: "Dana White"}, {Type: "IP address", Label: "203.0.113.42"}}
	phishEntities := []model.SecurityEntity{{Type: "Mailbox", Label: "finance@contoso.com"}, {Type: "URL", Label: "login-document.example"}}
	appEntities := []model.SecurityEntity{{Type: "Application", Label: "Legacy Importer"}}
	sharingEntities := []model.SecurityEntity{{Type: "User", Label: "Ivan Petrov"}, {Type: "Site", Label: "Finance Operations"}}

	return []model.SecurityIncidentDetail{
		{
			SecurityIncident: incident("sec_1001", "Suspicious inbox forwarding rule", "Critical", model.SecurityTriageNew, "active", "Defender for Office 365", 2, 3, 1, forwardingEntities),
			Alerts: []model.SecurityAlert{
				alert("alert_1001", "External inbox forwarding rule created", "Critical", "Defender for Office 365", 3),
				alert("alert_1002", "Unusual mailbox access before forwarding", "High", "Defender for Office 365", 4),
			},
			Timeline: []model.SecurityTimelineEvent{
				timeline("evt_1001", "Unusual mailbox access", "Mailbox opened from a new network and client.", "Defender for Office 365", 4),
				timeline("evt_1002", "Forwarding rule created", "Messages are being forwarded to an external address.", "Microsoft 365 Audit", 3),
				timeline("evt_1003", "Incident correlated", "Defender correlated the mailbox events into one incident.", "Microsoft Defender XDR", 1),
			},
		},
		{
			SecurityIncident: incident("sec_1002", "Risky sign-in followed by MFA change", "High", model.SecurityTriageInProgress, "active", "Entra ID Protection", 2, 7, 2, riskyEntities),
			Alerts: []model.SecurityAlert{
				alert("alert_1003", "Unfamiliar sign-in properties", "High", "Entra ID Protection", 7),
				alert("alert_1004", "Authentication method registered", "Medium", "Entra ID Protection", 6),
			},
			Timeline: []model.SecurityTimelineEvent{
				timeline("evt_1004", "Risky sign-in detected", "The user signed in from an unfamiliar network and device.", "Entra ID Protection", 7),
				timeline("evt_1005", "MFA method changed", "A new Microsoft Authenticator method was registered.", "Microsoft 365 Audit", 6),
			},
		},
		{
			SecurityIncident: incident("sec_1003", "Conditional Access policy disabled", "High", model.SecurityTriageNew, "active", "Entra ID Protection", 1, 10, 5, caEntities),
			Alerts:           []model.SecurityAlert{alert("alert_1005", "High-impact Conditional Access change", "High", "Entra ID Protection", 10)},
			Timeline:         []model.SecurityTimelineEvent{timeline("evt_1006", "Policy disabled", "A policy protecting privileged roles was disabled.", "Microsoft 365 Audit", 10)},
		},
		{
			SecurityIncident: incident("sec_1004", "Multiple failed sign-ins followed by success", "Medium", model.SecurityTriageInProgress, "active", "Entra ID Protection", 2, 14, 8, sprayEntities),
			Alerts:           []model.SecurityAlert{alert("alert_1006", "Password spray activity", "Medium", "Entra ID Protection", 14)},
			Timeline:         []model.SecurityTimelineEvent{timeline("evt_1007", "Successful sign-in", "A successful sign-in followed repeated failures from the same network.", "Entra ID Protection", 8)},
		},
		{
			SecurityIncident: incident("sec_1005", "Defender phishing campaign", "Medium", model.SecurityTriageNew, "active", "Defender for Office 365", 4, 20, 11, phishEntities),
			Alerts:           []model.SecurityAlert{alert("alert_1007", "Credential phishing messages delivered", "Medium", "Defender for Office 365", 20)},
			Timeline:         []model.SecurityTimelineEvent{timeline("evt_1008", "Campaign correlated", "Twelve recipients received messages sharing the same malicious URL.", "Defender for Office 365", 11)},
		},
		{
			SecurityIncident: incident("sec_1006", "New service principal with high privileges", "Low", model.SecurityTriageNew, "active", "App Governance", 1, 27, 16, appEntities),
			Alerts:           []model.SecurityAlert{alert("alert_1008", "Application granted directory privileges", "Low", "App Governance", 27)},
			Timeline:         []model.SecurityTimelineEvent{timeline("evt_1009", "Admin consent granted", "The application received tenant-wide directory read permissions.", "Microsoft 365 Audit", 27)},
		},
		{
			SecurityIncident: incident("sec_1007", "Unexpected external SharePoint access", "Low", model.SecurityTriageResolved, "resolved", "Defender for Cloud Apps", 1, 42, 30, sharingEntities),
			Alerts:           []model.SecurityAlert{alert("alert_1009", "External user accessed finance site", "Low", "Defender for Cloud Apps", 42)},
			Timeline:         []model.SecurityTimelineEvent{timeline("evt_1010", "Incident resolved", "The site owner confirmed the external access was expected.", "RTM sample", 30)},
		},
	}
}
