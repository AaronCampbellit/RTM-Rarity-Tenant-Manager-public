package graph

import (
	"context"
	"net/http"
	"testing"
)

const securityIncidentsJSON = `{
  "@odata.nextLink":"https://graph.microsoft.com/v1.0/security/incidents?$skip=100",
  "value":[{
    "id":"42",
    "displayName":"Suspicious inbox forwarding rule",
    "description":"External forwarding was configured after unusual access.",
    "severity":"high",
    "status":"active",
    "classification":"truePositive",
    "determination":"compromisedAccount",
    "assignedTo":"analyst@rarity.io",
    "createdDateTime":"2026-08-23T10:00:00Z",
    "lastUpdateDateTime":"2026-08-23T10:05:00Z",
    "incidentWebUrl":"https://security.microsoft.com/incidents/42",
    "alerts":[{
      "id":"a1",
      "title":"Inbox rule created",
      "description":"A rule forwards mail externally.",
      "severity":"high",
      "status":"newAlert",
      "serviceSource":"microsoftDefenderForOffice365",
      "detectionSource":"microsoftDefenderForOffice365",
      "createdDateTime":"2026-08-23T10:01:00Z",
      "lastUpdateDateTime":"2026-08-23T10:04:00Z",
      "evidence":[
        {"@odata.type":"#microsoft.graph.security.userEvidence","userAccount":{"userPrincipalName":"megan@contoso.com"}},
        {"@odata.type":"#microsoft.graph.security.ipEvidence","ipAddress":"198.51.100.10"},
        {"@odata.type":"#microsoft.graph.security.userEvidence","userAccount":{"userPrincipalName":"megan@contoso.com"}}
      ]
    }]
  }]
}`

func TestSecurityIncidentsNormalizeDefenderResponse(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/security/incidents"] = securityIncidentsJSON
	c := newTestClient(f, nil)

	feed, err := c.SecurityIncidents(context.Background(), "")
	if err != nil {
		t.Fatalf("SecurityIncidents: %v", err)
	}
	if feed.Mode != "live" || !feed.Truncated || len(feed.Incidents) != 1 {
		t.Fatalf("feed = %+v", feed)
	}
	incident := feed.Incidents[0]
	if incident.ID != "42" || incident.Title != "Suspicious inbox forwarding rule" || incident.Severity != "High" {
		t.Fatalf("incident = %+v", incident)
	}
	if incident.Source != "Defender for Office 365" || incident.Status != "New" || incident.ProviderOwner != "analyst@rarity.io" || incident.Owner != "" {
		t.Fatalf("normalized source/state = %+v", incident)
	}
	if incident.EntityCount != 2 || len(incident.Entities) != 2 {
		t.Fatalf("entities = %+v", incident.Entities)
	}
	if incident.Entities[0].Type != "User" || incident.Entities[0].Label != "megan@contoso.com" {
		t.Fatalf("first entity = %+v", incident.Entities[0])
	}
}

func TestSecurityIncidentDetailBuildsAlertTimeline(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/security/incidents/42"] = `{
    "id":"42","displayName":"Suspicious inbox forwarding rule","severity":"high","status":"active",
    "createdDateTime":"2026-08-23T10:00:00Z","lastUpdateDateTime":"2026-08-23T10:05:00Z",
    "alerts":[{
      "id":"a1","title":"Inbox rule created","description":"A rule forwards mail externally.",
      "severity":"high","status":"newAlert","serviceSource":"microsoftDefenderForOffice365",
      "detectionSource":"microsoftDefenderForOffice365","createdDateTime":"2026-08-23T10:01:00Z",
      "lastUpdateDateTime":"2026-08-23T10:04:00Z","evidence":[]
    }]
  }`
	c := newTestClient(f, nil)

	detail, err := c.SecurityIncident(context.Background(), "", "42")
	if err != nil {
		t.Fatalf("SecurityIncident: %v", err)
	}
	if len(detail.Alerts) != 1 || detail.Alerts[0].ServiceSource != "Defender for Office 365" {
		t.Fatalf("alerts = %+v", detail.Alerts)
	}
	if len(detail.Timeline) != 2 || detail.Timeline[0].Title != "Incident created" || detail.Timeline[1].Title != "Inbox rule created" {
		t.Fatalf("timeline = %+v", detail.Timeline)
	}
}

func TestSecurityIncidentDetailFallsBackToDocumentedExpandedList(t *testing.T) {
	f := newFakeGraph(t)
	f.status["/security/incidents/42"] = http.StatusBadRequest
	f.responses["/security/incidents/42"] = `{"error":{"code":"Request_BadRequest","message":"Unsupported query"}}`
	f.responses["/security/incidents"] = securityIncidentsJSON
	c := newTestClient(f, nil)

	detail, err := c.SecurityIncident(context.Background(), "", "42")
	if err != nil {
		t.Fatalf("SecurityIncident fallback: %v", err)
	}
	if detail.ID != "42" || len(detail.Alerts) != 1 || len(detail.Timeline) != 2 {
		t.Fatalf("detail = %+v", detail)
	}
}

func TestSampleSecurityIncidentsAreExplicit(t *testing.T) {
	provider := newSampleProvider()
	feed, err := provider.SecurityIncidents(context.Background(), "ten_1")
	if err != nil {
		t.Fatalf("SecurityIncidents: %v", err)
	}
	if feed.Mode != "sample" || len(feed.Incidents) == 0 || !feed.Incidents[0].Sample {
		t.Fatalf("feed = %+v", feed)
	}
}
