package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/securefields"
)

func TestPGSecurityEventSemanticDeduplication(t *testing.T) {
	dsn := os.Getenv("RTM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("RTM_TEST_DATABASE_URL is not configured")
	}
	protector, err := securefields.New(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pg, err := NewPG(ctx, dsn, protector)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pg.Close)

	now := time.Now().UTC().Truncate(time.Second)
	fast := model.SecurityAuditEvent{
		ID: "pg-fast", TenantID: "ten_1", ProviderRecordID: "pg-graph-record",
		ContentType: "Graph.SignIn", Workload: "EntraID", Operation: "UserLoggedIn",
		Actor: "analyst@example.com", ClientIP: "203.0.113.10", ObjectID: "app-1",
		ResultStatus: "Succeeded", OccurredAt: now, AvailableAt: now.Add(time.Second),
		IngestedAt: now.Add(2 * time.Second), Sources: []string{"entra_graph"},
		Raw: json.RawMessage(`{"source":"graph"}`),
	}
	backfill := fast
	backfill.ID, backfill.ProviderRecordID = "pg-audit", "pg-audit-record"
	backfill.ContentType, backfill.Workload = "Audit.AzureActiveDirectory", "AzureActiveDirectory"
	backfill.OccurredAt, backfill.AvailableAt, backfill.IngestedAt = now.Add(3*time.Second), now.Add(time.Minute), now.Add(time.Minute)
	backfill.Sources, backfill.Raw = []string{"m365_audit"}, json.RawMessage(`{"source":"audit"}`)
	detection := func(id, eventID string, occurred time.Time) model.SecurityNativeDetection {
		return model.SecurityNativeDetection{ID: id, TenantID: "ten_1", EventID: eventID, EventIDs: []string{eventID}, RuleID: "successful_sign_in", RuleVersion: 1, Title: "Successful sign-in", Severity: "Low", OccurredAt: occurred, CreatedAt: occurred}
	}

	if inserted, err := pg.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: fast.ContentType}, []model.SecurityAuditEvent{fast}, []model.SecurityNativeDetection{detection("pg-det-fast", fast.ID, fast.OccurredAt)}); err != nil || inserted != 1 {
		t.Fatalf("fast insert=%d err=%v", inserted, err)
	}
	if inserted, err := pg.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: backfill.ContentType}, []model.SecurityAuditEvent{backfill}, nil); err != nil || inserted != 0 {
		t.Fatalf("backfill insert=%d err=%v", inserted, err)
	}
	if inserted, err := pg.StoreSecurityNativeDetections(ctx, []model.SecurityNativeDetection{detection("pg-det-audit", backfill.ID, backfill.OccurredAt)}); err != nil || inserted != 0 {
		t.Fatalf("backfill detection insert=%d err=%v", inserted, err)
	}

	events, more, err := pg.SearchSecurityAuditEvents(ctx, model.SecurityAuditEventSearch{From: now.Add(-time.Minute), To: now.Add(2 * time.Minute), Limit: 10})
	if err != nil || more || len(events) != 1 {
		t.Fatalf("events=%+v more=%v err=%v", events, more, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(events[0].Raw, &raw); err != nil {
		t.Fatal(err)
	}
	if events[0].ID != fast.ID || len(events[0].Sources) != 2 || raw["source"] != "audit" {
		t.Fatalf("canonical=%+v", events[0])
	}
	evidence, err := pg.SecurityAuditEventEvidence(ctx, "ten_1", fast.ID)
	if err != nil || len(evidence) != 2 {
		t.Fatalf("source evidence=%+v err=%v", evidence, err)
	}
	var graphEvidence, auditEvidence map[string]any
	if err := json.Unmarshal(evidence[0].Raw, &graphEvidence); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(evidence[1].Raw, &auditEvidence); err != nil {
		t.Fatal(err)
	}
	if graphEvidence["source"] != "graph" || auditEvidence["source"] != "audit" {
		t.Fatalf("source evidence=%+v", evidence)
	}
	repolled := fast
	repolled.AvailableAt, repolled.IngestedAt = now.Add(2*time.Hour), now.Add(2*time.Hour)
	repolled.Raw = json.RawMessage(`{"source":"graph-repolled"}`)
	if inserted, err := pg.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: "ten_1", ContentType: fast.ContentType}, []model.SecurityAuditEvent{repolled}, nil); err != nil || inserted != 0 {
		t.Fatalf("repolled fast insert=%d err=%v", inserted, err)
	}
	evidence, err = pg.SecurityAuditEventEvidence(ctx, "ten_1", fast.ID)
	if err != nil || !evidence[0].AvailableAt.Equal(fast.AvailableAt) {
		t.Fatalf("refreshed source evidence=%+v err=%v", evidence, err)
	}
	if err := json.Unmarshal(evidence[0].Raw, &graphEvidence); err != nil || graphEvidence["source"] != "graph-repolled" {
		t.Fatalf("refreshed graph evidence=%+v err=%v", graphEvidence, err)
	}
	detections, err := pg.SecurityNativeDetectionsSince(ctx, now.Add(-time.Minute))
	if err != nil || len(detections) != 1 || detections[0].EventID != fast.ID {
		t.Fatalf("detections=%+v err=%v", detections, err)
	}
	allDetections, err := pg.SecurityNativeDetections(ctx)
	if err != nil || len(allDetections) != 1 || allDetections[0].ID != detections[0].ID {
		t.Fatalf("all detections=%+v err=%v", allDetections, err)
	}
	related, err := pg.SecurityNativeDetectionsForEvent(ctx, "ten_1", fast.ID)
	if err != nil || len(related) != 1 || related[0].ID != detections[0].ID {
		t.Fatalf("related=%+v err=%v", related, err)
	}
	var aliases int
	if err := pg.Pool().QueryRow(ctx, `SELECT count(*) FROM security_audit_event_aliases WHERE event_id=$1`, fast.ID).Scan(&aliases); err != nil || aliases != 2 {
		t.Fatalf("aliases=%d err=%v", aliases, err)
	}
	var providerEvidence int
	if err := pg.Pool().QueryRow(ctx, `SELECT count(*) FROM security_audit_events WHERE id=ANY($1)`, []string{fast.ID, backfill.ID}).Scan(&providerEvidence); err != nil || providerEvidence != 2 {
		t.Fatalf("provider evidence=%d err=%v", providerEvidence, err)
	}
}
