package m365audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
)

func TestSampleIngestionPersistsCheckpointAndDeduplicates(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	provider := NewProvider(Config{}, testLogger(), nil)
	service := NewService(st, provider, testLogger())

	first := service.RunTenant(ctx, "ten_1")
	second := service.RunTenant(ctx, "ten_1")
	if first.Failed != 0 || first.Received != 1 || first.Inserted != 1 {
		t.Fatalf("first result = %+v", first)
	}
	if second.Inserted != 0 {
		t.Fatalf("second result = %+v", second)
	}
	checkpoints, _ := st.SecurityAuditCheckpoints(ctx)
	detections, _ := st.SecurityNativeDetections(ctx)
	if len(checkpoints) != len(ContentTypes) || len(detections) != 1 || !detections[0].Sample {
		t.Fatalf("checkpoints=%+v detections=%+v", checkpoints, detections)
	}
	if detections[0].RuleID != "suspicious_mail_forwarding" {
		t.Fatalf("detection = %+v", detections[0])
	}
}

func TestHistoryBackfillRetainsEvidenceAndHonorsRecentIncidentCutoff(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	job, err := st.CreateJob(ctx, model.Job{ID: "job_history", Type: "Security history import", Status: "Queued"})
	if err != nil {
		t.Fatal(err)
	}
	history := model.SecurityHistoryImport{
		TenantID: "ten_1", JobID: job.ID, RequestedWindow: "last_7d", WindowHours: 168,
		HistoricalIncidentMode: "recent_24h", Status: "queued", RequestedAt: now,
		IncidentCutoffAt: now.Add(-24 * time.Hour),
	}
	if _, err := st.UpsertSecurityHistoryImport(ctx, history); err != nil {
		t.Fatal(err)
	}
	service := NewService(st, NewProvider(Config{}, testLogger(), nil), testLogger())
	service.now = func() time.Time { return now }
	payload, _ := json.Marshal(HistoryBackfillPayload{TenantID: "ten_1"})
	service.RunHistoryBackfill(ctx, job.ID, string(payload))

	got, err := st.SecurityHistoryImport(ctx, "ten_1")
	if err != nil || got.Status != "completed" || got.Progress != 100 || got.FeedsCompleted != 42 {
		t.Fatalf("history = %+v, err=%v", got, err)
	}
	events, err := st.SecurityAuditEventsSince(ctx, now.Add(-8*24*time.Hour))
	if err != nil || len(events) == 0 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	for _, event := range events {
		found := false
		for _, source := range event.Sources {
			found = found || source == historicalBackfillSource
		}
		if !found {
			t.Fatalf("event is not marked historical: %+v", event)
		}
	}
	jobs, _ := st.Jobs(ctx)
	if len(jobs) != 1 || jobs[0].Status != "Completed" || jobs[0].Progress != 100 {
		t.Fatalf("jobs = %+v", jobs)
	}
}

func TestHistoryBackfillBaselineOnlySuppressesHistoricalDetections(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	job, _ := st.CreateJob(ctx, model.Job{ID: "job_baseline", Type: "Security history import", Status: "Queued"})
	_, _ = st.UpsertSecurityHistoryImport(ctx, model.SecurityHistoryImport{
		TenantID: "ten_1", JobID: job.ID, RequestedWindow: "last_24h", WindowHours: 24,
		HistoricalIncidentMode: "baseline_only", Status: "queued", RequestedAt: now, IncidentCutoffAt: now,
	})
	service := NewService(st, NewProvider(Config{}, testLogger(), nil), testLogger())
	service.now = func() time.Time { return now }
	payload, _ := json.Marshal(HistoryBackfillPayload{TenantID: "ten_1"})
	service.RunHistoryBackfill(ctx, job.ID, string(payload))
	detections, _ := st.SecurityNativeDetections(ctx)
	if len(detections) != 0 {
		t.Fatalf("baseline-only import created detections: %+v", detections)
	}
}

func TestSampleFastIdentityPersistsSeparateCheckpoints(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	service := NewService(st, NewProvider(Config{}, testLogger(), nil), testLogger())
	first := service.RunFastTenant(ctx, "ten_1")
	second := service.RunFastTenant(ctx, "ten_1")
	if first.Failed != 0 || first.Received != 1 || first.Inserted != 1 || second.Inserted != 0 {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	checkpoints, _ := st.SecurityAuditCheckpoints(ctx)
	if len(checkpoints) != len(FastIdentityContentTypes) {
		t.Fatalf("checkpoints=%+v", checkpoints)
	}
}

func TestRunAllReplaysHistoricalEventsIntoNewRules(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	now := time.Now().UTC()
	event := testEvent("historical-connector", "New-OutboundConnector", now.Add(-time.Hour), nil)
	if _, err := st.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{
		TenantID: "ten_1", ContentType: "Audit.Exchange", Status: "healthy", Mode: "live",
		CursorEnd: now, LastPolledAt: now,
	}, []model.SecurityAuditEvent{event}, nil); err != nil {
		t.Fatal(err)
	}
	service := NewService(st, NewProvider(Config{}, testLogger(), nil), testLogger())
	if _, err := service.RunAll(ctx); err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	detections, _ := st.SecurityNativeDetections(ctx)
	if _, ok := detectionRuleIDs(detections)["outlook_connector_change"]; !ok {
		t.Fatalf("historical connector event was not replayed: %+v", detections)
	}
	before := len(detections)
	if _, err := service.RunAll(ctx); err != nil {
		t.Fatalf("second RunAll: %v", err)
	}
	detections, _ = st.SecurityNativeDetections(ctx)
	if len(detections) != before {
		t.Fatalf("replay duplicated detections: before=%d after=%d", before, len(detections))
	}
	completed, err := st.SecurityDetectionReplayCompleted(ctx, detectionPackVersion)
	if err != nil || !completed {
		t.Fatalf("replay checkpoint = %v, %v", completed, err)
	}
}
