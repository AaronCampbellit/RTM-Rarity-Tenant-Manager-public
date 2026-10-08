package offlineinvestigations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
)

func TestRunAnalysisKeepsEvidenceOutOfLiveSecurityTables(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	service := New(st, log)
	// Keep the fixture inside the storyline lookback regardless of when tests run.
	analysisTime := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return analysisTime }
	investigation, err := st.CreateOfflineInvestigation(ctx, store.NewOfflineInvestigation{
		Name: "Sign-in review", TenantLabel: "Contoso", CreatedBy: "Analyst",
	})
	if err != nil {
		t.Fatal(err)
	}
	files := []struct {
		name, evidence string
		content        []byte
	}{
		{"signIns.json", EvidenceEntraSignIns, []byte(`[{"id":"signin-1","createdDateTime":"2026-08-28T09:14:00Z","userPrincipalName":"alex@contoso.com","ipAddress":"198.51.100.77","resourceDisplayName":"Microsoft 365","status":{"errorCode":0},"authenticationRequirement":"singleFactorAuthentication","authenticationDetails":[{"authenticationMethod":"Password","succeeded":true}],"conditionalAccessStatus":"notApplied","isInteractive":true}]`)},
		{"directoryAudits.json", EvidenceEntraDirectoryAudit, []byte(`[{"id":"audit-1","activityDateTime":"2026-08-28T09:28:00Z","activityDisplayName":"Add authentication method","result":"success","initiatedBy":{"user":{"userPrincipalName":"alex@contoso.com","ipAddress":"198.51.100.77"}},"targetResources":[{"displayName":"alex@contoso.com"}]}]`)},
		{"activity.json", EvidenceM365Activity, []byte(`[{"Id":"activity-1","CreationTime":"2026-08-28T09:41:00Z","Operation":"New-InboxRule","Workload":"Exchange","UserId":"alex@contoso.com","ClientIP":"198.51.100.77","ObjectId":"Hide security mail","ResultStatus":"Succeeded","MoveToFolder":"Archive"}]`)},
	}
	for _, item := range files {
		digest := sha256.Sum256(item.content)
		parsed, err := ParseFile(item.name, "application/json", item.content)
		if err != nil {
			t.Fatalf("parse %s: %v", item.name, err)
		}
		if parsed.EvidenceType != item.evidence {
			t.Fatalf("%s evidence type = %s, want %s", item.name, parsed.EvidenceType, item.evidence)
		}
		if _, err := st.AddOfflineInvestigationFile(ctx, investigation.ID, model.OfflineInvestigationFile{
			Name: item.name, MediaType: "application/json", EvidenceType: item.evidence,
			SizeBytes: int64(len(item.content)), SHA256: hex.EncodeToString(digest[:]), RecordCount: 1, Content: item.content,
		}); err != nil {
			t.Fatal(err)
		}
	}
	job, err := st.CreateJob(ctx, model.Job{Type: AnalysisJobType, Tenant: "Contoso", Status: "Queued"})
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"investigationId":"` + investigation.ID + `","actor":"Analyst","correlationId":"test-correlation"}`
	if err := service.RunAnalysis(ctx, job.ID, payload); err != nil {
		t.Fatal(err)
	}

	completed, err := st.OfflineInvestigation(ctx, investigation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "complete" || completed.EventCount != 3 || completed.DetectionCount < 3 || completed.StorylineCount != 1 {
		t.Fatalf("unexpected completed investigation: %+v", completed)
	}
	if len(completed.Coverage) != 3 || completed.Coverage[0].Status != "present" {
		t.Fatalf("unexpected evidence coverage: %+v", completed.Coverage)
	}
	metadata, err := st.OfflineInvestigationFiles(ctx, investigation.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range metadata {
		if file.Content != nil {
			t.Fatal("case detail metadata must not decrypt or expose source content")
		}
	}
	analysis, err := st.OfflineInvestigationAnalysis(ctx, investigation.ID)
	if err != nil {
		t.Fatal(err)
	}
	foundSingleFactor := false
	for _, detection := range analysis.Detections {
		if detection.RuleID == "single_factor_authentication" {
			foundSingleFactor = true
		}
	}
	if !foundSingleFactor {
		t.Fatalf("single-factor detection missing: %+v", analysis.Detections)
	}
	liveEvents, err := st.SecurityAuditEventsSince(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(liveEvents) != 0 {
		t.Fatalf("offline analysis leaked %d events into live security storage", len(liveEvents))
	}
}

func TestCaseUploadLimitIsEnforcedInStore(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	investigation, err := st.CreateOfflineInvestigation(ctx, store.NewOfflineInvestigation{Name: "Bounded", TenantLabel: "Contoso", CreatedBy: "Analyst"})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < store.OfflineInvestigationMaxFiles; index++ {
		if _, err := st.AddOfflineInvestigationFile(ctx, investigation.ID, model.OfflineInvestigationFile{
			Name: "evidence.json", SHA256: string(rune('a' + index)), SizeBytes: 1, RecordCount: 1, Content: []byte("{}"),
		}); err != nil {
			t.Fatalf("file %d: %v", index, err)
		}
	}
	if _, err := st.AddOfflineInvestigationFile(ctx, investigation.ID, model.OfflineInvestigationFile{
		Name: "overflow.json", SHA256: "overflow", SizeBytes: 1, RecordCount: 1, Content: []byte("{}"),
	}); !errors.Is(err, store.ErrLimitExceeded) {
		t.Fatalf("overflow error = %v, want ErrLimitExceeded", err)
	}
}

func TestOfflineEvidenceLimitsAccommodateLargeExports(t *testing.T) {
	if MaxFileSize != 1<<30 {
		t.Fatalf("MaxFileSize = %d, want 1 GiB", MaxFileSize)
	}
	if MaxRecordsPerFile != 10_000_000 {
		t.Fatalf("MaxRecordsPerFile = %d, want 10,000,000", MaxRecordsPerFile)
	}
	if store.OfflineInvestigationMaxBytes != 10<<30 {
		t.Fatalf("case byte limit = %d, want 10 GiB", store.OfflineInvestigationMaxBytes)
	}
	if MaxCaseRecords != 50_000_000 {
		t.Fatalf("MaxCaseRecords = %d, want 50,000,000", MaxCaseRecords)
	}
}

func TestCaseByteAndRecordBoundariesAreEnforced(t *testing.T) {
	tests := []struct {
		name           string
		firstBytes     int64
		firstRecords   int
		overflowBytes  int64
		overflowRecord int
	}{
		{name: "bytes", firstBytes: store.OfflineInvestigationMaxBytes, firstRecords: 1, overflowBytes: 1, overflowRecord: 1},
		{name: "records", firstBytes: 1, firstRecords: store.OfflineInvestigationMaxRecords, overflowBytes: 1, overflowRecord: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			st := store.NewMem()
			investigation, err := st.CreateOfflineInvestigation(ctx, store.NewOfflineInvestigation{Name: "Boundary", TenantLabel: "Contoso", CreatedBy: "Analyst"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.AddOfflineInvestigationFile(ctx, investigation.ID, model.OfflineInvestigationFile{
				Name: "at-limit.json", SHA256: "at-limit", SizeBytes: test.firstBytes, RecordCount: test.firstRecords, Content: []byte("{}"),
			}); err != nil {
				t.Fatalf("exact boundary rejected: %v", err)
			}
			if _, err := st.AddOfflineInvestigationFile(ctx, investigation.ID, model.OfflineInvestigationFile{
				Name: "overflow.json", SHA256: "overflow", SizeBytes: test.overflowBytes, RecordCount: test.overflowRecord, Content: []byte("{}"),
			}); !errors.Is(err, store.ErrLimitExceeded) {
				t.Fatalf("overflow error = %v, want ErrLimitExceeded", err)
			}
		})
	}
}

func TestParseCSVSignInPreservesAuthenticationFields(t *testing.T) {
	content := []byte("id,createdDateTime,userPrincipalName,ipAddress,status.errorCode,authenticationRequirement,authenticationDetails,conditionalAccessStatus,isInteractive\n" +
		`signin-1,2026-08-28T09:14:00Z,alex@contoso.com,198.51.100.77,0,singleFactorAuthentication,"[{""authenticationMethod"":""Password"",""succeeded"":true}]",notApplied,true` + "\n")
	parsed, err := ParseFile("signIns.csv", "text/csv", content)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.EvidenceType != EvidenceEntraSignIns || len(parsed.Records) != 1 {
		t.Fatalf("parsed = %+v", parsed)
	}
	events, err := normalizeEvidence("offline:test", []ParsedFile{parsed}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	detections := m365audit.Detect(events, time.Now().UTC())
	for _, detection := range detections {
		if detection.RuleID == "single_factor_authentication" {
			found = true
		}
	}
	if !found {
		t.Fatalf("single-factor authentication field was not usable after CSV normalization: event=%+v detections=%+v raw=%s", events[0], detections, parsed.Records[0])
	}
}

func TestParsePurviewAuditSearchCSVUnwrapsAuditData(t *testing.T) {
	content := []byte("RecordId,CreationDate,RecordType,Operation,UserId,AuditData,AssociatedAdminUnits,AssociatedAdminUnitsNames\n" +
		`wrapper-1,2026-08-30T12:00:00Z,1,New-InboxRule,analyst@example.test,"{""Id"":""activity-1"",""CreationTime"":""2026-08-30T12:00:00Z"",""Operation"":""New-InboxRule"",""Workload"":""Exchange"",""UserId"":""analyst@example.test"",""ClientIPAddress"":""198.51.100.42"",""MailboxOwnerUPN"":""mailbox@example.test"",""ResultStatus"":""Succeeded""}",,` + "\n")
	parsed, err := ParseFile("purview-audit.csv", "text/csv", content)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.EvidenceType != EvidenceM365Activity || len(parsed.Records) != 1 {
		t.Fatalf("parsed = %+v", parsed)
	}
	var record map[string]any
	if err := json.Unmarshal(parsed.Records[0], &record); err != nil {
		t.Fatal(err)
	}
	if record["Id"] != "activity-1" || record["Workload"] != "Exchange" || record["AuditData"] != nil {
		t.Fatalf("Purview wrapper was not normalized: %+v", record)
	}
	events, err := normalizeEvidence("offline:purview", []ParsedFile{parsed}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ProviderRecordID != EvidenceM365Activity+":activity-1" || events[0].Operation != "New-InboxRule" || events[0].ClientIP != "198.51.100.42" || events[0].ObjectID != "mailbox@example.test" {
		t.Fatalf("normalized events = %+v", events)
	}
}
