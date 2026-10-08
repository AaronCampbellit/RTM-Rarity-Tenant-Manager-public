package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

// scriptedGraph fails exactly the user ids in fail and records every write.
type scriptedGraph struct {
	graph.Provider // sample provider for reads
	fail           map[string]bool
	calls          []string
}

func newScriptedGraph(fail ...string) *scriptedGraph {
	f := map[string]bool{}
	for _, id := range fail {
		f[id] = true
	}
	return &scriptedGraph{
		Provider: graph.NewProvider(graph.Config{}, testLogger(), nil),
		fail:     f,
	}
}

func (s *scriptedGraph) write(op, uid string) error {
	s.calls = append(s.calls, op+" "+uid)
	if s.fail[uid] {
		return fmt.Errorf("scripted failure for %s", uid)
	}
	return nil
}

func (s *scriptedGraph) AddGroupMembers(_ context.Context, _, _ string, ids []string) error {
	return s.write("add", ids[0])
}
func (s *scriptedGraph) RemoveGroupMembers(_ context.Context, _, _ string, ids []string) error {
	return s.write("remove", ids[0])
}
func (s *scriptedGraph) SetAccountEnabled(_ context.Context, _, uid string, enabled bool) error {
	return s.write(fmt.Sprintf("enabled=%v", enabled), uid)
}
func (s *scriptedGraph) AssignLicense(_ context.Context, _, uid, _ string, remove bool) error {
	return s.write(fmt.Sprintf("license remove=%v", remove), uid)
}
func (s *scriptedGraph) RevokeSessions(_ context.Context, _, uid string) error {
	return s.write("revoke", uid)
}

func run(t *testing.T, gp graph.Provider, p Payload) (*store.Mem, model.Job, model.ChangeDetail) {
	t.Helper()
	st := store.NewMem()
	job, _ := st.CreateJob(t.Context(), model.Job{Type: JobType(p.Action, p.RevertOf != ""), Status: "Queued"})
	raw, _ := json.Marshal(p)
	Process(t.Context(), st, gp, threatlocker.NewProvider(threatlocker.Config{}), testLogger(), job.ID, string(raw))

	jobs, _ := st.Jobs(t.Context())
	var final model.Job
	for _, j := range jobs {
		if j.ID == job.ID {
			final = j
		}
	}
	changes, _ := st.Changes(t.Context())
	if len(changes) == 0 {
		t.Fatal("no change recorded")
	}
	detail, err := st.Change(t.Context(), changes[0].ID)
	if err != nil {
		t.Fatalf("change detail: %v", err)
	}
	return st, final, detail
}

func TestProcessBlockSignInRevertsToUnblock(t *testing.T) {
	gp := newScriptedGraph()
	_, job, detail := run(t, gp, Payload{
		Action: ActionBlockSignIn, TenantID: "ten_1", TenantName: "Contoso Ltd",
		UserIDs: []string{"usr_4", "usr_12"}, Technician: "T. Tester",
	})
	if job.Status != "Completed" {
		t.Fatalf("job = %+v", job)
	}
	if detail.Action != "Blocked sign-in for 2 users" || detail.Target != "2 users" {
		t.Fatalf("change = %+v", detail.Change)
	}
	if !detail.RevertEligible {
		t.Fatal("block should be revertible")
	}
	var revert Payload
	if err := json.Unmarshal([]byte(detail.RevertPayload), &revert); err != nil {
		t.Fatalf("revert payload: %v", err)
	}
	if revert.Action != ActionUnblockSignIn || len(revert.UserIDs) != 2 {
		t.Fatalf("revert = %+v", revert)
	}
}

func TestProcessPartialFailure(t *testing.T) {
	gp := newScriptedGraph("usr_2") // middle user fails
	_, job, detail := run(t, gp, Payload{
		Action: ActionAssignLicense, TenantID: "ten_1", TenantName: "Contoso Ltd",
		SkuID: "sku-SPE_E5", SkuName: "Microsoft 365 E5",
		UserIDs: []string{"usr_1", "usr_2", "usr_3"}, Technician: "T. Tester",
	})
	if job.Status != "Partial" {
		t.Fatalf("job status = %q, want Partial", job.Status)
	}
	if detail.Status != "Partial" {
		t.Fatalf("change status = %q", detail.Status)
	}
	// The failure is in the log with its reason.
	joined := strings.Join(detail.ExecutionLog, "\n")
	if !strings.Contains(joined, "FAILED usr_2") || !strings.Contains(joined, "2 succeeded · 1 failed") {
		t.Fatalf("log = %v", detail.ExecutionLog)
	}
	// Revert covers exactly the users that succeeded.
	var revert Payload
	if err := json.Unmarshal([]byte(detail.RevertPayload), &revert); err != nil {
		t.Fatalf("revert payload: %v", err)
	}
	if revert.Action != ActionRemoveLicense || len(revert.UserIDs) != 2 ||
		revert.UserIDs[0] != "usr_1" || revert.UserIDs[1] != "usr_3" {
		t.Fatalf("revert = %+v", revert)
	}
}

func TestProcessAllFail(t *testing.T) {
	gp := newScriptedGraph("usr_1", "usr_2")
	_, job, detail := run(t, gp, Payload{
		Action: ActionRemoveFromGroup, TenantID: "ten_1", TenantName: "Contoso Ltd",
		GroupID: "grp_1", GroupName: "Sales", UserIDs: []string{"usr_1", "usr_2"}, Technician: "T",
	})
	if job.Status != "Failed" || detail.Status != "Failed" {
		t.Fatalf("job=%q change=%q, want Failed", job.Status, detail.Status)
	}
	if detail.RevertEligible {
		t.Fatal("nothing succeeded — no revert should be offered")
	}
}

func TestProcessRevokeSessionsNotRevertible(t *testing.T) {
	gp := newScriptedGraph()
	_, job, detail := run(t, gp, Payload{
		Action: ActionRevokeSessions, TenantID: "ten_1", TenantName: "Contoso Ltd",
		UserIDs: []string{"usr_1"}, Technician: "T",
	})
	if job.Status != "Completed" {
		t.Fatalf("job = %+v", job)
	}
	if detail.RevertEligible || detail.Revert != "Not supported" {
		t.Fatalf("revoke revert = %+v", detail.Change)
	}
}

func TestProcessRevertRunMarksOriginal(t *testing.T) {
	gp := newScriptedGraph()
	st := store.NewMem()
	// Seed an "original" change to be marked.
	_ = st.AppendChange(t.Context(), model.ChangeDetail{
		Change: model.Change{Timestamp: "2026-07-02 10:00", Action: "Blocked sign-in for 1 user", Status: "Completed", Revert: "Available"},
	})
	changes, _ := st.Changes(t.Context())
	origID := changes[0].ID

	job, _ := st.CreateJob(t.Context(), model.Job{Type: "Revert — Sign-in Block", Status: "Queued"})
	raw, _ := json.Marshal(Payload{
		Action: ActionUnblockSignIn, TenantID: "ten_1", TenantName: "Contoso Ltd",
		UserIDs: []string{"usr_4"}, Technician: "T", RevertOf: origID,
	})
	Process(t.Context(), st, gp, threatlocker.NewProvider(threatlocker.Config{}), testLogger(), job.ID, raw2string(raw))

	orig, _ := st.Change(t.Context(), origID)
	if orig.Revert != "Reverted" {
		t.Fatalf("original revert = %q, want Reverted", orig.Revert)
	}
	changes, _ = st.Changes(t.Context())
	if changes[0].Action != "Revert — Unblocked sign-in for 1 user" || changes[0].Revert != "Not supported" {
		t.Fatalf("revert change = %+v", changes[0])
	}
}

func raw2string(b []byte) string { return string(b) }

func TestJobTypeLabels(t *testing.T) {
	cases := map[string]string{
		ActionAddToGroup:     "Group Membership Change",
		ActionBlockSignIn:    "Sign-in Block",
		ActionAssignLicense:  "License Assignment",
		ActionRevokeSessions: "Session Revocation",
	}
	for action, want := range cases {
		if got := JobType(action, false); got != want {
			t.Fatalf("JobType(%s) = %q, want %q", action, got, want)
		}
	}
	if got := JobType(ActionRemoveLicense, true); got != "Revert — License Removal" {
		t.Fatalf("revert label = %q", got)
	}
}
