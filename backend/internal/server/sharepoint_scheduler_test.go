package server

import (
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func TestSharePointScopeDueSkipsRecentAndRunningScans(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	recent := model.SharePointScan{
		Scope: "sites", Status: "completed", StartedAt: now.Add(-23 * time.Hour).Format(time.RFC3339),
	}
	if sharePointScopeDue([]model.SharePointScan{recent}, "sites", now) {
		t.Fatal("recent completed scan was considered due")
	}
	running := model.SharePointScan{
		Scope: "onedrive", Status: "running", StartedAt: now.Add(-48 * time.Hour).Format(time.RFC3339),
	}
	if sharePointScopeDue([]model.SharePointScan{running}, "onedrive", now) {
		t.Fatal("running scan was considered due")
	}
	if !sharePointScopeDue([]model.SharePointScan{recent}, "onedrive", now) {
		t.Fatal("never-scanned scope was not considered due")
	}
	old := model.SharePointScan{
		Scope: "sites", Status: "partial", StartedAt: now.Add(-25 * time.Hour).Format(time.RFC3339),
	}
	if !sharePointScopeDue([]model.SharePointScan{old}, "sites", now) {
		t.Fatal("stale scan was not considered due")
	}
}
