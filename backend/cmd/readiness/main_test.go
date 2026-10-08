package main

import (
	"reflect"
	"testing"

	"github.com/rarity/rtm/internal/config"
)

func TestUnsatisfiedRequirementsReportsNonLiveAndUnknownOnce(t *testing.T) {
	checks := []config.IntegrationCheck{
		{Name: "graph", Mode: "sample"},
		{Name: "sharepoint", Mode: "live"},
		{Name: "threatlocker", Mode: "not_configured"},
	}
	want := []string{"graph", "threatlocker", "unknown"}
	if got := unsatisfiedRequirements(checks, "graph, sharepoint, threatlocker, graph, unknown"); !reflect.DeepEqual(got, want) {
		t.Fatalf("unsatisfiedRequirements = %v, want %v", got, want)
	}
}
