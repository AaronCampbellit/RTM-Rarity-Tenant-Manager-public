package reports

import (
	"context"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func entraProvider() *fakeProvider {
	day := 24 * time.Hour
	ts := func(offset time.Duration) string { return time.Now().Add(offset).UTC().Format(time.RFC3339) }
	p := liveProvider()
	p.readiness = map[string][]model.LicenseReadinessIssue{
		"ten_1": {{UserID: "u1", Name: "Ada", UPN: "ada@contoso.com", Issue: "Missing usage location", Status: "Active"}},
	}
	p.mfaRegs = map[string][]model.MFARegistration{
		"ten_1": {
			{ID: "u1", Name: "Ada", UPN: "ada@contoso.com", MFARegistered: true},
			{ID: "u2", Name: "Bo", UPN: "bo@contoso.com", MFARegistered: false},
			{ID: "u3", Name: "Adm", UPN: "adm@contoso.com", IsAdmin: true, MFARegistered: false},
		},
	}
	p.guests = map[string][]model.GuestAccount{
		"ten_1": {
			{ID: "g1", Name: "Fresh Guest", Mail: "fresh@p.com", State: "Accepted", Created: ts(-10 * day), LastSignIn: ts(-2 * day)},
			{ID: "g2", Name: "Stale Guest", Mail: "stale@p.com", State: "Accepted", Created: ts(-400 * day), LastSignIn: ts(-120 * day)},
			{ID: "g3", Name: "Stuck Invite", Mail: "stuck@p.com", State: "PendingAcceptance", Created: ts(-30 * day), LastSignIn: ts(-1 * day)},
		},
	}
	p.roles = map[string][]model.RoleAssignment{
		"ten_1": {
			{RoleName: "Global Administrator", MemberName: "Ada", MemberUPN: "ada@contoso.com", MemberType: "User"},
			{RoleName: "User Administrator", MemberName: "Bo", MemberUPN: "bo@contoso.com", MemberType: "User"},
		},
	}
	p.caex = map[string][]model.CAExclusion{
		"ten_1": {{PolicyName: "Require MFA", State: "reportOnly", Type: "Excluded group", Target: "IT Admins"}},
	}
	p.creds = map[string][]model.AppCredential{
		"ten_1": {
			{AppName: "Expired App", Type: "Secret", ExpiresAt: ts(-5 * day)},
			{AppName: "Expiring App", Type: "Secret", ExpiresAt: ts(30 * day)},
			{AppName: "Healthy App", Type: "Certificate", ExpiresAt: ts(300 * day)},
			{AppName: "No Expiry", Type: "Certificate", ExpiresAt: ""},
		},
	}
	return p
}

func TestEntraReadinessReportsFanOut(t *testing.T) {
	svc := New(testTenants, entraProvider(), disconnectedTL(), testLogger())
	ctx := context.Background()

	// license-readiness: one issue row, labeled with the tenant.
	rep, err := svc.Global(ctx, "license-readiness")
	if err != nil || len(rep.Rows) != 1 {
		t.Fatalf("license-readiness = %+v, %v", rep.Rows, err)
	}
	if rep.Rows[0][0].Text != "Contoso Ltd" || rep.Rows[0][3].Badge != "Missing usage location" {
		t.Fatalf("row = %+v", rep.Rows[0])
	}

	// mfa-gaps: only unregistered users, admins ranked first with the badge.
	rep, err = svc.Global(ctx, "mfa-gaps")
	if err != nil || len(rep.Rows) != 2 {
		t.Fatalf("mfa-gaps = %+v, %v", rep.Rows, err)
	}
	if rep.Rows[0][3].Badge != "Admin" || rep.Rows[0][3].Tone != "danger" {
		t.Fatalf("admin gap should rank first: %+v", rep.Rows[0])
	}

	// stale-guests: the stale guest and the stuck invite, not the fresh one.
	rep, err = svc.Global(ctx, "stale-guests")
	if err != nil || len(rep.Rows) != 2 {
		t.Fatalf("stale-guests = %+v, %v", rep.Rows, err)
	}

	// privileged-roles: every assignment; Global Administrator badged danger.
	rep, err = svc.Global(ctx, "privileged-roles")
	if err != nil || len(rep.Rows) != 2 {
		t.Fatalf("privileged-roles = %+v, %v", rep.Rows, err)
	}
	if rep.Rows[0][1].Badge != "Global Administrator" || rep.Rows[0][1].Tone != "danger" {
		t.Fatalf("ga row = %+v", rep.Rows[0])
	}

	// ca-exclusions: report-only state gets the warning tone.
	rep, err = svc.Global(ctx, "ca-exclusions")
	if err != nil || len(rep.Rows) != 1 || rep.Rows[0][2].Tone != "warning" {
		t.Fatalf("ca-exclusions = %+v, %v", rep.Rows, err)
	}

	// app-credentials: only the actionable subset (expired + expiring ≤90d).
	rep, err = svc.Global(ctx, "app-credentials")
	if err != nil || len(rep.Rows) != 2 {
		t.Fatalf("app-credentials = %+v, %v", rep.Rows, err)
	}
	if rep.Rows[0][4].Badge != "Expired" || rep.Rows[1][4].Badge != "Expiring soon" {
		t.Fatalf("status badges = %+v, %+v", rep.Rows[0][4], rep.Rows[1][4])
	}
}

// The readiness reports fan out even in sample mode — their provider reads
// have sample implementations, so they never delegate to a seeded fixture.
func TestEntraReportsFanOutInSampleMode(t *testing.T) {
	p := entraProvider()
	p.mode = "sample"
	svc := New(testTenants, p, disconnectedTL(), testLogger())

	rep, err := svc.Global(context.Background(), "privileged-roles")
	if err != nil {
		t.Fatalf("Global: %v", err)
	}
	if p.sampled {
		t.Fatal("readiness report should not delegate to the seeded GlobalReport")
	}
	if len(rep.Rows) != 2 || rep.Columns[0] != "Tenant" {
		t.Fatalf("rows = %+v", rep.Rows)
	}
}

func TestEntraReportToleratesPartialFailure(t *testing.T) {
	p := entraProvider()
	p.fail["ten_2"] = true
	svc := New(testTenants, p, disconnectedTL(), testLogger())

	rep, err := svc.Global(context.Background(), "mfa-gaps")
	if err != nil {
		t.Fatalf("partial failure should not error: %v", err)
	}
	if len(rep.Rows) != 2 {
		t.Fatalf("rows = %+v", rep.Rows)
	}
}
