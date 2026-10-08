package reports

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/threatlocker"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

// disconnectedTL is a ThreatLocker provider with no credentials anywhere —
// every tenant resolves to ErrNotConnected.
func disconnectedTL() threatlocker.Provider {
	return threatlocker.NewProvider(threatlocker.Config{})
}

type fakeTenants []model.Tenant

func (f fakeTenants) Tenants(context.Context) ([]model.Tenant, error) { return f, nil }

type failingTenants struct{}

func (failingTenants) Tenants(context.Context) ([]model.Tenant, error) {
	return nil, errors.New("store down")
}

// fakeProvider serves distinct per-tenant data keyed by RTM tenant id, and can
// be told to fail specific tenants.
type fakeProvider struct {
	mode      string
	users     map[string][]model.User
	lics      map[string][]model.License
	mfaRegs   map[string][]model.MFARegistration
	guests    map[string][]model.GuestAccount
	roles     map[string][]model.RoleAssignment
	caex      map[string][]model.CAExclusion
	creds     map[string][]model.AppCredential
	readiness map[string][]model.LicenseReadinessIssue
	fail      map[string]bool
	sampled   bool // GlobalReport was called (sample delegation)
}

func (f *fakeProvider) Mode() string { return f.mode }

func (f *fakeProvider) Users(_ context.Context, tenantID string) ([]model.User, error) {
	if f.fail[tenantID] {
		return nil, fmt.Errorf("tenant %s unreachable", tenantID)
	}
	return f.users[tenantID], nil
}

func (f *fakeProvider) Licenses(_ context.Context, tenantID string) ([]model.License, error) {
	if f.fail[tenantID] {
		return nil, fmt.Errorf("tenant %s unreachable", tenantID)
	}
	return f.lics[tenantID], nil
}

func (f *fakeProvider) GlobalReport(context.Context, string) (model.GlobalReport, error) {
	f.sampled = true
	return model.GlobalReport{Columns: []string{"Seeded"}}, nil
}

func (f *fakeProvider) Groups(context.Context, string) ([]model.Group, error) { return nil, nil }
func (f *fakeProvider) GroupMembers(context.Context, string, string) ([]model.GroupMember, error) {
	return nil, nil
}
func (f *fakeProvider) Mailboxes(context.Context, string) ([]model.Mailbox, error) { return nil, nil }
func (f *fakeProvider) Sites(context.Context, string) ([]model.Site, error)        { return nil, nil }
func (f *fakeProvider) SecurityIncidents(context.Context, string) (model.SecurityIncidentFeed, error) {
	return model.SecurityIncidentFeed{}, nil
}
func (f *fakeProvider) SecurityIncident(context.Context, string, string) (model.SecurityIncidentDetail, error) {
	return model.SecurityIncidentDetail{}, nil
}
func (f *fakeProvider) TestConnection(context.Context, string) error { return nil }
func (f *fakeProvider) DirectorySyncEnabled(context.Context, string) (*bool, error) {
	return nil, nil
}
func (f *fakeProvider) AddGroupMembers(context.Context, string, string, []string) error {
	return nil
}
func (f *fakeProvider) RemoveGroupMembers(context.Context, string, string, []string) error {
	return nil
}
func (f *fakeProvider) SetAccountEnabled(context.Context, string, string, bool) error {
	return nil
}
func (f *fakeProvider) AssignLicense(context.Context, string, string, string, bool) error {
	return nil
}
func (f *fakeProvider) RevokeSessions(context.Context, string, string) error {
	return nil
}
func (f *fakeProvider) ResetPassword(context.Context, string, string, string) error {
	return nil
}
func (f *fakeProvider) ResetMFA(context.Context, string, string) error { return nil }
func (f *fakeProvider) CreateGroup(context.Context, string, graph.NewGroup) (model.Group, error) {
	return model.Group{}, nil
}
func (f *fakeProvider) MailboxSettings(context.Context, string, string) (model.MailboxSettings, error) {
	return model.MailboxSettings{}, nil
}
func (f *fakeProvider) MailboxPermissions(context.Context, string, string) (model.MailboxPermissionFeed, error) {
	return model.MailboxPermissionFeed{}, nil
}
func (f *fakeProvider) SitePermissions(context.Context, string, string) ([]model.SitePermission, error) {
	return nil, nil
}
func (f *fakeProvider) SetMailboxForwarding(context.Context, string, string, string) error {
	return nil
}
func (f *fakeProvider) SetAutoReply(context.Context, string, string, bool, string) error {
	return nil
}
func (f *fakeProvider) SetMailboxPermission(context.Context, string, string, string, string, bool) error {
	return nil
}
func (f *fakeProvider) SetSiteAccess(context.Context, string, string, string, string, bool) error {
	return nil
}
func (f *fakeProvider) SetSiteSharing(context.Context, string, string, string) error {
	return nil
}

// Entra posture reads — per-tenant fixtures keyed like users/lics; a failed
// tenant fails these too so partial-failure tests cover the new reports.
func (f *fakeProvider) MFARegistrations(_ context.Context, tenantID string) ([]model.MFARegistration, error) {
	if f.fail[tenantID] {
		return nil, fmt.Errorf("tenant %s unreachable", tenantID)
	}
	return f.mfaRegs[tenantID], nil
}
func (f *fakeProvider) GuestAccounts(_ context.Context, tenantID string) ([]model.GuestAccount, error) {
	if f.fail[tenantID] {
		return nil, fmt.Errorf("tenant %s unreachable", tenantID)
	}
	return f.guests[tenantID], nil
}
func (f *fakeProvider) RoleAssignments(_ context.Context, tenantID string) ([]model.RoleAssignment, error) {
	if f.fail[tenantID] {
		return nil, fmt.Errorf("tenant %s unreachable", tenantID)
	}
	return f.roles[tenantID], nil
}
func (f *fakeProvider) CAExclusions(_ context.Context, tenantID string) ([]model.CAExclusion, error) {
	if f.fail[tenantID] {
		return nil, fmt.Errorf("tenant %s unreachable", tenantID)
	}
	return f.caex[tenantID], nil
}
func (f *fakeProvider) AppCredentials(_ context.Context, tenantID string) ([]model.AppCredential, error) {
	if f.fail[tenantID] {
		return nil, fmt.Errorf("tenant %s unreachable", tenantID)
	}
	return f.creds[tenantID], nil
}
func (f *fakeProvider) LicenseReadiness(_ context.Context, tenantID string) ([]model.LicenseReadinessIssue, error) {
	if f.fail[tenantID] {
		return nil, fmt.Errorf("tenant %s unreachable", tenantID)
	}
	return f.readiness[tenantID], nil
}
func (f *fakeProvider) Preflight(context.Context, string) ([]model.PreflightCheck, error) {
	return nil, nil
}
func (f *fakeProvider) UserRaw(context.Context, string, string) (model.UserRaw, error) {
	return model.UserRaw{}, nil
}
func (f *fakeProvider) UserGroupIDs(context.Context, string, string) ([]string, error) {
	return nil, nil
}
func (f *fakeProvider) SharedItems(context.Context, string, string) ([]model.SharedItem, error) {
	return nil, nil
}
func (f *fakeProvider) DeleteSitePermission(context.Context, string, string, string) error {
	return nil
}
func (f *fakeProvider) DeleteItemPermission(context.Context, string, string, string, string, string) error {
	return nil
}

func liveProvider() *fakeProvider {
	return &fakeProvider{
		mode: "graph",
		users: map[string][]model.User{
			"ten_1": {
				{ID: "u1", Name: "Ada", UPN: "ada@contoso.com", MFA: "Enabled", Status: "Active"},
				{ID: "u2", Name: "Gia", UPN: "gia@partner.com", MFA: "Unknown", Status: "Guest"},
			},
			"ten_2": {
				{ID: "u3", Name: "Dan", UPN: "dan@fabrikam.com", MFA: "Disabled", Status: "Disabled"},
			},
		},
		lics: map[string][]model.License{
			"ten_1": {{SKU: "SPE_E5", Product: "Microsoft 365 E5", Assigned: 90, Total: 100, Utilization: 90}},
			"ten_2": {{SKU: "SPE_E3", Product: "Microsoft 365 E3", Assigned: 5, Total: 10, Utilization: 50}},
		},
		fail: map[string]bool{},
	}
}

var testTenants = fakeTenants{
	{ID: "ten_1", Name: "Contoso Ltd"},
	{ID: "ten_2", Name: "Fabrikam, Inc."},
}

func TestGlobalFansOutAcrossTenants(t *testing.T) {
	svc := New(testTenants, liveProvider(), disconnectedTL(), testLogger())

	rep, err := svc.Global(context.Background(), "mfa")
	if err != nil {
		t.Fatalf("Global: %v", err)
	}
	if rep.Columns[0] != "Tenant" {
		t.Fatalf("columns = %v", rep.Columns)
	}
	// Rows from both tenants, in tenant-list order, labeled with tenant names.
	if len(rep.Rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rep.Rows))
	}
	if rep.Rows[0][0].Text != "Contoso Ltd" || rep.Rows[2][0].Text != "Fabrikam, Inc." {
		t.Fatalf("tenant labels = %q, %q", rep.Rows[0][0].Text, rep.Rows[2][0].Text)
	}
	// MFA badge tones follow the state.
	if rep.Rows[0][3].Badge != "Enabled" || rep.Rows[0][3].Tone != "success" {
		t.Fatalf("mfa cell = %+v", rep.Rows[0][3])
	}
	if rep.Rows[2][3].Badge != "Disabled" || rep.Rows[2][3].Tone != "danger" {
		t.Fatalf("mfa cell = %+v", rep.Rows[2][3])
	}
}

func TestGlobalLicenseReport(t *testing.T) {
	svc := New(testTenants, liveProvider(), disconnectedTL(), testLogger())

	rep, err := svc.Global(context.Background(), "license")
	if err != nil {
		t.Fatalf("Global: %v", err)
	}
	if len(rep.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rep.Rows))
	}
	row := rep.Rows[0]
	if row[0].Text != "Contoso Ltd" || row[1].Text != "SPE_E5" || row[3].Text != "90" || row[5].Text != "90%" {
		t.Fatalf("license row = %+v", row)
	}
}

func TestGlobalFilters(t *testing.T) {
	svc := New(testTenants, liveProvider(), disconnectedTL(), testLogger())
	ctx := context.Background()

	guests, err := svc.Global(ctx, "guests")
	if err != nil || len(guests.Rows) != 1 || guests.Rows[0][2].Text != "gia@partner.com" {
		t.Fatalf("guests = %+v, %v", guests.Rows, err)
	}

	inactive, err := svc.Global(ctx, "inactive")
	if err != nil || len(inactive.Rows) != 1 || inactive.Rows[0][2].Text != "dan@fabrikam.com" {
		t.Fatalf("inactive = %+v, %v", inactive.Rows, err)
	}
}

func TestGlobalToleratesPartialFailure(t *testing.T) {
	p := liveProvider()
	p.fail["ten_1"] = true
	svc := New(testTenants, p, disconnectedTL(), testLogger())

	rep, err := svc.Global(context.Background(), "mfa")
	if err != nil {
		t.Fatalf("partial failure should not error: %v", err)
	}
	// Only the healthy tenant's rows remain.
	if len(rep.Rows) != 1 || rep.Rows[0][0].Text != "Fabrikam, Inc." {
		t.Fatalf("rows = %+v", rep.Rows)
	}
}

func TestGlobalFailsWhenAllTenantsFail(t *testing.T) {
	p := liveProvider()
	p.fail["ten_1"] = true
	p.fail["ten_2"] = true
	svc := New(testTenants, p, disconnectedTL(), testLogger())

	if _, err := svc.Global(context.Background(), "mfa"); err == nil {
		t.Fatal("expected an error when every tenant fails")
	}
}

func TestGlobalEmptyTenantList(t *testing.T) {
	svc := New(fakeTenants{}, liveProvider(), disconnectedTL(), testLogger())
	rep, err := svc.Global(context.Background(), "license")
	if err != nil || len(rep.Rows) != 0 || len(rep.Columns) == 0 {
		t.Fatalf("empty list report = %+v, %v", rep, err)
	}
}

func TestGlobalTenantSourceError(t *testing.T) {
	svc := New(failingTenants{}, liveProvider(), disconnectedTL(), testLogger())
	if _, err := svc.Global(context.Background(), "mfa"); err == nil {
		t.Fatal("expected the store error to surface")
	}
}

func TestGlobalSampleModeDelegates(t *testing.T) {
	p := liveProvider()
	p.mode = "sample"
	svc := New(testTenants, p, disconnectedTL(), testLogger())

	rep, err := svc.Global(context.Background(), "mfa")
	if err != nil {
		t.Fatalf("Global: %v", err)
	}
	if !p.sampled || len(rep.Columns) != 1 || rep.Columns[0] != "Seeded" {
		t.Fatalf("sample mode did not delegate: %+v", rep)
	}
}
