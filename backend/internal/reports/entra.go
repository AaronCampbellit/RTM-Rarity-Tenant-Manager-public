package reports

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/model"
)

// Entra readiness reports — the operational reviews an MSP runs before
// license rollouts, MFA pushes, and access recertification. Each fans out per
// tenant like every other global report; the per-family reads live on the
// graph.Provider so sample tenants contribute sample rows.

// staleGuestAfter is the inactivity window for the stale-guest report.
const staleGuestAfter = 90 * 24 * time.Hour

// appCredentialWindow is how far ahead the credential-expiry report looks.
const appCredentialWindow = 90 * 24 * time.Hour

// entraReportColumns maps the readiness report types to their columns; also
// the registry of which types exist.
var entraReportColumns = map[string][]string{
	"license-readiness": {"Tenant", "Display Name", "UPN", "Issue", "Status"},
	"mfa-gaps":          {"Tenant", "Display Name", "UPN", "Admin", "Methods Registered", "SSPR"},
	"stale-guests":      {"Tenant", "Display Name", "Email", "Invite State", "Created", "Last Sign-in"},
	"privileged-roles":  {"Tenant", "Role", "Member", "UPN", "Type"},
	"ca-exclusions":     {"Tenant", "Policy", "State", "Exclusion", "Target"},
	"app-credentials":   {"Tenant", "Application", "Type", "Expires", "Status"},
}

func isEntraReport(reportType string) bool {
	_, ok := entraReportColumns[reportType]
	return ok
}

func (s *Service) entraRows(ctx context.Context, t model.Tenant, reportType string) ([][]model.GlobalReportCell, error) {
	switch reportType {
	case "license-readiness":
		return s.licenseReadinessRows(ctx, t)
	case "mfa-gaps":
		return s.mfaGapRows(ctx, t)
	case "stale-guests":
		return s.staleGuestRows(ctx, t)
	case "privileged-roles":
		return s.privilegedRoleRows(ctx, t)
	case "ca-exclusions":
		return s.caExclusionRows(ctx, t)
	default: // "app-credentials"
		return s.appCredentialRows(ctx, t)
	}
}

func (s *Service) licenseReadinessRows(ctx context.Context, t model.Tenant) ([][]model.GlobalReportCell, error) {
	issues, err := s.provider.LicenseReadiness(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	rows := make([][]model.GlobalReportCell, 0, len(issues))
	for _, i := range issues {
		tone := "warning"
		if i.Issue == "Unlicensed" {
			tone = "info"
		}
		rows = append(rows, []model.GlobalReportCell{
			{Text: t.Name}, {Text: i.Name}, {Text: i.UPN},
			{Badge: i.Issue, Tone: tone}, {Text: i.Status},
		})
	}
	return rows, nil
}

// mfaGapRows lists users who have not registered MFA — admins first, because
// an unregistered admin is the risk that matters most.
func (s *Service) mfaGapRows(ctx context.Context, t model.Tenant) ([][]model.GlobalReportCell, error) {
	regs, err := s.provider.MFARegistrations(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	var adminRows, userRows [][]model.GlobalReportCell
	for _, r := range regs {
		if r.MFARegistered {
			continue
		}
		adminCell := model.GlobalReportCell{Text: "—"}
		if r.IsAdmin {
			adminCell = model.GlobalReportCell{Badge: "Admin", Tone: "danger"}
		}
		methods := strings.Join(r.Methods, ", ")
		if methods == "" {
			methods = "None"
		}
		ssprTone, sspr := "neutral", "Not registered"
		if r.SSPR {
			ssprTone, sspr = "success", "Registered"
		}
		row := []model.GlobalReportCell{
			{Text: t.Name}, {Text: r.Name}, {Text: r.UPN},
			adminCell, {Text: methods}, {Badge: sspr, Tone: ssprTone},
		}
		if r.IsAdmin {
			adminRows = append(adminRows, row)
		} else {
			userRows = append(userRows, row)
		}
	}
	return append(adminRows, userRows...), nil
}

// staleGuestRows lists guests with no sign-in inside the window (or ever) and
// invites stuck in PendingAcceptance.
func (s *Service) staleGuestRows(ctx context.Context, t model.Tenant) ([][]model.GlobalReportCell, error) {
	guests, err := s.provider.GuestAccounts(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(-staleGuestAfter)
	rows := [][]model.GlobalReportCell{}
	for _, g := range guests {
		stale := g.LastSignIn == ""
		if !stale {
			if last, err := time.Parse(time.RFC3339, g.LastSignIn); err == nil {
				stale = last.Before(cutoff)
			}
		}
		pending := g.State == "PendingAcceptance"
		if !stale && !pending {
			continue
		}
		stateTone, state := "neutral", g.State
		if pending {
			stateTone, state = "warning", "Pending acceptance"
		}
		if state == "" {
			state = "—"
		}
		last := "Never"
		if g.LastSignIn != "" {
			last = ago(g.LastSignIn)
		}
		mail := g.Mail
		if mail == "" {
			mail = g.UPN
		}
		rows = append(rows, []model.GlobalReportCell{
			{Text: t.Name}, {Text: g.Name}, {Text: mail},
			{Badge: state, Tone: stateTone}, {Text: ago(g.Created)}, {Text: last},
		})
	}
	return rows, nil
}

func (s *Service) privilegedRoleRows(ctx context.Context, t model.Tenant) ([][]model.GlobalReportCell, error) {
	assignments, err := s.provider.RoleAssignments(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	rows := make([][]model.GlobalReportCell, 0, len(assignments))
	for _, a := range assignments {
		roleTone := "info"
		if a.RoleName == "Global Administrator" {
			roleTone = "danger"
		}
		rows = append(rows, []model.GlobalReportCell{
			{Text: t.Name}, {Badge: a.RoleName, Tone: roleTone},
			{Text: a.MemberName}, {Text: a.MemberUPN}, {Text: a.MemberType},
		})
	}
	return rows, nil
}

func (s *Service) caExclusionRows(ctx context.Context, t model.Tenant) ([][]model.GlobalReportCell, error) {
	exclusions, err := s.provider.CAExclusions(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	rows := make([][]model.GlobalReportCell, 0, len(exclusions))
	for _, e := range exclusions {
		stateTone := "success"
		switch e.State {
		case "reportOnly":
			stateTone = "warning"
		case "disabled":
			stateTone = "neutral"
		}
		rows = append(rows, []model.GlobalReportCell{
			{Text: t.Name}, {Text: e.PolicyName}, {Badge: e.State, Tone: stateTone},
			{Text: e.Type}, {Text: e.Target},
		})
	}
	return rows, nil
}

// appCredentialRows lists app secrets/certificates that are expired or expire
// within the window — the actionable subset, not the whole inventory.
func (s *Service) appCredentialRows(ctx context.Context, t model.Tenant) ([][]model.GlobalReportCell, error) {
	creds, err := s.provider.AppCredentials(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	horizon := now.Add(appCredentialWindow)
	rows := [][]model.GlobalReportCell{}
	for _, c := range creds {
		if c.ExpiresAt == "" {
			continue
		}
		expires, err := time.Parse(time.RFC3339, c.ExpiresAt)
		if err != nil || expires.After(horizon) {
			continue
		}
		status, tone := "Expiring soon", "warning"
		if expires.Before(now) {
			status, tone = "Expired", "danger"
		}
		rows = append(rows, []model.GlobalReportCell{
			{Text: t.Name}, {Text: c.AppName}, {Text: c.Type},
			{Text: expires.Format("2006-01-02")}, {Badge: status, Tone: tone},
		})
	}
	return rows, nil
}

// ago renders an RFC3339 timestamp as a rough "N days ago" — the resolution
// these reports need.
func ago(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "—"
	}
	days := int(time.Since(t).Hours() / 24)
	switch {
	case days <= 0:
		return "today"
	case days == 1:
		return "1 day ago"
	case days < 365:
		return fmt.Sprintf("%d days ago", days)
	default:
		return fmt.Sprintf("%.1f years ago", float64(days)/365)
	}
}
