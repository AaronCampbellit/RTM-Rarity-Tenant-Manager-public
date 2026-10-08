// Package reports builds the cross-tenant global reports (read-only by
// design — Security Spec). It is the fan-out layer above the per-tenant
// graph.Provider: it loops the managed tenants from the store, reads each one
// with its own Graph calls (and, in live mode, its own app-only token via the
// provider's authority resolver), and merges the rows into a single report.
//
// A tenant that fails to read is skipped and logged rather than failing the
// whole report — MSP operators still want the other tenants' rows. Only when
// every tenant fails does the report error.
package reports

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/threatlocker"
)

// TenantSource lists the managed tenants to fan out over (satisfied by
// store.Store).
type TenantSource interface {
	Tenants(ctx context.Context) ([]model.Tenant, error)
}

// maxConcurrent bounds parallel per-tenant reads so a large tenant list can't
// stampede Graph (throttling) or the API's outbound connections.
const maxConcurrent = 4

type Service struct {
	tenants  TenantSource
	provider graph.Provider
	tl       threatlocker.Provider
	log      *slog.Logger
}

func New(ts TenantSource, p graph.Provider, tlp threatlocker.Provider, log *slog.Logger) *Service {
	return &Service{tenants: ts, provider: p, tl: tlp, log: log}
}

// Global builds the cross-tenant report of the given type. In sample mode the
// provider's seeded cross-tenant dataset is returned as-is (it is the demo
// fixture); in live mode the report is assembled by fanning out over the
// managed tenants.
func (s *Service) Global(ctx context.Context, reportType string) (model.GlobalReport, error) {
	if reportType == "threatlocker" {
		rows, err := s.threatLockerRow(ctx, model.Tenant{Name: "MSP workspace"})
		return model.GlobalReport{Columns: columnsFor(reportType), Rows: rows}, err
	}
	// The Entra readiness reports fan out in every mode: their per-family
	// provider reads have sample implementations, so there is no separate
	// seeded report fixture to serve.
	if s.provider.Mode() == "sample" && !isEntraReport(reportType) {
		return s.provider.GlobalReport(ctx, reportType)
	}

	tenants, err := s.tenants.Tenants(ctx)
	if err != nil {
		return model.GlobalReport{}, err
	}

	report := model.GlobalReport{Columns: columnsFor(reportType)}
	if len(tenants) == 0 {
		return report, nil
	}

	// Fan out with bounded concurrency, keeping per-tenant results indexed so
	// the merged report preserves the tenant list's order.
	rows := make([][][]model.GlobalReportCell, len(tenants))
	errs := make([]error, len(tenants))
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for i, t := range tenants {
		wg.Add(1)
		go func(i int, t model.Tenant) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rows[i], errs[i] = s.tenantRows(ctx, t, reportType)
		}(i, t)
	}
	wg.Wait()

	failed := 0
	var firstErr error
	for i, t := range tenants {
		if errs[i] != nil {
			failed++
			if firstErr == nil {
				firstErr = errs[i]
			}
			s.log.Warn("global report: tenant skipped", "tenant", t.Name, "report", reportType, "error", errs[i])
			continue
		}
		report.Rows = append(report.Rows, rows[i]...)
	}
	if failed == len(tenants) {
		return model.GlobalReport{}, fmt.Errorf("global report %q: all %d tenants failed: %w", reportType, failed, firstErr)
	}
	return report, nil
}

func columnsFor(reportType string) []string {
	if cols, ok := entraReportColumns[reportType]; ok {
		return cols
	}
	switch reportType {
	case "license":
		return []string{"Tenant", "SKU", "Product", "Assigned", "Total", "Utilization"}
	case "threatlocker":
		return []string{"Workspace", "Devices", "Secured", "Reduced Protection", "Pending Approvals", "Offline > 7d"}
	default:
		return []string{"Tenant", "Display Name", "UPN", "MFA State", "Status", "Last Sign-in"}
	}
}

// tenantRows reads one tenant and renders its rows for the report type. The
// provider is keyed by RTM tenant id; in live mode it resolves that to the
// tenant's own Entra authority.
func (s *Service) tenantRows(ctx context.Context, t model.Tenant, reportType string) ([][]model.GlobalReportCell, error) {
	if reportType == "threatlocker" {
		return s.threatLockerRow(ctx, t)
	}
	if isEntraReport(reportType) {
		return s.entraRows(ctx, t, reportType)
	}
	if reportType == "license" {
		lics, err := s.provider.Licenses(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		rows := make([][]model.GlobalReportCell, 0, len(lics))
		for _, l := range lics {
			rows = append(rows, []model.GlobalReportCell{
				{Text: t.Name}, {Text: l.SKU}, {Text: l.Product},
				{Text: strconv.Itoa(l.Assigned)}, {Text: strconv.Itoa(l.Total)}, {Text: strconv.Itoa(l.Utilization) + "%"},
			})
		}
		return rows, nil
	}

	// "mfa", "inactive", "guests" all derive from the tenant's directory.
	return s.directoryRows(ctx, t, reportType)
}

// threatLockerRow summarizes the single global ThreatLocker workspace.
func (s *Service) threatLockerRow(ctx context.Context, t model.Tenant) ([][]model.GlobalReportCell, error) {
	devices, err := s.tl.Devices(ctx, t.ID)
	if errors.Is(err, threatlocker.ErrNotConnected) {
		return [][]model.GlobalReportCell{{
			{Text: t.Name}, {Badge: "Not connected", Tone: "neutral"},
			{Text: "—"}, {Text: "—"}, {Text: "—"}, {Text: "—"},
		}}, nil
	}
	if err != nil {
		return nil, err
	}
	pending, err := s.tl.ApprovalRequests(ctx, t.ID, threatlocker.RequestPending)
	if err != nil {
		return nil, err
	}
	secured, reduced, offline := 0, 0, 0
	weekAgo := time.Now().Add(-7 * 24 * time.Hour)
	for _, d := range devices {
		switch d.Mode {
		case threatlocker.ModeSecured, threatlocker.ModeLockdown, threatlocker.ModeIsolated:
			secured++
		default:
			reduced++
		}
		if !d.Online {
			if last, err := time.Parse(time.RFC3339, d.LastCheckIn); err == nil && last.Before(weekAgo) {
				offline++
			}
		}
	}
	reducedTone, pendingTone := "success", "success"
	if reduced > 0 {
		reducedTone = "warning"
	}
	if len(pending) > 0 {
		pendingTone = "warning"
	}
	return [][]model.GlobalReportCell{{
		{Text: t.Name},
		{Text: strconv.Itoa(len(devices))},
		{Text: strconv.Itoa(secured)},
		{Badge: strconv.Itoa(reduced), Tone: reducedTone},
		{Badge: strconv.Itoa(len(pending)), Tone: pendingTone},
		{Text: strconv.Itoa(offline)},
	}}, nil
}

func (s *Service) directoryRows(ctx context.Context, t model.Tenant, reportType string) ([][]model.GlobalReportCell, error) {
	users, err := s.provider.Users(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	rows := make([][]model.GlobalReportCell, 0, len(users))
	for _, u := range users {
		switch reportType {
		case "guests":
			if u.Status != "Guest" {
				continue
			}
		case "inactive":
			// Graph sign-in activity needs a premium license; disabled accounts
			// are the reliable inactivity signal available app-only.
			if u.Status != "Disabled" {
				continue
			}
		}
		mfaTone := "danger"
		if u.MFA == "Enabled" || u.MFA == "Enforced" {
			mfaTone = "success"
		}
		rows = append(rows, []model.GlobalReportCell{
			{Text: t.Name}, {Text: u.Name}, {Text: u.UPN},
			{Badge: u.MFA, Tone: mfaTone}, {Text: u.Status}, {Text: u.LastSignIn},
		})
	}
	return rows, nil
}
