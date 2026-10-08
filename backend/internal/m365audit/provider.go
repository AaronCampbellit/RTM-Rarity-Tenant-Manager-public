// Package m365audit ingests the Microsoft 365 Management Activity API and
// evaluates RTM-owned, versioned detections over normalized audit events.
package m365audit

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/rarity/rtm/internal/model"
)

const (
	Permission      = "ActivityFeed.Read"
	GraphPermission = "AuditLog.Read.All"
	ModeLive        = "live"
	ModeSample      = "sample"
)

const (
	ContentTypeEntraSignIn         = "Graph.SignIn"
	ContentTypeEntraDirectoryAudit = "Graph.DirectoryAudit"
)

var FastIdentityContentTypes = []string{
	ContentTypeEntraSignIn,
	ContentTypeEntraDirectoryAudit,
}

var ContentTypes = []string{
	"Audit.AzureActiveDirectory",
	"Audit.Exchange",
	"Audit.SharePoint",
	"Audit.General",
}

var ErrNotConfigured = errors.New("m365 audit: no application credentials configured")

type APIError struct {
	Status  int
	Code    string
	Message string
	Path    string
}

func (e *APIError) Error() string {
	return "m365 audit " + e.Path + ": " + e.Code + ": " + e.Message
}

type Config struct {
	ClientID     string
	ClientSecret string
	TenantID     string
}

type Auth struct {
	Authority    string
	ClientID     string
	ClientSecret string
}

type AuthResolver func(context.Context, string) (Auth, error)

type Provider interface {
	Mode(ctx context.Context, tenantID string) (string, error)
	Collect(ctx context.Context, tenantID, contentType string, start, end time.Time) ([]model.SecurityAuditEvent, error)
	CollectFastIdentity(ctx context.Context, tenantID, contentType string, start, end time.Time) ([]model.SecurityAuditEvent, error)
	Preflight(ctx context.Context, tenantID string) model.PreflightCheck
	FastIdentityPreflight(ctx context.Context, tenantID string) model.PreflightCheck
}

func NewProvider(cfg Config, log *slog.Logger, resolve AuthResolver) Provider {
	return newClient(cfg, log, resolve)
}
