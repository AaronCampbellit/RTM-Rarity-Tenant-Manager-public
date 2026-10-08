// Package config loads system configuration from environment variables
// (ADR-017, layer 1). Secrets stay in env / a future secrets manager and are
// never written to application logs.
package config

import (
	"fmt"
	"os"
)

const committedDemoJWTKey = "rtm-demo-signing-key-7f3a2c9d5e1b4a86-change-me"

type Config struct {
	Env         string // development | production
	HTTPAddr    string // e.g. ":8080"
	DatabaseURL string // PostgreSQL DSN (empty → in-memory store)
	CORSOrigin  string // allowed frontend origin
	LogLevel    string // debug | info | warn | error

	JWTSigningKey      string // HMAC key for RTM JWTs (required in production)
	FieldEncryptionKey string // base64 32-byte key for tenant credential encryption

	// Microsoft Entra app (client-credentials / app-only). Empty → sample Graph.
	EntraClientID     string
	EntraClientSecret string
	EntraTenantID     string

	// Central multi-tenant SharePoint administration app. SharePoint REST
	// app-only authentication requires a certificate; the private key stays in
	// the deployment secret store and is never accepted through the RTM API.
	SharePointClientID        string
	SharePointCertificatePath string
	SharePointPrivateKeyPath  string

	// Global ThreatLocker MSP parent-org API credentials (optional fallback —
	// tenants can instead carry their own instance/token). Tenants still need
	// their own organization ID; no creds at all → NOT_CONNECTED.
	ThreatLockerInstance    string
	ThreatLockerToken       string
	ThreatLockerParentOrgID string
}

// Load reads configuration and validates it at startup (ADR-017).
func Load() (*Config, error) {
	c := &Config{
		Env:                       env("RTM_ENV", "development"),
		HTTPAddr:                  env("RTM_HTTP_ADDR", ":8080"),
		DatabaseURL:               env("RTM_DATABASE_URL", ""),
		CORSOrigin:                env("RTM_CORS_ORIGIN", "http://localhost:5173"),
		LogLevel:                  env("RTM_LOG_LEVEL", "info"),
		JWTSigningKey:             env("RTM_JWT_SIGNING_KEY", ""),
		FieldEncryptionKey:        env("RTM_FIELD_ENCRYPTION_KEY", ""),
		EntraClientID:             env("RTM_ENTRA_CLIENT_ID", ""),
		EntraClientSecret:         env("RTM_ENTRA_CLIENT_SECRET", ""),
		EntraTenantID:             env("RTM_ENTRA_TENANT_ID", ""),
		SharePointClientID:        env("RTM_SHAREPOINT_CLIENT_ID", ""),
		SharePointCertificatePath: env("RTM_SHAREPOINT_CERTIFICATE_PATH", ""),
		SharePointPrivateKeyPath:  env("RTM_SHAREPOINT_PRIVATE_KEY_PATH", ""),

		ThreatLockerInstance:    env("RTM_THREATLOCKER_INSTANCE", ""),
		ThreatLockerToken:       env("RTM_THREATLOCKER_TOKEN", ""),
		ThreatLockerParentOrgID: env("RTM_THREATLOCKER_PARENT_ORG_ID", ""),
	}

	spConfigured := 0
	for _, value := range []string{c.SharePointClientID, c.SharePointCertificatePath, c.SharePointPrivateKeyPath} {
		if value != "" {
			spConfigured++
		}
	}
	if spConfigured != 0 && spConfigured != 3 {
		return nil, fmt.Errorf("RTM_SHAREPOINT_CLIENT_ID, RTM_SHAREPOINT_CERTIFICATE_PATH, and RTM_SHAREPOINT_PRIVATE_KEY_PATH must be configured together")
	}

	if c.IsProduction() {
		if c.DatabaseURL == "" {
			return nil, fmt.Errorf("RTM_DATABASE_URL is required in production")
		}
		if c.JWTSigningKey == "" {
			return nil, fmt.Errorf("RTM_JWT_SIGNING_KEY is required in production")
		}
		if c.JWTSigningKey == committedDemoJWTKey {
			return nil, fmt.Errorf("RTM_JWT_SIGNING_KEY must not use the committed demo value")
		}
		if c.FieldEncryptionKey == "" {
			return nil, fmt.Errorf("RTM_FIELD_ENCRYPTION_KEY is required in production")
		}
	}
	return c, nil
}

func (c *Config) IsProduction() bool { return c.Env == "production" }

// StoreMode reports which store backs the API ("postgres" | "memory").
func (c *Config) StoreMode() string {
	if c.DatabaseURL != "" {
		return "postgres"
	}
	return "memory"
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
