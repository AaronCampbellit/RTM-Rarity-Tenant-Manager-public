package config

import "testing"

func TestLoadReadsThreatLockerParentOrgID(t *testing.T) {
	t.Setenv("RTM_ENV", "development")
	t.Setenv("RTM_THREATLOCKER_PARENT_ORG_ID", "org_parent")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ThreatLockerParentOrgID != "org_parent" {
		t.Fatalf("ThreatLockerParentOrgID = %q, want org_parent", cfg.ThreatLockerParentOrgID)
	}
}

func TestLoadRejectsCommittedDemoJWTKeyInProduction(t *testing.T) {
	t.Setenv("RTM_ENV", "production")
	t.Setenv("RTM_DATABASE_URL", "postgres://example")
	t.Setenv("RTM_JWT_SIGNING_KEY", "rtm-demo-signing-key-7f3a2c9d5e1b4a86-change-me")
	t.Setenv("RTM_FIELD_ENCRYPTION_KEY", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted the committed demo JWT key in production")
	}
}

func TestLoadRequiresFieldEncryptionKeyInProduction(t *testing.T) {
	t.Setenv("RTM_ENV", "production")
	t.Setenv("RTM_DATABASE_URL", "postgres://example")
	t.Setenv("RTM_JWT_SIGNING_KEY", "not-the-demo-key")
	t.Setenv("RTM_FIELD_ENCRYPTION_KEY", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted production without field encryption key")
	}
}

func TestLoadReadsCentralSharePointCertificateConfig(t *testing.T) {
	t.Setenv("RTM_ENV", "development")
	t.Setenv("RTM_SHAREPOINT_CLIENT_ID", "sharepoint-app")
	t.Setenv("RTM_SHAREPOINT_CERTIFICATE_PATH", "/run/secrets/rtm-sharepoint.cer")
	t.Setenv("RTM_SHAREPOINT_PRIVATE_KEY_PATH", "/run/secrets/rtm-sharepoint.key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SharePointClientID != "sharepoint-app" ||
		cfg.SharePointCertificatePath != "/run/secrets/rtm-sharepoint.cer" ||
		cfg.SharePointPrivateKeyPath != "/run/secrets/rtm-sharepoint.key" {
		t.Fatalf("SharePoint config = %+v", cfg)
	}
}

func TestLoadRejectsPartialSharePointCertificateConfig(t *testing.T) {
	t.Setenv("RTM_ENV", "development")
	t.Setenv("RTM_SHAREPOINT_CLIENT_ID", "sharepoint-app")
	t.Setenv("RTM_SHAREPOINT_CERTIFICATE_PATH", "")
	t.Setenv("RTM_SHAREPOINT_PRIVATE_KEY_PATH", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load accepted a partial SharePoint certificate configuration")
	}
}
