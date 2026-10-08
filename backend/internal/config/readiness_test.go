package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func readinessByName(t *testing.T, checks []IntegrationCheck, name string) IntegrationCheck {
	t.Helper()
	for _, check := range checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("readiness check %q missing from %+v", name, checks)
	return IntegrationCheck{}
}

func TestIntegrationReadinessClassifiesConfiguredIntegrations(t *testing.T) {
	dir := t.TempDir()
	certificate := filepath.Join(dir, "sharepoint.crt")
	privateKey := filepath.Join(dir, "sharepoint.key")
	if err := os.WriteFile(certificate, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKey, []byte("private-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		EntraClientID: "graph-id", EntraClientSecret: "graph-secret", EntraTenantID: "tenant-id",
		SharePointClientID: "sp-id", SharePointCertificatePath: certificate, SharePointPrivateKeyPath: privateKey,
		ThreatLockerInstance: "g", ThreatLockerToken: "tl-secret", ThreatLockerParentOrgID: "parent-id",
	}
	checks := cfg.IntegrationReadiness()
	for _, name := range []string{"graph", "sharepoint", "threatlocker"} {
		check := readinessByName(t, checks, name)
		if check.Mode != "live" || len(check.Missing) != 0 || len(check.Problems) != 0 {
			t.Fatalf("%s readiness = %+v", name, check)
		}
	}
}

func TestIntegrationReadinessReportsSafeMissingNames(t *testing.T) {
	cfg := &Config{SharePointClientID: "partial-id"}
	checks := cfg.IntegrationReadiness()

	graph := readinessByName(t, checks, "graph")
	if graph.Mode != "sample" || !reflect.DeepEqual(graph.Missing, []string{
		"RTM_ENTRA_CLIENT_ID", "RTM_ENTRA_CLIENT_SECRET", "RTM_ENTRA_TENANT_ID",
	}) {
		t.Fatalf("graph readiness = %+v", graph)
	}
	sharepoint := readinessByName(t, checks, "sharepoint")
	if sharepoint.Mode != "invalid" || !reflect.DeepEqual(sharepoint.Missing, []string{
		"RTM_SHAREPOINT_CERTIFICATE_PATH", "RTM_SHAREPOINT_PRIVATE_KEY_PATH",
	}) {
		t.Fatalf("sharepoint readiness = %+v", sharepoint)
	}
	threatlocker := readinessByName(t, checks, "threatlocker")
	if threatlocker.Mode != "not_configured" || len(threatlocker.Missing) != 3 {
		t.Fatalf("threatlocker readiness = %+v", threatlocker)
	}
}

func TestIntegrationReadinessReportsUnreadableSharePointFiles(t *testing.T) {
	cfg := &Config{
		SharePointClientID:        "sp-id",
		SharePointCertificatePath: "/missing/sharepoint.crt",
		SharePointPrivateKeyPath:  "/missing/sharepoint.key",
	}
	check := readinessByName(t, cfg.IntegrationReadiness(), "sharepoint")
	if check.Mode != "invalid" || !reflect.DeepEqual(check.Problems, []string{
		"certificate file is not readable", "private key file is not readable",
	}) {
		t.Fatalf("sharepoint readiness = %+v", check)
	}
}

func TestIntegrationReadinessDoesNotExposeSecrets(t *testing.T) {
	cfg := &Config{
		EntraClientID: "graph-id", EntraClientSecret: "graph-top-secret", EntraTenantID: "tenant-id",
		ThreatLockerInstance: "g", ThreatLockerToken: "threatlocker-top-secret", ThreatLockerParentOrgID: "parent-id",
	}
	raw, err := json.Marshal(cfg.IntegrationReadiness())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"graph-top-secret", "threatlocker-top-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("readiness output exposed %q: %s", secret, raw)
		}
	}
}
