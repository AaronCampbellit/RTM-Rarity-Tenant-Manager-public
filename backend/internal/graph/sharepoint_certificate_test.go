package graph

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func writeTestCertificate(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "RTM SharePoint Test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "sharepoint.cer")
	keyPath = filepath.Join(dir, "sharepoint.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestSharePointCertificateTokenUsesTargetTenantAndResource(t *testing.T) {
	certPath, keyPath := writeTestCertificate(t)
	f := newFakeGraph(t)
	c := newGraphClient(Config{
		SharePointClientID:        "central-sp-app",
		SharePointCertificatePath: certPath,
		SharePointPrivateKeyPath:  keyPath,
	}, testLogger(), func(context.Context, string) (TenantAuth, error) {
		return TenantAuth{Authority: "customer-tenant"}, nil
	})
	c.loginBase = f.srv.URL
	c.http = f.srv.Client()

	token, err := c.sharePointToken(context.Background(), "ten_1", "https://contoso.sharepoint.com")
	if err != nil {
		t.Fatalf("sharePointToken: %v", err)
	}
	if token != "tok-customer-tenant" {
		t.Fatalf("token = %q", token)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tokenClients) != 1 || f.tokenClients[0] != "central-sp-app" {
		t.Fatalf("clients = %v", f.tokenClients)
	}
	if len(f.tokenScopes) != 1 || f.tokenScopes[0] != "https://contoso.sharepoint.com/.default" {
		t.Fatalf("scopes = %v", f.tokenScopes)
	}
	if len(f.tokenAssertions) != 1 || f.tokenAssertions[0] == "" {
		t.Fatal("client assertion was not sent")
	}
}

func TestSharePointCertificateStatusExposesNoPrivateMaterial(t *testing.T) {
	certPath, keyPath := writeTestCertificate(t)
	c := newGraphClient(Config{
		SharePointClientID:        "central-sp-app",
		SharePointCertificatePath: certPath,
		SharePointPrivateKeyPath:  keyPath,
	}, testLogger(), nil)

	status := c.SharePointCertificateStatus()
	if !status.Configured || status.ClientID != "central-sp-app" || status.Thumbprint == "" || status.ExpiresAt == "" {
		t.Fatalf("status = %+v", status)
	}
}

func TestSharePointPreflightUsesResourceTokenRoles(t *testing.T) {
	certPath, keyPath := writeTestCertificate(t)
	f := newFakeGraph(t)
	f.tokenRolesByScope = map[string][]string{
		"https://graph.microsoft.com/.default": {"Directory.ReadWrite.All", "Sites.ReadWrite.All"},
		f.srv.URL + "/.default":                {"Sites.FullControl.All"},
	}
	f.responses["/sites/getAllSites"] = `{"value":[]}`
	f.responses["/users"] = `{"value":[]}`
	f.responses["/groups"] = `{"value":[]}`
	f.responses["/_api/web"] = `{"Title":"Admin"}`
	c := newGraphClient(Config{
		SharePointClientID:        "central-sp-app",
		SharePointCertificatePath: certPath,
		SharePointPrivateKeyPath:  keyPath,
	}, testLogger(), func(context.Context, string) (TenantAuth, error) {
		return TenantAuth{Authority: "customer-tenant", SharePointAdminURL: f.srv.URL}, nil
	})
	c.base, c.loginBase, c.http = f.srv.URL, f.srv.URL, f.srv.Client()

	checks := c.SharePointPreflight(context.Background(), "ten_1")
	byPermission := map[string]model.PreflightCheck{}
	for _, check := range checks {
		byPermission[check.Resource+"|"+check.Permission] = check
		if check.Status == "unchecked" {
			t.Fatalf("unchecked row = %+v", check)
		}
	}
	if got := byPermission["Microsoft Graph|GroupMember.Read.All"]; got.Status != "ok" || got.GrantedVia != "Directory.ReadWrite.All" {
		t.Fatalf("group member check = %+v", got)
	}
	if got := byPermission["Microsoft Graph|Sites.ReadWrite.All"]; got.Status != "ok" || got.GrantedVia != "" {
		t.Fatalf("sites write check = %+v", got)
	}
	if got := byPermission["SharePoint Online|Sites.FullControl.All"]; got.Status != "ok" {
		t.Fatalf("SharePoint full control check = %+v", got)
	}
}

func TestSharePointRESTRoleAssignmentsAndWriteUseCertificateApp(t *testing.T) {
	certPath, keyPath := writeTestCertificate(t)
	f := newFakeGraph(t)
	siteURL := f.srv.URL + "/sites/ops"
	f.responses["/sites/s1"] = `{"webUrl":"` + siteURL + `"}`
	f.responses["/sites/ops/_api/web"] = `{"HasUniqueRoleAssignments":true}`
	f.responses["/sites/ops/_api/web/roleassignments"] = `{"value":[
		{"PrincipalId":7,"Member":{"Id":7,"Title":"Operations Security","LoginName":"c:0t.c|tenant|group-id","PrincipalType":4},
		 "RoleDefinitionBindings":[{"Name":"Read"}]}
	]}`
	f.responses["/sites/ops/_api/web/ensureuser"] = `{"Id":11}`
	f.responses["/sites/ops/_api/web/roledefinitions/getbyname('Read')"] = `{"Id":1073741826}`
	f.responses["/sites/ops/_api/web/roleassignments/addroleassignment(principalid=11,roledefid=1073741826)"] = `{}`

	c := newGraphClient(Config{
		SharePointClientID:        "central-sp-app",
		SharePointCertificatePath: certPath,
		SharePointPrivateKeyPath:  keyPath,
	}, testLogger(), func(context.Context, string) (TenantAuth, error) {
		return TenantAuth{Authority: "customer-tenant"}, nil
	})
	c.base, c.loginBase, c.http = f.srv.URL, f.srv.URL, f.srv.Client()
	target := model.SharePointPermissionTarget{SiteID: "s1", Kind: "site", Path: "/"}

	permissions, err := c.SharePointScopePermissions(context.Background(), "ten_1", target)
	if err != nil {
		t.Fatalf("SharePointScopePermissions: %v", err)
	}
	if len(permissions) != 1 || permissions[0].Type != "Security Group" || permissions[0].Role != "Read" {
		t.Fatalf("permissions = %+v", permissions)
	}
	if err := c.SetSharePointScopePermission(context.Background(), "ten_1", model.SharePointPermissionChange{
		Target: target, PrincipalID: "group-id", PrincipalUPN: "c:0t.c|tenant|group-id",
		Role: "Read", Operation: "grant",
	}); err != nil {
		t.Fatalf("SetSharePointScopePermission: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	found := false
	for _, call := range f.apiCalls {
		if call == "POST /sites/ops/_api/web/roleassignments/addroleassignment(principalid=11,roledefid=1073741826)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("role assignment call missing: %v", f.apiCalls)
	}
}
