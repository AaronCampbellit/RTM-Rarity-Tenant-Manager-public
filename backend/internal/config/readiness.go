package config

import "os"

// IntegrationCheck is safe to print in logs or CI output: it contains only
// integration state, environment-variable names, and non-sensitive problem
// categories. Credential values and configured paths are deliberately absent.
type IntegrationCheck struct {
	Name     string   `json:"name"`
	Mode     string   `json:"mode"`
	Missing  []string `json:"missing,omitempty"`
	Problems []string `json:"problems,omitempty"`
}

type readinessField struct {
	name  string
	value string
}

// IntegrationReadiness classifies the optional live providers without
// exposing their credential values. Local sample mode remains valid.
func (c *Config) IntegrationReadiness() []IntegrationCheck {
	graphMissing := missingReadinessFields([]readinessField{
		{name: "RTM_ENTRA_CLIENT_ID", value: c.EntraClientID},
		{name: "RTM_ENTRA_CLIENT_SECRET", value: c.EntraClientSecret},
		{name: "RTM_ENTRA_TENANT_ID", value: c.EntraTenantID},
	})
	graph := IntegrationCheck{Name: "graph", Mode: "live"}
	if len(graphMissing) > 0 {
		graph.Mode = "sample"
		graph.Missing = graphMissing
	}

	sharePointFields := []readinessField{
		{name: "RTM_SHAREPOINT_CLIENT_ID", value: c.SharePointClientID},
		{name: "RTM_SHAREPOINT_CERTIFICATE_PATH", value: c.SharePointCertificatePath},
		{name: "RTM_SHAREPOINT_PRIVATE_KEY_PATH", value: c.SharePointPrivateKeyPath},
	}
	sharePointMissing := missingReadinessFields(sharePointFields)
	sharepoint := IntegrationCheck{Name: "sharepoint", Mode: "live"}
	if len(sharePointMissing) == len(sharePointFields) {
		sharepoint.Mode = "not_configured"
		sharepoint.Missing = sharePointMissing
	} else if len(sharePointMissing) > 0 {
		sharepoint.Mode = "invalid"
		sharepoint.Missing = sharePointMissing
	} else {
		if !readableFile(c.SharePointCertificatePath) {
			sharepoint.Problems = append(sharepoint.Problems, "certificate file is not readable")
		}
		if !readableFile(c.SharePointPrivateKeyPath) {
			sharepoint.Problems = append(sharepoint.Problems, "private key file is not readable")
		}
		if len(sharepoint.Problems) > 0 {
			sharepoint.Mode = "invalid"
		}
	}

	threatLockerMissing := missingReadinessFields([]readinessField{
		{name: "RTM_THREATLOCKER_INSTANCE", value: c.ThreatLockerInstance},
		{name: "RTM_THREATLOCKER_TOKEN", value: c.ThreatLockerToken},
		{name: "RTM_THREATLOCKER_PARENT_ORG_ID", value: c.ThreatLockerParentOrgID},
	})
	threatlocker := IntegrationCheck{Name: "threatlocker", Mode: "live"}
	if len(threatLockerMissing) > 0 {
		threatlocker.Mode = "not_configured"
		threatlocker.Missing = threatLockerMissing
	}

	return []IntegrationCheck{graph, sharepoint, threatlocker}
}

func missingReadinessFields(fields []readinessField) []string {
	missing := make([]string, 0, len(fields))
	for _, field := range fields {
		if field.value == "" {
			missing = append(missing, field.name)
		}
	}
	return missing
}

func readableFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	return file.Close() == nil
}
