package graph

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const (
	resourceMicrosoftGraph   = "Microsoft Graph"
	resourceSharePointOnline = "SharePoint Online"
	resourceExchangeOnline   = "Exchange Online"
)

// permissionParents is deliberately conservative. It models effective
// application-permission coverage, not naming similarity.
var permissionParents = map[string]map[string][]string{
	resourceMicrosoftGraph: {
		"User.Read.All":                 {"User.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
		"User.ReadWrite.All":            {"Directory.ReadWrite.All"},
		"Group.Read.All":                {"Group.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
		"GroupMember.Read.All":          {"GroupMember.ReadWrite.All", "Group.Read.All", "Group.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
		"GroupMember.ReadWrite.All":     {"Group.ReadWrite.All", "Directory.ReadWrite.All"},
		"Organization.Read.All":         {"Directory.Read.All", "Directory.ReadWrite.All"},
		"Application.Read.All":          {"Application.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"},
		"RoleManagement.Read.Directory": {"Directory.Read.All", "Directory.ReadWrite.All"},
	},
}

func resolveEffectiveGrant(resource, required string, assigned map[string]struct{}) (string, string) {
	if _, ok := assigned[required]; ok {
		return "ok", ""
	}
	for _, parent := range permissionParents[resource][required] {
		if _, ok := assigned[parent]; ok {
			return "ok", parent
		}
	}
	return "missing", ""
}

// tokenRoleSet reads the roles claim from an access token received directly
// from Microsoft over TLS. Signature validation is unnecessary here: RTM is
// not accepting a caller-supplied token or using these claims for access
// control; it is reporting the permission set Microsoft issued to RTM.
func tokenRoleSet(token string) (map[string]struct{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("Microsoft returned an opaque access token; application roles could not be inspected")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("Microsoft access token roles could not be decoded")
	}
	var claims struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("Microsoft access token claims could not be decoded")
	}
	roles := make(map[string]struct{}, len(claims.Roles))
	for _, role := range claims.Roles {
		roles[role] = struct{}{}
	}
	return roles, nil
}
