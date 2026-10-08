package graph

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rarity/rtm/internal/model"
)

func sharePointSiteBase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid SharePoint site URL")
	}
	return u.Scheme + "://" + u.Host + strings.TrimSuffix(u.Path, "/"), nil
}

func sharePointResource(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid SharePoint URL")
	}
	return u.Scheme + "://" + u.Host, nil
}

func odataString(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func (c *graphClient) sharePointFolderHasUnique(ctx context.Context, tenantID, siteURL, folderURL string) (bool, error) {
	siteBase, err := sharePointSiteBase(siteURL)
	if err != nil {
		return false, err
	}
	resource, err := sharePointResource(siteURL)
	if err != nil {
		return false, err
	}
	folder, err := url.Parse(folderURL)
	if err != nil || folder.Path == "" {
		return false, fmt.Errorf("invalid folder URL")
	}
	endpoint := siteBase + "/_api/web/GetFolderByServerRelativePath(decodedurl='" +
		odataString(folder.EscapedPath()) + "')/ListItemAllFields?$select=HasUniqueRoleAssignments"
	var out struct {
		HasUniqueRoleAssignments bool `json:"HasUniqueRoleAssignments"`
		D                        struct {
			HasUniqueRoleAssignments bool `json:"HasUniqueRoleAssignments"`
		} `json:"d"`
	}
	if err := c.certificateGet(ctx, tenantID, resource, endpoint, &out); err != nil {
		return false, err
	}
	return out.HasUniqueRoleAssignments || out.D.HasUniqueRoleAssignments, nil
}

func (c *graphClient) sharePointTargetURLs(ctx context.Context, tenantID string, target model.SharePointPermissionTarget) (siteBase, resource, securable string, err error) {
	var site struct {
		WebURL string `json:"webUrl"`
	}
	if err = c.sharePointGraphGet(ctx, tenantID, "/sites/"+url.PathEscape(target.SiteID)+"?$select=webUrl", &site); err != nil {
		return
	}
	siteBase, err = sharePointSiteBase(site.WebURL)
	if err != nil {
		return
	}
	resource, err = sharePointResource(site.WebURL)
	if err != nil {
		return
	}
	if target.Kind == "site" {
		securable = siteBase + "/_api/web"
		return
	}
	var item struct {
		WebURL string `json:"webUrl"`
	}
	itemPath := "/drives/" + url.PathEscape(target.DriveID) + "/root?$select=webUrl"
	if target.ItemID != "" {
		itemPath = "/drives/" + url.PathEscape(target.DriveID) + "/items/" + url.PathEscape(target.ItemID) + "?$select=webUrl"
	}
	if err = c.sharePointGraphGet(ctx, tenantID, itemPath, &item); err != nil {
		return
	}
	parsed, parseErr := url.Parse(item.WebURL)
	if parseErr != nil || parsed.Path == "" {
		err = fmt.Errorf("invalid SharePoint target URL")
		return
	}
	kind := "GetFolderByServerRelativePath"
	if target.Kind == "file" {
		kind = "GetFileByServerRelativePath"
	}
	securable = siteBase + "/_api/web/" + kind + "(decodedurl='" + odataString(parsed.EscapedPath()) + "')/ListItemAllFields"
	return
}

func (c *graphClient) SharePointScopePermissions(ctx context.Context, tenantID string, target model.SharePointPermissionTarget) ([]model.SharePointScopePermission, error) {
	_, resource, securable, err := c.sharePointTargetURLs(ctx, tenantID, target)
	if err != nil {
		return nil, err
	}
	var unique struct {
		HasUniqueRoleAssignments bool `json:"HasUniqueRoleAssignments"`
	}
	if err := c.certificateGet(ctx, tenantID, resource, securable+"?$select=HasUniqueRoleAssignments", &unique); err != nil {
		return nil, err
	}
	var out struct {
		Value []struct {
			PrincipalID int `json:"PrincipalId"`
			Member      struct {
				ID            int    `json:"Id"`
				Title         string `json:"Title"`
				LoginName     string `json:"LoginName"`
				PrincipalType int    `json:"PrincipalType"`
			} `json:"Member"`
			Bindings []struct {
				Name string `json:"Name"`
			} `json:"RoleDefinitionBindings"`
		} `json:"value"`
	}
	endpoint := securable + "/roleassignments?$expand=Member,RoleDefinitionBindings&" +
		"$select=PrincipalId,Member/Id,Member/Title,Member/LoginName,Member/PrincipalType,RoleDefinitionBindings/Name"
	if err := c.certificateGet(ctx, tenantID, resource, endpoint, &out); err != nil {
		return nil, err
	}
	permissions := []model.SharePointScopePermission{}
	for _, assignment := range out.Value {
		role := ""
		for _, binding := range assignment.Bindings {
			if binding.Name == "Limited Access" {
				continue
			}
			if role == "" || role == SiteRoleRead {
				role = binding.Name
			}
		}
		if role == "" {
			continue
		}
		typ := sharePointPrincipalType(assignment.Member.PrincipalType, assignment.Member.LoginName)
		permission := model.SharePointScopePermission{
			ID: strconv.Itoa(assignment.PrincipalID), PrincipalID: strconv.Itoa(assignment.Member.ID),
			Principal: assignment.Member.Title, PrincipalUPN: assignment.Member.LoginName,
			Type: typ, Role: role, Source: "Direct",
			Expandable: typ == "Security Group" || typ == "Microsoft 365 Group" || typ == "SharePoint Group",
		}
		if target.Kind != "site" && !unique.HasUniqueRoleAssignments {
			source := model.SharePointPermissionTarget{SiteID: target.SiteID, Kind: "site", Path: "/"}
			permission.Inherited = true
			permission.Source = "Inherited from parent scope"
			permission.SourceTarget = &source
		}
		permissions = append(permissions, permission)
	}
	return permissions, nil
}

func sharePointPrincipalType(principalType int, loginName string) string {
	switch principalType {
	case 4:
		return "Security Group"
	case 8:
		return "SharePoint Group"
	}
	if strings.Contains(strings.ToLower(loginName), "#ext#") {
		return "Guest"
	}
	return "User"
}

func (c *graphClient) SetSharePointScopePermission(ctx context.Context, tenantID string, change model.SharePointPermissionChange) error {
	siteBase, resource, securable, err := c.sharePointTargetURLs(ctx, tenantID, change.Target)
	if err != nil {
		return err
	}
	if change.Operation == "restore_inheritance" {
		return c.certificateSend(ctx, tenantID, resource, http.MethodPost, securable+"/resetroleinheritance", nil, nil)
	}
	if change.BreakInheritance {
		copyAssignments := "false"
		if change.CopyAssignments {
			copyAssignments = "true"
		}
		if err := c.certificateSend(ctx, tenantID, resource, http.MethodPost,
			securable+"/breakroleinheritance(copyRoleAssignments="+copyAssignments+",clearSubscopes=false)", nil, nil); err != nil {
			return err
		}
	}
	login := change.PrincipalUPN
	if login == "" {
		login = change.PrincipalID
		if change.PrincipalType == "Security Group" || change.PrincipalType == "Microsoft 365 Group" {
			login = "c:0t.c|tenant|" + change.PrincipalID
		}
	}
	var ensured struct {
		ID int `json:"Id"`
		D  struct {
			ID int `json:"Id"`
		} `json:"d"`
	}
	if err := c.certificateSend(ctx, tenantID, resource, http.MethodPost, siteBase+"/_api/web/ensureuser",
		map[string]string{"logonName": login}, &ensured); err != nil {
		return err
	}
	principalID := ensured.ID
	if principalID == 0 {
		principalID = ensured.D.ID
	}
	if principalID == 0 {
		return fmt.Errorf("SharePoint did not resolve principal %s", login)
	}
	var roleDef struct {
		ID int `json:"Id"`
		D  struct {
			ID int `json:"Id"`
		} `json:"d"`
	}
	role := change.Role
	if role == "" {
		role = SiteRoleRead
	}
	if err := c.certificateGet(ctx, tenantID, resource,
		siteBase+"/_api/web/roledefinitions/getbyname('"+odataString(role)+"')?$select=Id", &roleDef); err != nil {
		return err
	}
	roleID := roleDef.ID
	if roleID == 0 {
		roleID = roleDef.D.ID
	}
	action := "addroleassignment"
	if change.Operation == "revoke" {
		action = "removeroleassignment"
	}
	endpoint := fmt.Sprintf("%s/roleassignments/%s(principalid=%d,roledefid=%d)", securable, action, principalID, roleID)
	return c.certificateSend(ctx, tenantID, resource, http.MethodPost, endpoint, nil, nil)
}
