// Package worker executes RTM write jobs: it performs the real Microsoft
// Graph mutations, advances the RTM job record, appends the change-history
// entry (with before/after state, execution log, and revert payload), and
// audits the outcome. It is shared by the River worker (Postgres deployments)
// and the inline executor (in-memory mode), so the pipeline behaves the same
// everywhere.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
)

// Payload describes one write job. It is serialized into the queue so the
// worker process can execute it without the API's request context.
type Payload struct {
	Action     string `json:"action"`
	TenantID   string `json:"tenantId"`
	TenantName string `json:"tenantName"`
	GroupID    string `json:"groupId,omitempty"` // group actions
	GroupName  string `json:"groupName,omitempty"`
	SkuID      string `json:"skuId,omitempty"` // license actions
	SkuName    string `json:"skuName,omitempty"`
	// UserIDs carries the per-target ids the worker iterates: user ids for
	// directory actions, mailbox ids for Exchange actions, site ids for
	// set_site_sharing. Field name is kept for payload compatibility.
	UserIDs    []string `json:"userIds"`
	Technician string   `json:"technician"`
	// RevertOf marks this run as the revert of an earlier change record.
	RevertOf string `json:"revertOf,omitempty"`

	// Exchange action parameters.
	ForwardTo        string `json:"forwardTo,omitempty"`        // set_forwarding
	AutoReplyMessage string `json:"autoReplyMessage,omitempty"` // enable_auto_reply
	Permission       string `json:"permission,omitempty"`       // mailbox permission actions
	DelegateID       string `json:"delegateId,omitempty"`
	DelegateName     string `json:"delegateName,omitempty"`

	// SharePoint action parameters.
	SiteID       string `json:"siteId,omitempty"` // site access actions
	SiteName     string `json:"siteName,omitempty"`
	Role         string `json:"role,omitempty"`         // site access actions
	SharingLevel string `json:"sharingLevel,omitempty"` // set_site_sharing

	// ThreatLocker action parameters. Device actions iterate UserIDs as device
	// ids; approval actions iterate them as approval-request ids.
	MaintenanceType string `json:"maintenanceType,omitempty"` // enter_maintenance_mode
	DurationMinutes int    `json:"durationMinutes,omitempty"` // enter_maintenance_mode
	Scope           string `json:"scope,omitempty"`           // approve_request permit scope
	ExpiresAt       string `json:"expiresAt,omitempty"`       // approve_request temporary permit
	Reason          string `json:"reason,omitempty"`          // deny_request
}

// The v1 write actions. Every one is What-If-gated, executed per user with
// partial-failure tolerance, recorded in change history, and audited.
const (
	ActionAddToGroup       = "add_to_group"
	ActionRemoveFromGroup  = "remove_from_group"
	ActionBlockSignIn      = "block_signin"
	ActionUnblockSignIn    = "unblock_signin"
	ActionAssignLicense    = "assign_license"
	ActionRemoveLicense    = "remove_license"
	ActionRevokeSessions   = "revoke_sessions"
	ActionResetPassword    = "reset_password"
	ActionRevokeUserAccess = "revoke_user_access"

	// Exchange actions (targets are mailboxes).
	ActionSetForwarding     = "set_forwarding"
	ActionClearForwarding   = "clear_forwarding"
	ActionEnableAutoReply   = "enable_auto_reply"
	ActionDisableAutoReply  = "disable_auto_reply"
	ActionGrantMailboxPerm  = "grant_mailbox_permission"
	ActionRevokeMailboxPerm = "revoke_mailbox_permission"

	// SharePoint actions. Site access targets users on one site;
	// set_site_sharing targets sites.
	ActionGrantSiteAccess  = "grant_site_access"
	ActionRevokeSiteAccess = "revoke_site_access"
	ActionSetSiteSharing   = "set_site_sharing"

	// ThreatLocker device actions (targets are devices).
	ActionEnterMaintenanceMode = "enter_maintenance_mode"
	ActionSecureDevice         = "secure_device"
	ActionLockdownDevice       = "lockdown_device"
	ActionReleaseLockdown      = "release_lockdown"
	ActionIsolateDevice        = "isolate_device"
	ActionReleaseIsolation     = "release_isolation"
	ActionEnableTamper         = "enable_tamper_protection"
	ActionDisableTamper        = "disable_tamper_protection"
	ActionRestartAgent         = "restart_agent"

	// ThreatLocker approval actions (targets are approval requests).
	ActionApproveRequest = "approve_request"
	ActionDenyRequest    = "deny_request"
)

// revertAction maps each action to the action that undoes it ("" = not
// revertible).
func revertAction(action string) string {
	switch action {
	case ActionAddToGroup:
		return ActionRemoveFromGroup
	case ActionRemoveFromGroup:
		return ActionAddToGroup
	case ActionBlockSignIn:
		return ActionUnblockSignIn
	case ActionUnblockSignIn:
		return ActionBlockSignIn
	case ActionAssignLicense:
		return ActionRemoveLicense
	case ActionRemoveLicense:
		return ActionAssignLicense
	case ActionSetForwarding:
		return ActionClearForwarding // clearing has no snapshot of prior state → one-way pair
	case ActionEnableAutoReply:
		return ActionDisableAutoReply
	case ActionGrantMailboxPerm:
		return ActionRevokeMailboxPerm
	case ActionRevokeMailboxPerm:
		return ActionGrantMailboxPerm
	case ActionGrantSiteAccess:
		return ActionRevokeSiteAccess
	case ActionRevokeSiteAccess:
		return ActionGrantSiteAccess
	case ActionEnterMaintenanceMode:
		return ActionSecureDevice // securing has no snapshot of prior mode → one-way pair
	case ActionLockdownDevice:
		return ActionReleaseLockdown
	case ActionReleaseLockdown:
		return ActionLockdownDevice
	case ActionIsolateDevice:
		return ActionReleaseIsolation
	case ActionReleaseIsolation:
		return ActionIsolateDevice
	case ActionEnableTamper:
		return ActionDisableTamper
	case ActionDisableTamper:
		return ActionEnableTamper
	default:
		// revoke_sessions (nothing to restore), clear_forwarding /
		// disable_auto_reply (prior per-mailbox state isn't snapshotted),
		// set_site_sharing (prior per-site level isn't snapshotted),
		// secure_device (prior mode/expiry isn't snapshotted), restart_agent
		// (nothing to restore), approve_request (the created ThreatLocker
		// policy isn't managed yet), deny_request (requester must resubmit).
		return ""
	}
}

// JobType is the display label for the jobs table.
func JobType(action string, isRevert bool) string {
	var label string
	switch action {
	case ActionAddToGroup, ActionRemoveFromGroup:
		label = "Group Membership Change"
	case ActionBlockSignIn:
		label = "Sign-in Block"
	case ActionUnblockSignIn:
		label = "Sign-in Unblock"
	case ActionAssignLicense:
		label = "License Assignment"
	case ActionRemoveLicense:
		label = "License Removal"
	case ActionRevokeSessions:
		label = "Session Revocation"
	case ActionResetPassword:
		label = "Password Reset"
	case ActionRevokeUserAccess:
		label = "Compromised User Containment"
	case ActionSetForwarding, ActionClearForwarding:
		label = "Mail Forwarding Change"
	case ActionEnableAutoReply, ActionDisableAutoReply:
		label = "Auto-Reply Change"
	case ActionGrantMailboxPerm, ActionRevokeMailboxPerm:
		label = "Mailbox Permission"
	case ActionGrantSiteAccess, ActionRevokeSiteAccess:
		label = "Site Access Change"
	case ActionSetSiteSharing:
		label = "Site Sharing Change"
	case ActionEnterMaintenanceMode, ActionSecureDevice:
		label = "Maintenance Mode Change"
	case ActionLockdownDevice, ActionReleaseLockdown:
		label = "Device Lockdown Change"
	case ActionIsolateDevice, ActionReleaseIsolation:
		label = "Device Isolation Change"
	case ActionEnableTamper, ActionDisableTamper:
		label = "Tamper Protection Change"
	case ActionRestartAgent:
		label = "Agent Restart"
	case ActionApproveRequest, ActionDenyRequest:
		label = "Approval Decision"
	default:
		label = "Change"
	}
	if isRevert {
		return "Revert — " + label
	}
	return label
}

// applyOne performs the action for a single target (user, mailbox, site,
// device, or approval request, per the action family).
func applyOne(ctx context.Context, gp graph.Provider, tlp threatlocker.Provider, p Payload, userID string) error {
	switch p.Action {
	case ActionEnterMaintenanceMode:
		return tlp.SetMaintenanceMode(ctx, p.TenantID, userID, p.MaintenanceType, p.DurationMinutes)
	case ActionSecureDevice:
		return tlp.SecureDevice(ctx, p.TenantID, userID)
	case ActionLockdownDevice:
		return tlp.SetLockdown(ctx, p.TenantID, userID, true)
	case ActionReleaseLockdown:
		return tlp.SetLockdown(ctx, p.TenantID, userID, false)
	case ActionIsolateDevice:
		return tlp.SetIsolation(ctx, p.TenantID, userID, true)
	case ActionReleaseIsolation:
		return tlp.SetIsolation(ctx, p.TenantID, userID, false)
	case ActionEnableTamper:
		return tlp.SetTamperProtection(ctx, p.TenantID, userID, true)
	case ActionDisableTamper:
		return tlp.SetTamperProtection(ctx, p.TenantID, userID, false)
	case ActionRestartAgent:
		return tlp.RestartAgent(ctx, p.TenantID, userID)
	case ActionApproveRequest:
		return tlp.ApproveRequest(ctx, p.TenantID, userID, p.Scope, p.ExpiresAt)
	case ActionDenyRequest:
		return tlp.DenyRequest(ctx, p.TenantID, userID, p.Reason)
	}
	switch p.Action {
	case ActionAddToGroup:
		return gp.AddGroupMembers(ctx, p.TenantID, p.GroupID, []string{userID})
	case ActionRemoveFromGroup:
		return gp.RemoveGroupMembers(ctx, p.TenantID, p.GroupID, []string{userID})
	case ActionBlockSignIn:
		return gp.SetAccountEnabled(ctx, p.TenantID, userID, false)
	case ActionUnblockSignIn:
		return gp.SetAccountEnabled(ctx, p.TenantID, userID, true)
	case ActionAssignLicense:
		return gp.AssignLicense(ctx, p.TenantID, userID, p.SkuID, false)
	case ActionRemoveLicense:
		return gp.AssignLicense(ctx, p.TenantID, userID, p.SkuID, true)
	case ActionRevokeSessions:
		return gp.RevokeSessions(ctx, p.TenantID, userID)
	case ActionSetForwarding:
		return gp.SetMailboxForwarding(ctx, p.TenantID, userID, p.ForwardTo)
	case ActionClearForwarding:
		return gp.SetMailboxForwarding(ctx, p.TenantID, userID, "")
	case ActionEnableAutoReply:
		return gp.SetAutoReply(ctx, p.TenantID, userID, true, p.AutoReplyMessage)
	case ActionDisableAutoReply:
		return gp.SetAutoReply(ctx, p.TenantID, userID, false, "")
	case ActionGrantMailboxPerm:
		return gp.SetMailboxPermission(ctx, p.TenantID, userID, p.DelegateID, p.Permission, false)
	case ActionRevokeMailboxPerm:
		return gp.SetMailboxPermission(ctx, p.TenantID, userID, p.DelegateID, p.Permission, true)
	case ActionGrantSiteAccess:
		return gp.SetSiteAccess(ctx, p.TenantID, p.SiteID, userID, p.Role, false)
	case ActionRevokeSiteAccess:
		return gp.SetSiteAccess(ctx, p.TenantID, p.SiteID, userID, p.Role, true)
	case ActionSetSiteSharing:
		return gp.SetSiteSharing(ctx, p.TenantID, userID, p.SharingLevel)
	default:
		return fmt.Errorf("unknown action %q", p.Action)
	}
}

// Process runs one job to completion. Per-user failures don't abort the job:
// the outcome is Completed (all ok), Partial (some ok), or Failed (none ok),
// always recorded honestly. Errors are recorded rather than returned so queue
// backends don't retry non-transient Graph errors like missing permissions.
func Process(ctx context.Context, st store.Store, gp graph.Provider, tlp threatlocker.Provider, log *slog.Logger, jobID, rawPayload string) {
	var p Payload
	if err := json.Unmarshal([]byte(rawPayload), &p); err != nil {
		log.Error("job payload unreadable", "job", jobID, "error", err)
		_ = st.CompleteJob(ctx, jobID, "Failed", "—")
		return
	}

	start := time.Now()
	_ = st.UpdateJobStatus(ctx, jobID, "Running", 20)
	logLines := []string{stamp() + "  Job started · " + describe(p)}

	// Member count before group writes, for the change record's before/after.
	before := -1
	if p.Action == ActionAddToGroup || p.Action == ActionRemoveFromGroup {
		if members, err := gp.GroupMembers(ctx, p.TenantID, p.GroupID); err == nil {
			before = len(members)
		}
	}

	// Execute per user; collect successes so a partial run reverts exactly
	// what happened.
	var succeeded []string
	var failures []string
	for i, uid := range p.UserIDs {
		if err := applyOne(ctx, gp, tlp, p, uid); err != nil {
			failures = append(failures, fmt.Sprintf("%s  FAILED %s: %v", stamp(), uid, err))
		} else {
			succeeded = append(succeeded, uid)
		}
		_ = st.UpdateJobStatus(ctx, jobID, "Running", 20+(70*(i+1))/len(p.UserIDs))
	}
	duration := fmt.Sprintf("%.1fs", time.Since(start).Seconds())

	status := "Completed"
	switch {
	case len(succeeded) == 0:
		status = "Failed"
	case len(failures) > 0:
		status = "Partial"
	}
	logLines = append(logLines, stamp()+fmt.Sprintf("  %s · %d succeeded · %d failed", providerName(p.Action), len(succeeded), len(failures)))
	logLines = append(logLines, failures...)

	detail := model.ChangeDetail{
		Change: model.Change{
			Timestamp: now(), Technician: p.Technician, Tenant: p.TenantName,
			Action: describe(p), Target: target(p), Status: status, Revert: "—",
		},
		ExecutionLog: logLines,
	}
	if before >= 0 {
		after := before + len(succeeded)
		if p.Action == ActionRemoveFromGroup {
			after = before - len(succeeded)
		}
		detail.Before = []string{fmt.Sprintf("members: %d", before)}
		detail.After = []string{fmt.Sprintf("members: %d", after)}
	} else {
		detail.Before = []string{fmt.Sprintf("targets: %d", len(p.UserIDs))}
		detail.After = []string{
			fmt.Sprintf("succeeded: %d", len(succeeded)),
			fmt.Sprintf("failed: %d", len(failures)),
		}
	}

	// Revert snapshot: undoes exactly the users that succeeded. Reverts of
	// reverts are not offered.
	if ra := revertAction(p.Action); ra != "" && len(succeeded) > 0 && p.RevertOf == "" {
		revert := p
		revert.Action = ra
		revert.UserIDs = succeeded
		revert.RevertOf = "" // filled by the revert handler with this change's id
		if b, err := json.Marshal(revert); err == nil {
			detail.RevertEligible = true
			detail.Revert = "Available"
			detail.RevertPayload = string(b)
		}
	} else if p.Action == ActionRevokeSessions || p.Action == ActionSecureDevice ||
		p.Action == ActionRestartAgent || p.Action == ActionApproveRequest || p.Action == ActionDenyRequest {
		detail.Revert = "Not supported"
	} else if p.RevertOf != "" {
		detail.Revert = "Not supported"
	}

	if status != "Failed" {
		detail.ExecutionLog = append(detail.ExecutionLog, stamp()+"  Change recorded · revert snapshot saved")
	}
	_ = st.CompleteJob(ctx, jobID, status, duration)
	_ = st.AppendChange(ctx, detail)
	if p.RevertOf != "" && status != "Failed" {
		_ = st.UpdateChangeRevert(ctx, p.RevertOf, "Reverted")
	}
	result := "Success"
	if status != "Completed" {
		result = status
	}
	_ = st.AppendAudit(ctx, model.AuditEntry{
		Actor: p.Technician, Action: auditAction(p.Action), Resource: p.TenantName, Result: result,
	})
	log.Info("job done", "job", jobID, "action", p.Action, "status", status,
		"succeeded", len(succeeded), "failed", len(failures))
}

func auditAction(action string) string {
	switch action {
	case ActionEnterMaintenanceMode, ActionSecureDevice,
		ActionLockdownDevice, ActionReleaseLockdown,
		ActionIsolateDevice, ActionReleaseIsolation,
		ActionEnableTamper, ActionDisableTamper,
		ActionRestartAgent, ActionApproveRequest, ActionDenyRequest:
		return "threatlocker." + action
	default:
		return "changes." + action
	}
}

// describe renders the change-history action label.
func describe(p Payload) string {
	n := len(p.UserIDs)
	users := "users"
	if n == 1 {
		users = "user"
	}
	members := "members"
	if n == 1 {
		members = "member"
	}
	var s string
	switch p.Action {
	case ActionAddToGroup:
		s = fmt.Sprintf("Added %d %s", n, members)
	case ActionRemoveFromGroup:
		s = fmt.Sprintf("Removed %d %s", n, members)
	case ActionBlockSignIn:
		s = fmt.Sprintf("Blocked sign-in for %d %s", n, users)
	case ActionUnblockSignIn:
		s = fmt.Sprintf("Unblocked sign-in for %d %s", n, users)
	case ActionAssignLicense:
		s = fmt.Sprintf("Assigned %s to %d %s", p.SkuName, n, users)
	case ActionRemoveLicense:
		s = fmt.Sprintf("Removed %s from %d %s", p.SkuName, n, users)
	case ActionRevokeSessions:
		s = fmt.Sprintf("Revoked sessions for %d %s", n, users)
	case ActionSetForwarding:
		s = fmt.Sprintf("Set forwarding to %s for %d %s", p.ForwardTo, n, plural(n, "mailbox", "mailboxes"))
	case ActionClearForwarding:
		s = fmt.Sprintf("Cleared forwarding for %d %s", n, plural(n, "mailbox", "mailboxes"))
	case ActionEnableAutoReply:
		s = fmt.Sprintf("Enabled auto-reply for %d %s", n, plural(n, "mailbox", "mailboxes"))
	case ActionDisableAutoReply:
		s = fmt.Sprintf("Disabled auto-reply for %d %s", n, plural(n, "mailbox", "mailboxes"))
	case ActionGrantMailboxPerm:
		s = fmt.Sprintf("Granted %s to %s on %d %s", p.Permission, p.DelegateName, n, plural(n, "mailbox", "mailboxes"))
	case ActionRevokeMailboxPerm:
		s = fmt.Sprintf("Revoked %s from %s on %d %s", p.Permission, p.DelegateName, n, plural(n, "mailbox", "mailboxes"))
	case ActionGrantSiteAccess:
		s = fmt.Sprintf("Granted %s on “%s” to %d %s", p.Role, p.SiteName, n, users)
	case ActionRevokeSiteAccess:
		s = fmt.Sprintf("Revoked %s on “%s” from %d %s", p.Role, p.SiteName, n, users)
	case ActionSetSiteSharing:
		s = fmt.Sprintf("Set external sharing to %s for %d %s", p.SharingLevel, n, plural(n, "site", "sites"))
	case ActionEnterMaintenanceMode:
		s = fmt.Sprintf("Entered %s maintenance on %d %s", maintenanceLabel(p.MaintenanceType), n, plural(n, "device", "devices"))
	case ActionSecureDevice:
		s = fmt.Sprintf("Secured %d %s", n, plural(n, "device", "devices"))
	case ActionLockdownDevice:
		s = fmt.Sprintf("Locked down %d %s", n, plural(n, "device", "devices"))
	case ActionReleaseLockdown:
		s = fmt.Sprintf("Released lockdown on %d %s", n, plural(n, "device", "devices"))
	case ActionIsolateDevice:
		s = fmt.Sprintf("Isolated %d %s", n, plural(n, "device", "devices"))
	case ActionReleaseIsolation:
		s = fmt.Sprintf("Released isolation on %d %s", n, plural(n, "device", "devices"))
	case ActionEnableTamper:
		s = fmt.Sprintf("Enabled tamper protection on %d %s", n, plural(n, "device", "devices"))
	case ActionDisableTamper:
		s = fmt.Sprintf("Disabled tamper protection on %d %s", n, plural(n, "device", "devices"))
	case ActionRestartAgent:
		s = fmt.Sprintf("Restarted the ThreatLocker agent on %d %s", n, plural(n, "device", "devices"))
	case ActionApproveRequest:
		s = fmt.Sprintf("Approved %d application %s (%s scope)", n, plural(n, "request", "requests"), p.Scope)
	case ActionDenyRequest:
		s = fmt.Sprintf("Denied %d application %s", n, plural(n, "request", "requests"))
	default:
		s = p.Action
	}
	if p.RevertOf != "" {
		return "Revert — " + s
	}
	return s
}

// target renders the change-history target column.
func target(p Payload) string {
	n := len(p.UserIDs)
	switch p.Action {
	case ActionAddToGroup, ActionRemoveFromGroup:
		return p.GroupName
	case ActionAssignLicense, ActionRemoveLicense:
		return p.SkuName
	case ActionSetForwarding, ActionClearForwarding, ActionEnableAutoReply,
		ActionDisableAutoReply, ActionGrantMailboxPerm, ActionRevokeMailboxPerm:
		return fmt.Sprintf("%d %s", n, plural(n, "mailbox", "mailboxes"))
	case ActionGrantSiteAccess, ActionRevokeSiteAccess:
		return p.SiteName
	case ActionSetSiteSharing:
		return fmt.Sprintf("%d %s", n, plural(n, "site", "sites"))
	case ActionEnterMaintenanceMode, ActionSecureDevice, ActionLockdownDevice, ActionReleaseLockdown,
		ActionIsolateDevice, ActionReleaseIsolation, ActionEnableTamper, ActionDisableTamper, ActionRestartAgent:
		return fmt.Sprintf("%d %s", n, plural(n, "device", "devices"))
	case ActionApproveRequest, ActionDenyRequest:
		return fmt.Sprintf("%d approval %s", n, plural(n, "request", "requests"))
	default:
		return fmt.Sprintf("%d %s", n, plural(n, "user", "users"))
	}
}

// providerName is the execution-log label for the backend the action writes
// through.
func providerName(action string) string {
	switch action {
	case ActionEnterMaintenanceMode, ActionSecureDevice, ActionLockdownDevice, ActionReleaseLockdown,
		ActionIsolateDevice, ActionReleaseIsolation, ActionEnableTamper, ActionDisableTamper,
		ActionRestartAgent, ActionApproveRequest, ActionDenyRequest:
		return "ThreatLocker"
	default:
		return "Microsoft Graph"
	}
}

// maintenanceLabel renders a maintenance type for change-history text.
func maintenanceLabel(t string) string {
	switch t {
	case "monitor_only":
		return "Monitor Only"
	case "learning":
		return "Learning"
	case "installation":
		return "Installation"
	case "disable_protection":
		return "Disable Protection"
	default:
		return t
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func stamp() string { return time.Now().Format("15:04:05") }
func now() string   { return time.Now().Format("2006-01-02 15:04") }
