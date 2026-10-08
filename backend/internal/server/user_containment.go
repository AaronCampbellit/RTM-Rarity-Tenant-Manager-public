package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/worker"
)

// executeSensitiveUserAction runs password-bearing actions synchronously as a
// tracked job. A temporary password must never be serialized into River's job
// payload or persisted in RTM. The no-store response is therefore the only
// place the generated credential exists outside Microsoft Graph.
func (s *Server) executeSensitiveUserAction(w http.ResponseWriter, r *http.Request, body changeRequest, cc changeContext, targets []planTarget) {
	user := auth.UserFromContext(r.Context())
	job, err := s.store.CreateJob(r.Context(), model.Job{
		Type: worker.JobType(body.Action, false), Tenant: cc.tenantName,
		Status: "Running", Progress: 10, Started: time.Now().Format("15:04"),
		Duration: "—", TriggeredBy: user.Name,
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}

	start := time.Now()
	logs := []string{containmentStamp() + "  Job started · " + sensitiveActionDescription(body.Action, len(targets))}
	passwords := make([]model.OneTimePassword, 0, len(targets))
	passwordSucceeded, mfaSucceeded, sessionsSucceeded := 0, 0, 0
	stepsSucceeded, stepsFailed := 0, 0
	totalSteps := len(targets)
	if body.Action == worker.ActionRevokeUserAccess {
		totalSteps *= 3
	}

	for i, target := range targets {
		if body.Action == worker.ActionRevokeUserAccess {
			if err := s.graph.ResetMFA(r.Context(), body.TenantID, target.id); err != nil {
				stepsFailed++
				logs = append(logs, containmentFailure(target.name, "MFA method reset", err))
			} else {
				stepsSucceeded++
				mfaSucceeded++
				logs = append(logs, containmentStamp()+"  OK "+target.name+" · registered authentication methods removed")
			}
			if err := s.graph.RevokeSessions(r.Context(), body.TenantID, target.id); err != nil {
				stepsFailed++
				logs = append(logs, containmentFailure(target.name, "session revocation", err))
			} else {
				stepsSucceeded++
				sessionsSucceeded++
				logs = append(logs, containmentStamp()+"  OK "+target.name+" · sign-in sessions revoked")
			}
		}

		// Reset the password last. That keeps the only-copy credential's lifetime
		// in API memory as short as possible before it is returned to the admin.
		temporaryPassword := auth.TempPassword()
		if err := s.graph.ResetPassword(r.Context(), body.TenantID, target.id, temporaryPassword); err != nil {
			stepsFailed++
			logs = append(logs, containmentFailure(target.name, "password reset", err))
		} else {
			stepsSucceeded++
			passwordSucceeded++
			passwords = append(passwords, model.OneTimePassword{
				UserID: target.id, User: target.name, UPN: target.detail, Password: temporaryPassword,
			})
			logs = append(logs, containmentStamp()+"  OK "+target.name+" · password reset")
		}
		_ = s.store.UpdateJobStatus(r.Context(), job.ID, "Running", 10+(85*(i+1))/len(targets))
	}

	storedStatus, responseStatus := "Completed", "succeeded"
	switch {
	case stepsSucceeded == 0:
		storedStatus, responseStatus = "Failed", "failed"
	case stepsFailed > 0:
		storedStatus, responseStatus = "Partial", "partial_success"
	}
	duration := fmt.Sprintf("%.1fs", time.Since(start).Seconds())
	logs = append(logs, containmentStamp()+fmt.Sprintf("  %s · %d of %d security steps succeeded", storedStatus, stepsSucceeded, totalSteps))

	action := sensitiveActionDescription(body.Action, len(targets))
	detail := model.ChangeDetail{
		Change: model.Change{
			Timestamp: time.Now().Format("2006-01-02 15:04"), Technician: user.Name,
			Tenant: cc.tenantName, Action: action,
			Target: fmt.Sprintf("%d %s", len(targets), containmentPlural(len(targets), "user", "users")),
			Status: storedStatus, Revert: "Not supported",
		},
		Before:       []string{fmt.Sprintf("targets: %d", len(targets))},
		After:        []string{fmt.Sprintf("passwords reset: %d", passwordSucceeded)},
		ExecutionLog: logs,
	}
	if body.Action == worker.ActionRevokeUserAccess {
		detail.After = append(detail.After,
			fmt.Sprintf("MFA registrations reset: %d", mfaSucceeded),
			fmt.Sprintf("sessions revoked: %d", sessionsSucceeded),
		)
	}
	if err := s.store.CompleteJob(r.Context(), job.ID, storedStatus, duration); err != nil {
		s.log.Error("complete sensitive user job", "job", job.ID, "error", err)
	}
	if err := s.store.AppendChange(r.Context(), detail); err != nil {
		s.log.Error("record sensitive user change", "job", job.ID, "error", err)
	}
	auditResult := "Success"
	if storedStatus != "Completed" {
		auditResult = storedStatus
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "changes." + body.Action,
		Resource: cc.tenantName, Result: auditResult,
		CorrelationID: httpx.CorrelationID(r.Context()),
	})

	// This response contains the only copy RTM returns. It must not be cached.
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	httpx.WriteJSON(w, http.StatusOK, model.JobRef{
		JobID: job.ID, Status: responseStatus, OneTimePasswords: passwords,
	})
}

func sensitiveActionDescription(action string, count int) string {
	if action == worker.ActionRevokeUserAccess {
		return fmt.Sprintf("Revoked access for %d %s", count, containmentPlural(count, "user", "users"))
	}
	return fmt.Sprintf("Reset password for %d %s", count, containmentPlural(count, "user", "users"))
}

func containmentPlural(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func containmentStamp() string { return time.Now().Format("15:04:05") }

func containmentFailure(user, step string, err error) string {
	detail := "Microsoft rejected the operation"
	var apiErr *graph.APIError
	if errors.As(err, &apiErr) {
		detail = fmt.Sprintf("Microsoft Graph %d %s", apiErr.Status, apiErr.Code)
	}
	return containmentStamp() + "  FAILED " + user + " · " + step + " · " + detail
}
