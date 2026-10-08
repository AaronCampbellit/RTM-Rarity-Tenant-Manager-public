package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/httpx"
)

type writeApproval struct {
	actor   string
	payload string
	expires time.Time
}

func (s *Server) issueChangeApproval(r *http.Request, body changeRequest) string {
	body.ApprovalToken = ""
	raw, _ := json.Marshal(body)
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	s.approvalMu.Lock()
	defer s.approvalMu.Unlock()
	s.approvals[token] = writeApproval{actor: auth.UserFromContext(r.Context()).ID, payload: string(raw), expires: time.Now().Add(5 * time.Minute)}
	return token
}

func (s *Server) issueApproval(r *http.Request, payload any) string {
	raw, _ := json.Marshal(payload)
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	s.approvalMu.Lock()
	s.approvals[token] = writeApproval{actor: auth.UserFromContext(r.Context()).ID, payload: string(raw), expires: time.Now().Add(5 * time.Minute)}
	s.approvalMu.Unlock()
	return token
}
func (s *Server) consumeApproval(w http.ResponseWriter, r *http.Request, token string, payload any) bool {
	if s.cfg.Env != "production" {
		return true
	}
	raw, _ := json.Marshal(payload)
	s.approvalMu.Lock()
	a, ok := s.approvals[token]
	delete(s.approvals, token)
	s.approvalMu.Unlock()
	if !ok || a.actor != auth.UserFromContext(r.Context()).ID || a.payload != string(raw) || time.Now().After(a.expires) {
		httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeAuthorizationDenied, "A current What-If preview approval is required before executing this change.")
		return false
	}
	return true
}

func (s *Server) consumeChangeApproval(w http.ResponseWriter, r *http.Request, body changeRequest) bool {
	if s.cfg.Env != "production" {
		return true
	}
	token := body.ApprovalToken
	body.ApprovalToken = ""
	raw, _ := json.Marshal(body)
	s.approvalMu.Lock()
	approval, ok := s.approvals[token]
	delete(s.approvals, token)
	s.approvalMu.Unlock()
	if !ok || approval.actor != auth.UserFromContext(r.Context()).ID || approval.payload != string(raw) || time.Now().After(approval.expires) {
		httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeAuthorizationDenied, "A current What-If preview approval is required before executing this change.")
		return false
	}
	return true
}
