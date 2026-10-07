package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/timedaccess"
)

// AttachTimedAccess must run before serving requests. Providers late-bind the
// service policy, like the existing dynamic credential resolver.
func (s *Server) AttachTimedAccess(m *timedaccess.Manager) { s.timedAccess = m }

func (s *Server) authorizeTimedAccess(ctx context.Context, scope *brokercore.ProxyScope, service string) error {
	if s.timedAccess == nil {
		return nil
	}
	vault, err := s.store.GetVaultByID(ctx, scope.VaultID)
	if err != nil || vault == nil {
		return timedaccess.ErrDenied
	}
	if !s.timedAccess.Protected(vault.Name, service) {
		return nil
	}
	// Instance owners can read secrets through administrative endpoints.
	// Protected agents must retain the least-privileged existing instance role.
	agent, err := s.store.GetAgentByID(ctx, scope.AgentID)
	if err != nil || agent == nil || agent.Role != "no-access" || agent.Status != "active" {
		return timedaccess.ErrDenied
	}
	currentRole, err := s.store.GetVaultRole(ctx, scope.AgentID, vault.ID)
	if err != nil || currentRole != "proxy" {
		return timedaccess.ErrDenied
	}
	return s.timedAccess.Authorize(ctx, scope.AgentID, scope.UserID, scope.VaultRole, vault.ID, vault.Name, service)
}

func (s *Server) handleTimedAccessGrant(w http.ResponseWriter, r *http.Request) {
	if s.timedAccess == nil {
		jsonError(w, http.StatusNotFound, "Timed access is not enabled")
		return
	}
	sess := sessionFromContext(r.Context())
	if sess == nil || sess.AgentID == "" || sess.UserID != "" {
		jsonError(w, http.StatusForbidden, "Timed access requires an enrolled proxy-only agent token")
		return
	}
	vault, role, err := s.resolveVaultForSession(w, r, sess)
	if err != nil {
		return
	}
	agent, err := s.store.GetAgentByID(r.Context(), sess.AgentID)
	if err != nil || agent == nil || agent.Role != "no-access" || agent.Status != "active" || role != "proxy" {
		jsonError(w, http.StatusForbidden, "Timed access requires instance no-access and vault proxy roles")
		return
	}
	currentRole, err := s.store.GetVaultRole(r.Context(), sess.AgentID, vault.ID)
	if err != nil || currentRole != "proxy" {
		jsonError(w, http.StatusForbidden, "Agent no longer has proxy-only vault access")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
	var sub timedaccess.Submission
	if err != nil || len(raw) > 64*1024 || timedaccess.DecodeStrict(raw, &sub) != nil {
		jsonError(w, http.StatusBadRequest, "Invalid access submission")
		return
	}
	var request timedaccess.Request
	if timedaccess.DecodeStrict([]byte(sub.RequestJSON), &request) != nil {
		jsonError(w, http.StatusBadRequest, "Invalid access request")
		return
	}
	// Grants name existing enabled services; service creation continues to use
	// the existing human administration/proposal flow.
	cfg, err := s.store.GetBrokerConfig(r.Context(), vault.ID)
	var services []broker.Service
	if err != nil || cfg == nil || json.Unmarshal([]byte(cfg.ServicesJSON), &services) != nil {
		jsonError(w, http.StatusForbidden, "Service unavailable")
		return
	}
	broker.AssignSlugNames(services)
	found := false
	for _, service := range services {
		if service.Name == request.Service && service.IsEnabled() {
			found = true
		}
	}
	if !found {
		jsonError(w, http.StatusForbidden, "Service unavailable")
		return
	}
	grant, err := s.timedAccess.Issue(r.Context(), sess.AgentID, role, vault.ID, vault.Name, sub)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Timed access denied: requester or human approval invalid, expired or replayed")
		return
	}
	jsonOK(w, struct {
		RequestID string `json:"request_id"`
		Principal string `json:"principal"`
		Vault     string `json:"vault"`
		Service   string `json:"service"`
		ExpiresAt string `json:"expires_at"`
	}{grant.RequestID, grant.Principal, vault.Name, grant.Service, grant.ExpiresAt.UTC().Format(time.RFC3339Nano)})
}
