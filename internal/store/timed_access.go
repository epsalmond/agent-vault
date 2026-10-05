package store

import (
	"context"
	"errors"
	"time"
)

var ErrAccessReplayConflict = errors.New("request ID already consumed for different access bytes")

// TimedAccessGrant is both a durable grant and its consumed request ID.
// Never delete expired rows: replay must retain the original expiry forever.
type TimedAccessGrant struct {
	RequestID, RequestHash, Principal, AgentID, VaultID, Service string
	ApprovedAt, ExpiresAt                                        time.Time
}

type TimedAccessStore interface {
	ConsumeTimedAccess(context.Context, TimedAccessGrant) (*TimedAccessGrant, error)
	HasTimedAccess(context.Context, string, string, string, string, time.Time) (bool, error)
}

// ConsumeTimedAccess atomically consumes the request ID by inserting the
// grant itself. Unique conflict returns the original expiry; it never extends
// access. This single statement works across concurrent SQLite/Postgres servers.
func (s *SQLStore) ConsumeTimedAccess(ctx context.Context, g TimedAccessGrant) (*TimedAccessGrant, error) {
	_, err := s.db.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO timed_access_grants
		(request_id, request_hash, principal, agent_id, vault_id, service, approved_at_ms, expires_at_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(request_id) DO NOTHING`),
		g.RequestID, g.RequestHash, g.Principal, g.AgentID, g.VaultID, g.Service, g.ApprovedAt.UnixMilli(), g.ExpiresAt.UnixMilli())
	if err != nil {
		return nil, err
	}
	var stored TimedAccessGrant
	var approved, expires int64
	err = s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT request_id, request_hash, principal, agent_id, vault_id,
		service, approved_at_ms, expires_at_ms FROM timed_access_grants WHERE request_id = ?`), g.RequestID).
		Scan(&stored.RequestID, &stored.RequestHash, &stored.Principal, &stored.AgentID, &stored.VaultID, &stored.Service, &approved, &expires)
	if err != nil {
		return nil, err
	}
	if stored.RequestHash != g.RequestHash || stored.Principal != g.Principal || stored.AgentID != g.AgentID ||
		stored.VaultID != g.VaultID || stored.Service != g.Service {
		return nil, ErrAccessReplayConflict
	}
	stored.ApprovedAt, stored.ExpiresAt = time.UnixMilli(approved), time.UnixMilli(expires)
	return &stored, nil
}

func (s *SQLStore) HasTimedAccess(ctx context.Context, principal, agentID, vaultID, service string, now time.Time) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM timed_access_grants
		WHERE principal = ? AND agent_id = ? AND vault_id = ? AND service = ? AND expires_at_ms > ?`),
		principal, agentID, vaultID, service, now.UnixMilli()).Scan(&count)
	return count > 0, err
}
