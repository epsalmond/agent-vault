package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if err := db.Exec(`CREATE TABLE timed_access_grants (
			request_id TEXT PRIMARY KEY,
			request_hash TEXT NOT NULL,
			principal TEXT NOT NULL,
			agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
			vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
			service TEXT NOT NULL,
			approved_at_ms BIGINT NOT NULL,
			expires_at_ms BIGINT NOT NULL
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX idx_timed_access_scope_expiry
			ON timed_access_grants(principal, agent_id, vault_id, service, expires_at_ms)`).Error
	})
}
