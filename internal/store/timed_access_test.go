package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestTimedAccessPersistsExpiryAndReplayConsumptionAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.db")
	ctx := context.Background()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := db.GetVault(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := db.CreateAgent(ctx, "engineer-host", "", "no-access")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Millisecond)
	g := TimedAccessGrant{RequestID: "durable-test", RequestHash: "hash", Principal: "ssh-principal", AgentID: agent.ID, VaultID: vault.ID, Service: "catalog", ApprovedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if _, err = db.ConsumeTimedAccess(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	active, err := db.HasTimedAccess(ctx, g.Principal, g.AgentID, g.VaultID, g.Service, now)
	if err != nil || !active {
		t.Fatalf("restart lost grant %v %v", active, err)
	}
	g.ExpiresAt = g.ExpiresAt.Add(time.Hour)
	replayed, err := db.ConsumeTimedAccess(ctx, g)
	if err != nil || !replayed.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("restart replay extended expiry %v %v", replayed, err)
	}
}

func TestMigrateDataPreservesTimedAccessAndConsumedRequests(t *testing.T) {
	ctx := context.Background()
	source, err := Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	target, err := Open(filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	vault, err := source.GetVault(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := source.CreateAgent(ctx, "engineer-host", "", "no-access")
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_000_123)
	active := TimedAccessGrant{RequestID: "active-request", RequestHash: "active-hash", Principal: "ssh-principal", AgentID: agent.ID,
		VaultID: vault.ID, Service: "catalog", ApprovedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	// A two-second grant may expire while its 90-second approval ceremony
	// remains replayable. Its consumed ID must survive database cutover too.
	expired := TimedAccessGrant{RequestID: "expired-request", RequestHash: "expired-hash", Principal: active.Principal, AgentID: agent.ID,
		VaultID: vault.ID, Service: "expired-service", ApprovedAt: now.Add(-10 * time.Second), ExpiresAt: now.Add(-8 * time.Second)}
	for _, grant := range []TimedAccessGrant{active, expired} {
		if _, err := source.ConsumeTimedAccess(ctx, grant); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := CountSourceTables(source)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, count := range counts {
		if count.Table == "timed_access_grants" {
			found = count.Count == 2
		}
	}
	if !found {
		t.Fatal("migration dry-run omits active grants or consumed request IDs")
	}
	copied := -1
	if err := MigrateData(ctx, source, target, func(table string, count int) {
		if table == "timed_access_grants" {
			copied = count
		}
	}); err != nil {
		t.Fatal(err)
	}
	if copied != 2 {
		t.Fatalf("migration copied %d timed access rows, want 2", copied)
	}
	for _, original := range []TimedAccessGrant{active, expired} {
		isActive, err := target.HasTimedAccess(ctx, original.Principal, original.AgentID, original.VaultID, original.Service, now)
		if err != nil || isActive != original.ExpiresAt.After(now) {
			t.Fatalf("migrated grant status: active=%v err=%v", isActive, err)
		}
		attempt := original
		attempt.ApprovedAt, attempt.ExpiresAt = now.Add(20*time.Second), now.Add(time.Hour)
		replayed, err := target.ConsumeTimedAccess(ctx, attempt)
		if err != nil || *replayed != original {
			t.Fatalf("cutover changed scope or extended replay expiry: got=%+v original=%+v err=%v", replayed, original, err)
		}
		attempt.RequestHash = "altered-request-bytes"
		if _, err := target.ConsumeTimedAccess(ctx, attempt); !errors.Is(err, ErrAccessReplayConflict) {
			t.Fatalf("cutover lost consumed request hash: %v", err)
		}
	}
}
