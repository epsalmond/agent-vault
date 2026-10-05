package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/timedaccess"
	"golang.org/x/crypto/ssh"
)

func timedServerFixture(t *testing.T) (*Server, *store.SQLStore, *timedaccess.Manager, *store.Agent, *store.Vault, *store.Session) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	v, err := db.GetVault(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	a, err := db.CreateAgent(context.Background(), "engineer-host", "", "no-access")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.GrantVaultRole(context.Background(), a.ID, "agent", v.ID, "proxy"); err != nil {
		t.Fatal(err)
	}
	token, err := db.CreateAgentToken(context.Background(), a.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewSignerFromKey(priv)
	m, err := timedaccess.New(timedaccess.Config{Audience: "local-broker", Helper: "/missing/helper", PinsDir: "/service-pins",
		ProtectedServices: map[string][]string{"default": {"catalog"}}, Principals: []timedaccess.Principal{{AgentID: a.ID, SSHPublicKey: string(ssh.MarshalAuthorizedKey(key.PublicKey())), Approver: "test-pin"}}}, db)
	if err != nil {
		t.Fatal(err)
	}
	enc := make([]byte, 32)
	enc[0] = 1
	ct, nonce, err := crypto.Encrypt([]byte("fake-secret-do-not-reveal"), enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.SetCredential(context.Background(), v.ID, "CATALOG_KEY", ct, nonce); err != nil {
		t.Fatal(err)
	}
	if _, err = db.SetBrokerConfig(context.Background(), v.ID, `[{"name":"catalog","host":"catalog.example","auth":{"type":"bearer","token":"CATALOG_KEY"}}]`); err != nil {
		t.Fatal(err)
	}
	s := New("127.0.0.1:0", db, enc, nil, true, "local-broker", slog.New(slog.DiscardHandler))
	s.AttachTimedAccess(m)
	return s, db, m, a, v, token
}

func TestTimedAccessRolesCannotRevealRawSecretsOrUseUnscopedInject(t *testing.T) {
	s, db, m, a, v, token := timedServerFixture(t)
	p := s.CredentialProvider()
	scope := &brokercore.ProxyScope{AgentID: a.ID, VaultID: v.ID, VaultName: v.Name, VaultRole: "proxy"}
	if _, err := p.InjectScoped(context.Background(), scope, "catalog.example", 443, "/"); !errors.Is(err, brokercore.ErrAccessRequired) {
		t.Fatal("missing grant accepted", err)
	}
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(m.Config.Principals[0].SSHPublicKey))
	_, err := db.ConsumeTimedAccess(context.Background(), store.TimedAccessGrant{RequestID: "role-test", RequestHash: "test", Principal: ssh.FingerprintSHA256(pub), AgentID: a.ID, VaultID: v.ID, Service: "catalog", ApprovedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.InjectScoped(context.Background(), scope, "catalog.example", 443, "/"); err != nil {
		t.Fatal(err)
	}
	for _, sco := range []*brokercore.ProxyScope{{VaultID: v.ID, VaultName: v.Name, VaultRole: "proxy"}, {AgentID: a.ID, UserID: "human", VaultID: v.ID, VaultName: v.Name, VaultRole: "proxy"}, {AgentID: a.ID, VaultID: v.ID, VaultName: v.Name, VaultRole: "admin"}} {
		if _, err = p.InjectScoped(context.Background(), sco, "catalog.example", 443, "/"); !errors.Is(err, brokercore.ErrAccessRequired) {
			t.Fatal("wrong scope accepted", err)
		}
	}
	if _, err = p.Inject(context.Background(), v.ID, "catalog.example", 443, "/"); !errors.Is(err, brokercore.ErrAccessRequired) {
		t.Fatal("unscoped injection bypassed access", err)
	}
	for _, path := range []string{"/v1/credentials?vault=default&reveal=true", "/v1/credentials?vault=default&reveal=true&key=CATALOG_KEY"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+token.ID)
		w := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "fake-secret-do-not-reveal") {
			t.Fatalf("raw reveal: %d %s", w.Code, w.Body.String())
		}
	}
	// Current membership is authoritative even if a scoped session retains
	// its old proxy role. Privilege expansion is not a timed-access bypass.
	if err = db.GrantVaultRole(context.Background(), a.ID, "agent", v.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.InjectScoped(context.Background(), scope, "catalog.example", 443, "/"); !errors.Is(err, brokercore.ErrAccessRequired) {
		t.Fatal("stale scope allowed changed role", err)
	}
}

func TestTimedAccessEndpointDisabledAndUnavailableVerifierDeny(t *testing.T) {
	s, _, _, _, _, token := timedServerFixture(t)
	for _, enabled := range []bool{false, true} {
		m := s.timedAccess
		if !enabled {
			s.timedAccess = nil
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/access/grants", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+token.ID)
		r.Header.Set("X-Vault", "default")
		w := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(w, r)
		if enabled && w.Code < 400 {
			t.Fatal("invalid submission accepted")
		}
		if !enabled && w.Code != http.StatusNotFound {
			t.Fatalf("disabled endpoint status %d", w.Code)
		}
		s.timedAccess = m
	}
	// The error response must never contain raw credential values.
	r := httptest.NewRequest(http.MethodGet, "/discover", nil)
	r.Header.Set("Authorization", "Bearer "+token.ID)
	r.Header.Set("X-Vault", "default")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, r)
	var data map[string]any
	if json.Unmarshal(w.Body.Bytes(), &data) != nil || strings.Contains(w.Body.String(), "fake-secret-do-not-reveal") {
		t.Fatal("discovery leaked credential")
	}
}
