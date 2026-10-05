package mitm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/timedaccess"
	"golang.org/x/crypto/ssh"
)

type timedCredentialStore struct{ *store.SQLStore }

type retryGrantProvider struct {
	*fakeCredProvider
	calls atomic.Int32
}

func (p *retryGrantProvider) InjectScoped(ctx context.Context, scope *brokercore.ProxyScope, host string, port int, path string) (*brokercore.InjectResult, error) {
	if scope.AgentID != "engineer-host" || p.calls.Add(1) > 1 {
		return nil, brokercore.ErrAccessRequired
	}
	return p.fakeCredProvider.InjectScoped(ctx, scope, host, port, path)
}

func TestTimedAccessOAuthRetryChecksGrantAgain(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(upstream.Close)
	cp := &retryGrantProvider{fakeCredProvider: &fakeCredProvider{byHost: map[string]fakeInjectResult{"127.0.0.1": {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer fake"}}}}}}
	proxyURL, roots, _ := setupProxy(t, validTokenResolver("fake-session", &brokercore.ProxyScope{AgentID: "engineer-host", VaultID: "v1", VaultName: "default", VaultRole: "proxy"}), cp)
	client := newTrustingClient(proxyURL, url.User("fake-session"), roots)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || cp.calls.Load() != 2 || upstreamCalls.Load() != 1 {
		t.Fatalf("retry bypass: status=%d inject=%d upstream=%d", resp.StatusCode, cp.calls.Load(), upstreamCalls.Load())
	}
}

func (timedCredentialStore) UnmatchedHostPolicy(context.Context, string) (brokercore.UnmatchedHostPolicy, error) {
	return brokercore.PolicyDeny, nil
}

func TestHTTP2TimedAccessExpiresOnReusedTunnelAndAdmittedStreamFinishes(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "access.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	vault, err := db.GetVault(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := db.CreateAgent(ctx, "engineer-host", "", "no-access")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.GrantVaultRole(ctx, agent.ID, "agent", vault.ID, "proxy"); err != nil {
		t.Fatal(err)
	}
	token, err := db.CreateAgentToken(ctx, agent.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	m, err := timedaccess.New(timedaccess.Config{Audience: "local-broker", Helper: "/test/helper", PinsDir: "/test/pins", ProtectedServices: map[string][]string{"default": {"catalog"}}, Principals: []timedaccess.Principal{{AgentID: agent.ID, SSHPublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), Approver: "test-pin"}}}, db)
	if err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	initial := time.Now().Truncate(time.Second)
	clock.Store(initial.UnixMilli())
	m.Now = func() time.Time { return time.UnixMilli(clock.Load()) }
	finish := make(chan struct{})
	var upstreamCalls atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.ProtoMajor != 2 || r.Header.Get("Authorization") != "Bearer fake-catalog-secret" {
			t.Error("upstream transport or injection")
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		if r.URL.Path == "/stream" {
			<-finish
		}
		_, _ = w.Write([]byte("ok"))
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	enc := make([]byte, 32)
	ct, nonce, err := crypto.Encrypt([]byte("fake-catalog-secret"), enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.SetCredential(ctx, vault.ID, "CATALOG_KEY", ct, nonce); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(upstream.URL)
	services, _ := json.Marshal([]broker.Service{{Name: "catalog", Host: u.Host, Auth: broker.Auth{Type: "bearer", Token: "CATALOG_KEY"}}})
	if _, err = db.SetBrokerConfig(ctx, vault.ID, string(services)); err != nil {
		t.Fatal(err)
	}
	cp := brokercore.NewStoreCredentialProvider(timedCredentialStore{db}, enc)
	cp.AccessAuthorizer = func(ctx context.Context, s *brokercore.ProxyScope, service string) error {
		return m.Authorize(ctx, s.AgentID, s.UserID, s.VaultRole, s.VaultID, s.VaultName, service)
	}
	proxyURL, roots, p := setupProxy(t, brokercore.NewStoreSessionResolver(db), cp)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}
	client := newTrustingClient(proxyURL, url.UserPassword(token.ID, "default"), roots)
	transport := client.Transport.(*http.Transport)
	transport.ForceAttemptHTTP2 = true
	t.Cleanup(transport.CloseIdleConnections)
	request := func(path string, wantStatus int, expectReused bool) *http.Response {
		t.Helper()
		reused := false
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}), http.MethodGet, upstream.URL+path, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != wantStatus || resp.ProtoMajor != 2 || (expectReused && !reused) {
			t.Fatalf("status=%d protocol=%s reused=%v", resp.StatusCode, resp.Proto, reused)
		}
		return resp
	}
	denied := request("/", 403, false)
	_, _ = io.Copy(io.Discard, denied.Body)
	_ = denied.Body.Close()
	if upstreamCalls.Load() != 0 {
		t.Fatal("unapproved request reached upstream")
	}
	_, err = db.ConsumeTimedAccess(ctx, store.TimedAccessGrant{RequestID: "h2-test", RequestHash: "fixture", Principal: ssh.FingerprintSHA256(signer.PublicKey()), AgentID: agent.ID, VaultID: vault.ID, Service: "catalog", ApprovedAt: initial, ExpiresAt: initial.Add(5 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	ok := request("/", 200, true)
	_, _ = io.Copy(io.Discard, ok.Body)
	_ = ok.Body.Close()
	active := request("/stream", 200, true)
	clock.Store(initial.Add(5 * time.Second).UnixMilli())
	expired := request("/new-stream", 403, true)
	_, _ = io.Copy(io.Discard, expired.Body)
	_ = expired.Body.Close()
	if upstreamCalls.Load() != 2 {
		t.Fatal("expired stream reached upstream")
	}
	close(finish)
	body, err := io.ReadAll(active.Body)
	_ = active.Body.Close()
	if err != nil || string(body) != "ok" {
		t.Fatalf("admitted stream interrupted %q %v", body, err)
	}
}
