package server

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/timedaccess"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh"
)

var oshiokiAccessTestBinary = flag.String("oshioki-access-test-binary", "", "actual Oshioki helper for the controlled local CLI proof")
var agentVaultAccessTestBinary = flag.String("agent-vault-access-test-binary", "", "actual Agent Vault CLI for the controlled local proof")

// TestTimedAccessCLIProof drives real CLI binaries and the real trusted Rust
// verifier. The native socket responder is explicitly a LOCAL TEST FIXTURE,
// with a disposable P-256 key manually pinned as native hardware. This proves
// protocol/CLI enforcement, not a live enrolled Touch ID or hardware ceremony.
func TestTimedAccessCLIProof(t *testing.T) {
	if *oshiokiAccessTestBinary == "" || *agentVaultAccessTestBinary == "" {
		t.Skip("run scripts/test-timed-access <oshioki-worktree> for the real local CLI proof")
	}
	s, db, _, a, v, token := timedServerFixture(t)
	dir := t.TempDir()
	native, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	box, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nativePublic, err := native.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	pub := nativePublic.Bytes()
	credentialID := sha256.Sum256(pub)
	fingerprintHash := sha256.New()
	_, _ = fingerprintHash.Write([]byte("oshioki/fingerprint/v1\x00"))
	for _, field := range [][]byte{credentialID[:], pub} {
		_ = binary.Write(fingerprintHash, binary.BigEndian, uint64(len(field)))
		_, _ = fingerprintHash.Write(field)
	}
	_, _ = fingerprintHash.Write(box.PublicKey().Bytes())
	fingerprint := base64.RawURLEncoding.EncodeToString(fingerprintHash.Sum(nil)[:16])
	encode := base64.RawURLEncoding.EncodeToString
	record := map[string]any{"version": 1, "kind": "secure-enclave", "fingerprint": fingerprint, "credential_id": encode(credentialID[:]),
		"credential_public_key": encode(pub), "box_public_key": encode(box.PublicKey().Bytes()), "api_token_hash": encode(make([]byte, 32)), "label": "LOCAL TEST FIXTURE (no biometric)", "sign_count": 0, "active": true}
	writeJSON := func(name string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON("devices.json", map[string]any{"version": 1, "devices": []any{record}})
	writeJSON("hook.json", map[string]any{"version": 1, "origin": "https://fixture.invalid", "rp_id": "fixture.invalid", "server_base_url": "https://fixture.invalid"})
	socketPath := filepath.Join(dir, "fixture.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err = os.WriteFile(filepath.Join(dir, "config.env"), []byte("OSHIOKI_AGENT_SOCKET="+socketPath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	responded := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			responded <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		read := func() ([]byte, error) {
			var n uint32
			if err := binary.Read(conn, binary.BigEndian, &n); err != nil {
				return nil, err
			}
			if n > 64*1024 {
				return nil, io.ErrShortBuffer
			}
			b := make([]byte, n)
			_, err := io.ReadFull(conn, b)
			return b, err
		}
		b, err := read()
		if err != nil {
			responded <- err
			return
		}
		var envelope struct {
			Sealed []struct {
				Fingerprint string `json:"device_fingerprint"`
				Ephemeral   string `json:"ephemeral_pub"`
				Nonce       string `json:"nonce"`
				Ciphertext  string `json:"ciphertext"`
			} `json:"sealed"`
		}
		if err = json.Unmarshal(b, &envelope); err != nil || len(envelope.Sealed) != 1 {
			responded <- io.ErrUnexpectedEOF
			return
		}
		body := envelope.Sealed[0]
		ephemeral, _ := base64.RawURLEncoding.DecodeString(body.Ephemeral)
		peer, err := ecdh.X25519().NewPublicKey(ephemeral)
		if err != nil {
			responded <- err
			return
		}
		shared, err := box.ECDH(peer)
		if err != nil {
			responded <- err
			return
		}
		cipher, err := chacha20poly1305.New(shared)
		if err != nil {
			responded <- err
			return
		}
		nonce, _ := base64.RawURLEncoding.DecodeString(body.Nonce)
		ciphertext, _ := base64.RawURLEncoding.DecodeString(body.Ciphertext)
		raw, err := cipher.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			responded <- err
			return
		}
		var request timedaccess.Request
		if err = timedaccess.DecodeStrict(raw, &request); err != nil {
			responded <- err
			return
		}
		challenge := sha256.Sum256(append([]byte("oshioki/credential-access/approve/v1\x00"), raw...))
		digest := sha256.Sum256(challenge[:])
		signature, err := ecdsa.SignASN1(rand.Reader, native, digest[:])
		if err != nil {
			responded <- err
			return
		}
		write := func(value any) error {
			b, err := json.Marshal(value)
			if err != nil {
				return err
			}
			if err = binary.Write(conn, binary.BigEndian, uint32(len(b))); err != nil {
				return err
			}
			_, err = conn.Write(b)
			return err
		}
		if err = write(map[string]any{"type": "alive", "version": 1, "request_id": request.RequestID}); err == nil {
			err = write(map[string]any{"type": "credential_access_native", "version": 4, "request_id": request.RequestID, "device_fingerprint": fingerprint, "signature": encode(signature)})
		}
		responded <- err
	}()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requester, _ := ssh.NewSignerFromKey(private)
	block, err := ssh.MarshalPrivateKey(private, "local fixture")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "requester-key")
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := timedaccess.New(timedaccess.Config{Audience: "local-broker", Helper: *oshiokiAccessTestBinary, PinsDir: dir,
		ProtectedServices: map[string][]string{"default": {"catalog"}}, Principals: []timedaccess.Principal{{AgentID: a.ID, SSHPublicKey: string(ssh.MarshalAuthorizedKey(requester.PublicKey())), Approver: fingerprint}}}, db)
	if err != nil {
		t.Fatal(err)
	}
	s.AttachTimedAccess(m)
	control := httptest.NewServer(s.httpServer.Handler)
	t.Cleanup(control.Close)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-secret-do-not-reveal" {
			t.Error("missing fake credential injection")
		}
		_, _ = io.WriteString(w, "controlled upstream accepted")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	if _, err = db.SetBrokerConfig(context.Background(), v.ID, `[{"name":"catalog","host":"`+u.Host+`","auth":{"type":"bearer","token":"CATALOG_KEY"}}]`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	caProvider, err := ca.New(s.encKey, ca.Options{Dir: filepath.Join(dir, "ca")})
	if err != nil {
		t.Fatal(err)
	}
	proxy := mitm.New("127.0.0.1:0", mitm.Options{CA: caProvider, Sessions: s.SessionResolver(), Credentials: s.CredentialProvider(), BaseURL: control.URL, Logger: slog.New(slog.DiscardHandler)})
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Serve(proxyListener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = proxy.Shutdown(ctx)
	})
	proxyURL := url.URL{Scheme: "http", Host: proxyListener.Addr().String(), User: url.UserPassword(token.ID, "default")}
	curl := func(want string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "curl", "--silent", "--show-error", "--noproxy", "", "--proxy", proxyURL.String(), "--write-out", "\n%{http_code}", upstream.URL)
		out, err := cmd.Output()
		if err != nil || !strings.HasSuffix(string(out), "\n"+want) {
			t.Fatalf("controlled curl: status wanted %s err=%v output=%s", want, err, out)
		}
		if strings.Contains(string(out), "fake-secret-do-not-reveal") {
			t.Fatal("credential leaked to CLI")
		}
	}
	curl("403")
	t.Log("real curl: denied without grant")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, *agentVaultAccessTestBinary, "access", "request", "--service", "catalog", "--purpose", "local fixture diagnostic", "--duration", "2s", "--ssh-key", keyPath, "--oshioki-config", dir, "--oshioki", *oshiokiAccessTestBinary, "--audience", "local-broker")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "AGENT_VAULT_ADDR=" + control.URL, "AGENT_VAULT_TOKEN=" + token.ID, "AGENT_VAULT_VAULT=default"}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real access CLI: %v %s", err, output)
	}
	if err = <-responded; err != nil {
		t.Fatal(err)
	}
	var grant struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err = json.Unmarshal(output, &grant); err != nil {
		t.Fatalf("grant CLI output: %v %s", err, output)
	}
	if strings.Contains(string(output), "fake-secret-do-not-reveal") {
		t.Fatal("grant metadata leaked credential")
	}
	t.Log("real agent-vault access CLI + Oshioki request + trusted Rust verify: approved using LOCAL FIXTURE identity")
	curl("200")
	t.Log("real curl retry: accepted by controlled upstream")
	// A single bounded script/test timer reaches the actual lease expiry.
	timer := time.NewTimer(time.Until(grant.ExpiresAt) + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("local expiry proof deadline")
	}
	curl("403")
	t.Log("real curl: denied again after absolute 2-second expiry")
}
