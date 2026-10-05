package timedaccess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
	"golang.org/x/crypto/ssh"
)

type verifierFunc func(context.Context, Principal, Submission) error

func (v verifierFunc) Verify(ctx context.Context, p Principal, s Submission) error {
	return v(ctx, p, s)
}

func fixture(t *testing.T) (*Manager, *store.SQLStore, ssh.Signer, string, string, *time.Time) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "access.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	vault, err := s.GetVault(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := s.CreateAgent(context.Background(), "engineer-host", "", "no-access")
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{Audience: "local-broker", Helper: "/usr/bin/oshioki", PinsDir: "/service-owned/pins",
		ProtectedServices: map[string][]string{"default": {"catalog"}}, Principals: []Principal{{AgentID: agent.ID,
			SSHPublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), Approver: "hardware-pin"}}}, s)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	m.Now = func() time.Time { return now }
	m.Verifier = verifierFunc(func(_ context.Context, p Principal, sub Submission) error {
		if p.Approver != "hardware-pin" || string(sub.Approval) != `{"approved_by":"hardware-pin"}` {
			return ErrDenied
		}
		return nil
	})
	return m, s, signer, agent.ID, vault.ID, &now
}

func submission(t *testing.T, signer ssh.Signer, now time.Time, duration int) Submission {
	t.Helper()
	r := Request{Type: RequestType, Version: Version, Audience: "local-broker", Principal: ssh.FingerprintSHA256(signer.PublicKey()),
		Host: "test-host", Vault: "default", Service: "catalog", Purpose: "local controlled catalog diagnostic", DurationSeconds: duration,
		RequestID: "request-test-1", Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 90}
	raw, _ := json.Marshal(r)
	sig, err := signer.Sign(rand.Reader, SignaturePayload(raw))
	if err != nil {
		t.Fatal(err)
	}
	return Submission{RequestJSON: string(raw), RequestSignature: *sig, Approval: json.RawMessage(`{"approved_by":"hardware-pin"}`)}
}

func TestAccessRequiresBothIdentitiesAndExactScope(t *testing.T) {
	m, _, signer, agent, vault, now := fixture(t)
	base := submission(t, signer, *now, DefaultDuration)
	for _, name := range []string{"duration", "purpose", "audience", "principal", "vault", "service", "nonce", "id", "wrong-key", "wrong-approver", "missing-approval", "expired", "over-max", "wrong-role", "unmapped"} {
		t.Run(name, func(t *testing.T) {
			sub := base
			role, id := "proxy", agent
			var r Request
			_ = json.Unmarshal([]byte(sub.RequestJSON), &r)
			switch name {
			case "duration":
				r.DurationSeconds++
			case "purpose":
				r.Purpose = "different operation"
			case "audience":
				r.Audience = "other-broker"
			case "principal":
				r.Principal = "other-principal"
			case "vault":
				r.Vault = "other-vault"
			case "service":
				r.Service = "other-service"
			case "nonce":
				r.Nonce = base64.RawURLEncoding.EncodeToString([]byte("bad"))
			case "id":
				r.RequestID = "other-id"
			case "wrong-key":
				_, private, _ := ed25519.GenerateKey(rand.Reader)
				other, _ := ssh.NewSignerFromKey(private)
				sig, _ := other.Sign(rand.Reader, SignaturePayload([]byte(sub.RequestJSON)))
				sub.RequestSignature = *sig
			case "wrong-approver":
				sub.Approval = json.RawMessage(`{"approved_by":"other-device"}`)
			case "missing-approval":
				sub.Approval = nil
			case "expired":
				r.ExpiresAt = now.Unix()
			case "over-max":
				r.DurationSeconds = MaxDuration + 1
			case "wrong-role":
				role = "admin"
			case "unmapped":
				id = "other-agent"
			}
			raw, _ := json.Marshal(r)
			sub.RequestJSON = string(raw)
			if _, err := m.Issue(context.Background(), id, role, vault, "default", sub); err == nil {
				t.Fatal("unauthorized access issued")
			}
		})
	}
	if err := m.Authorize(context.Background(), agent, "", "proxy", vault, "default", "catalog"); !errors.Is(err, ErrDenied) {
		t.Fatal("missing grant accepted")
	}
	g, err := m.Issue(context.Background(), agent, "proxy", vault, "default", base)
	if err != nil {
		t.Fatal(err)
	}
	if g.ExpiresAt.Sub(*now) != 5*time.Minute {
		t.Fatalf("default lifetime %v", g.ExpiresAt.Sub(*now))
	}
	if err := m.Authorize(context.Background(), agent, "", "proxy", vault, "default", "catalog"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ agent, user, role, service string }{{"", "", "proxy", "catalog"}, {"unmapped", "", "proxy", "catalog"}, {agent, "user", "proxy", "catalog"}, {agent, "", "member", "catalog"}} {
		if err := m.Authorize(context.Background(), c.agent, c.user, c.role, vault, "default", c.service); !errors.Is(err, ErrDenied) {
			t.Fatal("wrong proxy identity or role accepted")
		}
	}
	*now = g.ExpiresAt
	if err := m.Authorize(context.Background(), agent, "", "proxy", vault, "default", "catalog"); !errors.Is(err, ErrDenied) {
		t.Fatal("expiry boundary accepted")
	}
}

func TestReplayIsAtomicAndNeverExtends(t *testing.T) {
	m, s, signer, agent, vault, now := fixture(t)
	sub := submission(t, signer, *now, 10)
	const workers = 8
	var wg sync.WaitGroup
	expiries := make(chan time.Time, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := m.Issue(context.Background(), agent, "proxy", vault, "default", sub)
			if err != nil {
				t.Error(err)
				return
			}
			expiries <- g.ExpiresAt
		}()
	}
	wg.Wait()
	close(expiries)
	want := now.Add(10 * time.Second)
	for expiry := range expiries {
		if !expiry.Equal(want) {
			t.Fatalf("replay expiry %v", expiry)
		}
	}
	*now = now.Add(5 * time.Second)
	g, err := m.Issue(context.Background(), agent, "proxy", vault, "default", sub)
	if err != nil || !g.ExpiresAt.Equal(want) {
		t.Fatalf("replay extended: %v %v", g, err)
	}
	var r Request
	_ = json.Unmarshal([]byte(sub.RequestJSON), &r)
	r.DurationSeconds = 20
	raw, _ := json.Marshal(r)
	sig, _ := signer.Sign(rand.Reader, SignaturePayload(raw))
	sub.RequestJSON = string(raw)
	sub.RequestSignature = *sig
	if _, err := m.Issue(context.Background(), agent, "proxy", vault, "default", sub); !errors.Is(err, store.ErrAccessReplayConflict) {
		t.Fatalf("changed request ID accepted: %v", err)
	}
	*now = want
	active, err := s.HasTimedAccess(context.Background(), ssh.FingerprintSHA256(signer.PublicKey()), agent, vault, "catalog", *now)
	if err != nil || active {
		t.Fatalf("expired grant active: %v %v", active, err)
	}
}

func TestAccessExplicitMaximumAndUnavailableVerifier(t *testing.T) {
	m, _, signer, agent, vault, now := fixture(t)
	g, err := m.Issue(context.Background(), agent, "proxy", vault, "default", submission(t, signer, *now, MaxDuration))
	if err != nil || g.ExpiresAt.Sub(*now) != time.Hour {
		t.Fatalf("max duration %v %v", g, err)
	}
	m.Verifier = HelperVerifier{Helper: "/missing/oshioki", PinsDir: "/missing/pins"}
	if _, err := m.Issue(context.Background(), agent, "proxy", vault, "default", submission(t, signer, *now, DefaultDuration)); !errors.Is(err, ErrDenied) {
		t.Fatal("missing helper accepted")
	}
}

func TestTrustedHelperRequiresExactAttestationAndSuccessfulExit(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		allow      bool
	}{
		{"valid", `printf '%s\n' '{"type":"credential_access_verified","version":4}'`, true},
		{"boolean", `printf '%s\n' '{"approved":true}'`, false},
		{"empty", `exit 0`, false},
		{"fallback-exit", `printf '%s\n' '{"type":"credential_access_verified","version":4}'; exit 2`, false},
		{"wrong-purpose", `printf '%s\n' '{"type":"sudo_authenticated","version":2}'`, false},
		{"extra-output", `printf '%s\n' '{"type":"credential_access_verified","version":4}' 'extra'`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "helper")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"+tc.body+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0700); err != nil { // #nosec G302 -- owner-only disposable test helper must be executable.
				t.Fatal(err)
			}
			v := HelperVerifier{Helper: path, PinsDir: "/fixed-service-pins"}
			err := v.Verify(context.Background(), Principal{Approver: "fixed-service-approver"}, Submission{RequestJSON: "{}", Approval: json.RawMessage(`{}`)})
			if (err == nil) != tc.allow {
				t.Fatalf("attestation accepted=%v err=%v", err == nil, err)
			}
		})
	}
}

func TestExistingRSARequesterUsesSHA2AndRejectsWeakKeys(t *testing.T) {
	m, s, _, agent, vault, now := fixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.Config
	cfg.Principals = append([]Principal(nil), cfg.Principals...)
	cfg.Principals[0].SSHPublicKey = string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	rsaManager, err := New(cfg, s)
	if err != nil {
		t.Fatal(err)
	}
	rsaManager.Now = m.Now
	rsaManager.Verifier = m.Verifier
	sub := submission(t, signer, *now, DefaultDuration)
	if _, err = rsaManager.Issue(context.Background(), agent, "proxy", vault, "default", sub); !errors.Is(err, ErrDenied) {
		t.Fatal("legacy RSA SHA-1 requester signature accepted")
	}
	sig, err := signer.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, SignaturePayload([]byte(sub.RequestJSON)), ssh.KeyAlgoRSASHA512)
	if err != nil {
		t.Fatal(err)
	}
	sub.RequestSignature = *sig
	if _, err = rsaManager.Issue(context.Background(), agent, "proxy", vault, "default", sub); err != nil {
		t.Fatal("RSA SHA-2 request rejected", err)
	}
	// Enrollment rejection needs only a weak public modulus, not a weak
	// private key generated for signing.
	weak := key.PublicKey
	weak.N = new(big.Int).Rsh(key.N, 1024)
	weakPublic, err := ssh.NewPublicKey(&weak)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Principals[0].SSHPublicKey = string(ssh.MarshalAuthorizedKey(weakPublic))
	if _, err = New(cfg, s); err == nil {
		t.Fatal("weak RSA enrollment accepted")
	}
}
