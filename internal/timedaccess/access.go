// Package timedaccess authenticates the requester SSH principal separately
// from the human Oshioki assertion and evaluates durable per-service grants.
package timedaccess

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/Infisical/agent-vault/internal/store"
	"golang.org/x/crypto/ssh"
)

const DefaultDuration = 300
const MaxDuration = 3600
const Version = 4
const RequestType = "credential_access_request"

var ErrDenied = errors.New("credential access requires an active Oshioki grant")

// Config is loaded only at startup from an operator-owned file. Omitting the
// opt-in preserves legacy services; a configured protected service fails closed
// for every actor without an enrolled proxy-only principal.
type Config struct {
	Audience          string              `json:"audience"`
	Helper            string              `json:"helper"`
	PinsDir           string              `json:"pins_dir"`
	ProtectedServices map[string][]string `json:"protected_services"`
	Principals        []Principal         `json:"principals"`
}

type Principal struct {
	AgentID      string `json:"agent_id"`
	SSHPublicKey string `json:"ssh_public_key"`
	Approver     string `json:"approver"`
	key          ssh.PublicKey
	id           string
}

// Field order is the canonical request encoding shared with Oshioki. The
// signature is outside this object; both identities sign these exact bytes.
type Request struct {
	Type            string `json:"type"`
	Version         int    `json:"version"`
	Audience        string `json:"audience"`
	Principal       string `json:"principal"`
	Host            string `json:"host"`
	Vault           string `json:"vault"`
	Service         string `json:"service"`
	Purpose         string `json:"purpose"`
	DurationSeconds int    `json:"duration_seconds"`
	RequestID       string `json:"request_id"`
	Nonce           string `json:"nonce"`
	IssuedAt        int64  `json:"issued_at"`
	ExpiresAt       int64  `json:"expires_at"`
}

type Submission struct {
	RequestJSON      string          `json:"request_json"`
	RequestSignature ssh.Signature   `json:"request_signature"`
	Approval         json.RawMessage `json:"approval"`
}

type Verifier interface {
	Verify(context.Context, Principal, Submission) error
}

type Manager struct {
	Config   Config
	Store    store.TimedAccessStore
	Verifier Verifier
	Now      func() time.Time
}

func DecodeStrict(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func Load(path string, s store.TimedAccessStore) (*Manager, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err = DecodeStrict(raw, &c); err != nil {
		return nil, err
	}
	return New(c, s)
}

func New(c Config, s store.TimedAccessStore) (*Manager, error) {
	if c.Audience == "" || !filepath.IsAbs(c.Helper) || !filepath.IsAbs(c.PinsDir) || len(c.ProtectedServices) == 0 || len(c.Principals) == 0 || s == nil {
		return nil, errors.New("timed access requires audience, absolute helper and pins_dir, protected services, enrolled principals and durable store")
	}
	seenAgents, seenKeys := map[string]bool{}, map[string]bool{}
	for i := range c.Principals {
		p := &c.Principals[i]
		key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(p.SSHPublicKey))
		if err != nil || len(rest) != 0 || len(options) != 0 || p.AgentID == "" || p.Approver == "" {
			return nil, errors.New("invalid timed access principal enrollment")
		}
		switch key.Type() {
		case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		case ssh.KeyAlgoRSA:
			public, ok := key.(ssh.CryptoPublicKey)
			if !ok {
				return nil, errors.New("unsupported SSH public key")
			}
			rsaKey, ok := public.CryptoPublicKey().(*rsa.PublicKey)
			if !ok || rsaKey.N.BitLen() < 2048 {
				return nil, errors.New("timed access RSA keys require at least 2048 bits")
			}
		default:
			return nil, errors.New("timed access requires an Ed25519, ECDSA or RSA SHA-2 SSH key")
		}
		p.key, p.id = key, ssh.FingerprintSHA256(key)
		if seenAgents[p.AgentID] || seenKeys[p.id] {
			return nil, errors.New("duplicate timed access principal or AgentID")
		}
		seenAgents[p.AgentID], seenKeys[p.id] = true, true
	}
	for vault, services := range c.ProtectedServices {
		if vault == "" || len(services) == 0 {
			return nil, errors.New("invalid protected service policy")
		}
		seen := map[string]bool{}
		for _, service := range services {
			if service == "" || seen[service] {
				return nil, errors.New("invalid protected service policy")
			}
			seen[service] = true
		}
	}
	m := &Manager{Config: c, Store: s, Now: time.Now}
	m.Verifier = HelperVerifier{Helper: c.Helper, PinsDir: c.PinsDir}
	return m, nil
}

func (m *Manager) Protected(vault, service string) bool {
	for _, s := range m.Config.ProtectedServices[vault] {
		if s == service {
			return true
		}
	}
	return false
}

func (m *Manager) Principal(agentID string) (Principal, bool) {
	for _, p := range m.Config.Principals {
		if p.AgentID == agentID {
			return p, true
		}
	}
	return Principal{}, false
}

func SignaturePayload(raw []byte) []byte {
	return append([]byte("agent-vault/request-access/v1\x00"), raw...)
}

func validText(v string) bool {
	return v != "" && len(v) <= 1024 && !strings.ContainsFunc(v, unicode.IsControl)
}

func ValidateRequest(r Request, now time.Time) error {
	nonce, err := base64.RawURLEncoding.DecodeString(r.Nonce)
	if err != nil || len(nonce) != 32 || r.Type != RequestType || r.Version != Version || r.DurationSeconds < 1 || r.DurationSeconds > MaxDuration ||
		r.ExpiresAt <= r.IssuedAt || r.IssuedAt < now.Unix()-90 || r.IssuedAt > now.Unix()+5 || r.ExpiresAt-r.IssuedAt > 90 || r.ExpiresAt <= now.Unix() {
		return errors.New("invalid or expired access request")
	}
	for _, text := range []string{r.Audience, r.Principal, r.Host, r.Vault, r.Service, r.Purpose, r.RequestID} {
		if !validText(text) {
			return errors.New("invalid access scope")
		}
	}
	if len(r.RequestID) > 128 || strings.ContainsFunc(r.RequestID, func(c rune) bool {
		valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		return !valid
	}) {
		return errors.New("invalid request ID")
	}
	return nil
}

// Issue verifies both independent signatures, then persists an absolute
// expiry in the same atomic row that consumes the signed request ID.
func (m *Manager) Issue(ctx context.Context, agentID, role, vaultID, vaultName string, sub Submission) (*store.TimedAccessGrant, error) {
	p, ok := m.Principal(agentID)
	if !ok || role != "proxy" {
		return nil, ErrDenied
	}
	var r Request
	if len(sub.RequestJSON) > 16*1024 || DecodeStrict([]byte(sub.RequestJSON), &r) != nil {
		return nil, ErrDenied
	}
	raw, _ := json.Marshal(r)
	if !bytes.Equal(raw, []byte(sub.RequestJSON)) || ValidateRequest(r, m.Now()) != nil || r.Audience != m.Config.Audience || r.Principal != p.id || r.Vault != vaultName || !m.Protected(vaultName, r.Service) {
		return nil, ErrDenied
	}
	if sub.RequestSignature.Format == ssh.KeyAlgoRSA || p.key.Verify(SignaturePayload(raw), &sub.RequestSignature) != nil {
		return nil, ErrDenied
	}
	if m.Verifier == nil || m.Verifier.Verify(ctx, p, sub) != nil {
		return nil, ErrDenied
	}
	// Recheck ceremony expiry after the bounded verifier subprocess.
	now := m.Now()
	if err := ValidateRequest(r, now); err != nil {
		return nil, ErrDenied
	}
	hash := sha256.Sum256(raw)
	return m.Store.ConsumeTimedAccess(ctx, store.TimedAccessGrant{
		RequestID: r.RequestID, RequestHash: hex.EncodeToString(hash[:]), Principal: p.id, AgentID: agentID, VaultID: vaultID, Service: r.Service,
		ApprovedAt: now, ExpiresAt: now.Add(time.Duration(r.DurationSeconds) * time.Second),
	})
}

func (m *Manager) Authorize(ctx context.Context, agentID, userID, role, vaultID, vaultName, service string) error {
	if !m.Protected(vaultName, service) {
		return nil
	}
	p, ok := m.Principal(agentID)
	if !ok || userID != "" || role != "proxy" {
		return ErrDenied
	}
	active, err := m.Store.HasTimedAccess(ctx, p.id, agentID, vaultID, service, m.Now())
	if err != nil || !active {
		return ErrDenied
	}
	return nil
}

type HelperVerifier struct{ Helper, PinsDir string }

func (v HelperVerifier) Verify(ctx context.Context, p Principal, sub Submission) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Requester-controlled bytes go only on stdin. Executable, trust registry,
	// expected approver and origin are service-owned configuration.
	input, err := json.Marshal(struct {
		RequestJSON string          `json:"request_json"`
		Approval    json.RawMessage `json:"approval"`
	}{sub.RequestJSON, sub.Approval})
	if err != nil || len(input) > 64*1024 {
		return ErrDenied
	}
	cmd := exec.CommandContext(ctx, v.Helper, "access", "verify", "--config-dir", v.PinsDir, "--approver", p.Approver)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	var output cappedOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err = cmd.Run(); err != nil {
		return ErrDenied
	}
	if !bytes.Equal(bytes.TrimSpace(output.raw.Bytes()), []byte(`{"type":"credential_access_verified","version":4}`)) {
		return ErrDenied
	}
	return nil
}

type cappedOutput struct{ raw bytes.Buffer }

func (w *cappedOutput) Write(p []byte) (int, error) {
	if w.raw.Len()+len(p) > 1024 {
		return 0, fmt.Errorf("verifier output exceeds bound")
	}
	return w.raw.Write(p)
}
