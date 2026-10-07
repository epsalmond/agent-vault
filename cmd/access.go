package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/Infisical/agent-vault/internal/timedaccess"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var accessCmd = &cobra.Command{Use: "access", Short: "Request timed credential access through Oshioki"}

var accessRequestCmd = &cobra.Command{
	Use: "request", Short: "Approve access to an existing broker service, then retry your CLI",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		sess, source, err := resolveSession()
		if err != nil {
			return err
		}
		vault, err := resolveVaultForCommand(cmd, source)
		if err != nil {
			return err
		}
		service, _ := cmd.Flags().GetString("service")
		purpose, _ := cmd.Flags().GetString("purpose")
		keyPath, _ := cmd.Flags().GetString("ssh-key")
		pinsDir, _ := cmd.Flags().GetString("oshioki-config")
		helper, _ := cmd.Flags().GetString("oshioki")
		audience, _ := cmd.Flags().GetString("audience")
		duration, _ := cmd.Flags().GetDuration("duration")
		if duration < time.Second || duration > time.Hour || duration%time.Second != 0 {
			return fmt.Errorf("duration must be whole seconds from 1s to 1h (default 5m)")
		}
		signer, closeSigner, err := accessSigner(keyPath)
		if err != nil {
			return err
		}
		defer closeSigner()
		var nonce [32]byte
		var id [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return err
		}
		if _, err = rand.Read(id[:]); err != nil {
			return err
		}
		host, err := os.Hostname()
		if err != nil {
			return err
		}
		if audience == "" {
			audience = sess.Address
		}
		now := time.Now()
		request := timedaccess.Request{Type: timedaccess.RequestType, Version: timedaccess.Version, Audience: audience,
			Principal: ssh.FingerprintSHA256(signer.PublicKey()), Host: host, Vault: vault, Service: service, Purpose: purpose,
			DurationSeconds: int(duration / time.Second), RequestID: hex.EncodeToString(id[:]), Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]),
			IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 90}
		if err = timedaccess.ValidateRequest(request, now); err != nil {
			return err
		}
		raw, err := json.Marshal(request)
		if err != nil {
			return err
		}
		var sig *ssh.Signature
		if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
			algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
			if !ok {
				return fmt.Errorf("SSH signer must support RSA SHA-2")
			}
			sig, err = algorithmSigner.SignWithAlgorithm(rand.Reader, timedaccess.SignaturePayload(raw), ssh.KeyAlgoRSASHA512)
		} else {
			sig, err = signer.Sign(rand.Reader, timedaccess.SignaturePayload(raw))
		}
		if err != nil {
			return fmt.Errorf("sign requester identity: %w", err)
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 95*time.Second)
		defer cancel()
		approvalCmd := exec.CommandContext(ctx, helper, "access", "request", "--config-dir", pinsDir)
		approvalCmd.Stdin = bytes.NewReader(raw)
		approvalCmd.Stderr = cmd.ErrOrStderr()
		output, err := approvalCmd.Output()
		if err != nil {
			return fmt.Errorf("oshioki access denied or unavailable: %w", err)
		}
		var approved struct {
			RequestJSON string          `json:"request_json"`
			Approval    json.RawMessage `json:"approval"`
		}
		if len(output) > 64*1024 || timedaccess.DecodeStrict(output, &approved) != nil || approved.RequestJSON != string(raw) {
			return fmt.Errorf("oshioki returned an invalid or altered access request")
		}
		body, err := json.Marshal(timedaccess.Submission{RequestJSON: string(raw), RequestSignature: *sig, Approval: approved.Approval})
		if err != nil {
			return err
		}
		result, err := doVaultScopedRequestWithBody("POST", sess.Address+"/v1/access/grants", sess.Token, vault, body)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(result))
		return nil
	},
}

// A public key path selects that existing key from ssh-agent. Private key
// paths also work for unencrypted keys. Key generation/enrollment is separate.
func accessSigner(path string) (ssh.Signer, func(), error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, func() {}, err
	}
	if signer, err := ssh.ParsePrivateKey(raw); err == nil {
		return signer, func() {}, nil
	}
	pub, _, options, rest, err := ssh.ParseAuthorizedKey(raw)
	if err != nil || len(options) != 0 || len(rest) != 0 {
		return nil, func() {}, fmt.Errorf("ssh-key must be an unencrypted private key or a public key loaded in ssh-agent")
	}
	conn, err := net.DialTimeout("unix", os.Getenv("SSH_AUTH_SOCK"), 2*time.Second)
	if err != nil {
		return nil, func() {}, fmt.Errorf("connect to ssh-agent: %w", err)
	}
	if err = conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		_ = conn.Close()
		return nil, func() {}, err
	}
	signers, err := agent.NewClient(conn).Signers()
	if err == nil {
		for _, signer := range signers {
			if bytes.Equal(signer.PublicKey().Marshal(), pub.Marshal()) {
				return signer, func() { _ = conn.Close() }, nil
			}
		}
	}
	_ = conn.Close()
	return nil, func() {}, fmt.Errorf("the enrolled SSH key is not available in ssh-agent")
}

func init() {
	rootCmd.AddCommand(accessCmd)
	accessCmd.AddCommand(accessRequestCmd)
	f := accessRequestCmd.Flags()
	f.String("vault", "", "target vault (or AGENT_VAULT_VAULT)")
	f.String("service", "", "existing canonical service name from discover")
	f.String("purpose", "", "why access is needed, shown to the approver")
	f.Duration("duration", 5*time.Minute, "timed access duration, up to 1h")
	f.String("ssh-key", "", "enrolled SSH private key or public key in ssh-agent")
	f.String("oshioki-config", "", "requester's existing Oshioki enrollment/transport config directory")
	f.String("oshioki", "oshioki", "Oshioki request helper executable")
	f.String("audience", "", "broker audience from operator policy (defaults to server address)")
	for _, flag := range []string{"service", "purpose", "ssh-key", "oshioki-config"} {
		_ = accessRequestCmd.MarkFlagRequired(flag)
	}
}
