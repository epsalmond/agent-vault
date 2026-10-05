package mitm

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func TestTrailerPolicy(t *testing.T) {
	req := &http.Request{Header: http.Header{"Connection": {"X-Hop, te"}, "X-Substituted": {"token-placeholder"}}, Trailer: http.Header{
		"Authorization": {"untrusted"}, "Proxy-Authorization": {"session"}, "X-Vault": {"other"}, "X-Api-Key": {"untrusted"}, "X-Substituted": {"untrusted"}, "X-Hop": {"secret"}, "Content-Length": {"123"}, "X-Binary-Bin": {"AAH+/w=="},
	}}
	inject := &brokercore.InjectResult{Headers: map[string]string{"X-Api-Key": "fake-key"}, Substitutions: []brokercore.ResolvedSubstitution{{Placeholder: "token-placeholder", Value: "fake-secret", In: []string{"header"}}}}
	trailers := requestTrailers(req, inject)
	if len(trailers) != 1 || trailers.Get("X-Binary-Bin") != "AAH+/w==" {
		t.Fatal(trailers)
	}
	if acceptsTrailers(req.Header) {
		t.Fatal("Connection-nominated TE survived")
	}
	for _, value := range []string{"gzip", "trailers;q=0", "deflate"} {
		if acceptsTrailers(http.Header{"Te": {value}}) {
			t.Fatalf("invalid TE %q", value)
		}
	}
	if !acceptsTrailers(http.Header{"Te": {"gzip, TRAILERS"}}) {
		t.Fatal("legal trailer token stripped")
	}
	for _, name := range []string{"Set-Cookie", "Connection", "Content-Length", "Authorization", "X-Hop"} {
		if allowedResponseTrailer(name, map[string]bool{"X-Hop": true}) {
			t.Fatalf("illegal response trailer %s", name)
		}
	}
}

func TestHTTP2RejectsGRPCBodySubstitutions(t *testing.T) {
	var calls atomic.Int32
	client, server, p := setupHTTP2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }), nil)
	cp := p.creds.(*fakeCredProvider)
	cp.byHost["127.0.0.1"].result.Substitutions = []brokercore.ResolvedSubstitution{{Placeholder: "placeholder", Value: "fake-secret", In: []string{"body"}}}
	req, _ := http.NewRequest("POST", server.URL, strings.NewReader("opaque protobuf"))
	req.Header.Set("Content-Type", "application/grpc+proto")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 400 || !strings.Contains(string(body), "unsupported_body_substitution") || calls.Load() != 0 {
		t.Fatalf("body substitution: %d %s calls=%d", resp.StatusCode, body, calls.Load())
	}
}
