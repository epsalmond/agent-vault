package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func setupHTTP2Proxy(t *testing.T, handler http.Handler, resolver brokercore.SessionResolver) (*http.Client, *httptest.Server, *Proxy) {
	t.Helper()
	upstream := httptest.NewUnstartedServer(handler)
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	if resolver == nil {
		resolver = validTokenResolver("fake-session", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	}
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{"127.0.0.1": {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer fake-credential", "X-Api-Key": "fake-key"}}}}}
	proxyURL, roots, p := setupProxy(t, resolver, cp)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}
	client := newTrustingClient(proxyURL, url.User("fake-session"), roots)
	transport := client.Transport.(*http.Transport)
	transport.ForceAttemptHTTP2 = true
	t.Cleanup(transport.CloseIdleConnections)
	return client, upstream, p
}

func TestHTTP2DuplexAndTrailers(t *testing.T) {
	requestTrailers := make(chan http.Header, 1)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.TLS.NegotiatedProtocol != "h2" {
			t.Errorf("upstream protocol %s", r.Proto)
		}
		if r.Header.Get("Authorization") != "Bearer fake-credential" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Vault") != "" {
			t.Error("credential isolation")
		}
		if r.Header.Get("Te") != "trailers" {
			t.Errorf("TE = %q", r.Header.Get("Te"))
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message, Grpc-Status-Details-Bin, X-Binary-Bin, Set-Cookie")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		b := make([]byte, 5)
		if _, err := io.ReadFull(r.Body, b); err != nil {
			t.Error(err)
			return
		}
		w.Write(b)
		w.(http.Flusher).Flush()
		rest, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		w.Write(rest)
		requestTrailers <- r.Trailer.Clone()
		w.Header().Set("Grpc-Status", "7")
		w.Header().Set("Grpc-Message", "permission%20denied")
		w.Header().Set("Grpc-Status-Details-Bin", "AAH+/w==")
		w.Header().Set("X-Binary-Bin", "AP8=")
		w.Header().Set("Set-Cookie", "forbidden=1")
	})
	client, server, _ := setupHTTP2Proxy(t, upstream, nil)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req, _ := http.NewRequest("POST", server.URL+"/rpc", reader)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Authorization", "Bearer placeholder")
	req.Header.Set("X-Vault", "untrusted")
	req.Trailer = http.Header{"X-Request-Bin": nil, "X-Api-Key": nil, "X-Vault": nil}
	responses := make(chan *http.Response, 1)
	errors := make(chan error, 1)
	go func() {
		resp, err := client.Do(req) //nolint:bodyclose // Response ownership transfers through the channel to the caller.
		if err != nil {
			errors <- err
			return
		}
		responses <- resp
	}()
	writer.Write([]byte{0, 0, 0, 0, 3})
	var resp *http.Response
	select {
	case resp = <-responses:
	case err := <-errors:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("response headers waited for client EOF")
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("client protocol %s", resp.Proto)
	}
	first := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, []byte{0, 0, 0, 0, 3}) {
		t.Fatal(first)
	}
	req.Trailer.Set("X-Request-Bin", "AAH+/w==")
	req.Trailer.Set("X-Api-Key", "client-trailer")
	req.Trailer.Set("X-Vault", "other-vault")
	writer.Write([]byte{0, 255, 128})
	writer.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || !bytes.Equal(body, []byte{0, 255, 128}) {
		t.Fatalf("body=%v err=%v", body, err)
	}
	trailers := <-requestTrailers
	if trailers.Get("X-Request-Bin") != "AAH+/w==" || trailers.Get("X-Api-Key") != "" || trailers.Get("X-Vault") != "" {
		t.Errorf("request trailers %v", trailers)
	}
	if resp.Trailer.Get("Grpc-Status") != "7" || resp.Trailer.Get("Grpc-Message") != "permission%20denied" || resp.Trailer.Get("Grpc-Status-Details-Bin") != "AAH+/w==" || resp.Trailer.Get("X-Binary-Bin") != "AP8=" || resp.Trailer.Get("Set-Cookie") != "" {
		t.Errorf("response trailers %v", resp.Trailer)
	}
}

func TestHTTP2SessionRevalidatedOnOpenTunnel(t *testing.T) {
	for _, reason := range []string{"expired", "revoked", "grant removed", "vault changed"} {
		t.Run(reason, func(t *testing.T) {
			var denied atomic.Bool
			var calls atomic.Int32
			sr := &fakeSessionResolver{resolve: func(token, hint string) (*brokercore.ProxyScope, error) {
				if denied.Load() {
					if reason == "grant removed" {
						return nil, brokercore.ErrVaultAccessDenied
					}
					if reason == "vault changed" {
						return &brokercore.ProxyScope{VaultID: "v2", VaultName: "other", VaultRole: "proxy"}, nil
					}
					return nil, brokercore.ErrInvalidSession
				}
				return &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"}, nil
			}}
			client, server, _ := setupHTTP2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte("ok")) }), sr)
			req, _ := http.NewRequest("GET", server.URL, nil)
			reused := false
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.ProtoMajor != 2 {
				t.Fatalf("protocol %s", resp.Proto)
			}
			denied.Store(true)
			reused = false
			resp, err = client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 407 && resp.StatusCode != 403 {
				t.Fatalf("denied status %d", resp.StatusCode)
			}
			if !reused {
				t.Fatal("denial did not reuse established CONNECT")
			}
			if calls.Load() != 1 {
				t.Fatalf("upstream calls=%d", calls.Load())
			}
		})
	}
}

func TestHTTP2UnknownLengthLargeBody(t *testing.T) {
	const size = 65 << 20
	client, server, _ := setupHTTP2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil || n != size {
			t.Errorf("read %d: %v", n, err)
		}
		w.Write([]byte("ok"))
	}), nil)
	client.Timeout = 30 * time.Second // Race instrumentation slows this 65 MiB transfer.
	req, _ := http.NewRequestWithContext(context.Background(), "POST", server.URL, io.NopCloser(io.LimitReader(repeatingReader{}, size)))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
}

type repeatingReader struct{}

func (repeatingReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
