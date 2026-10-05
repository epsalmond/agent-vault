package mitm

import (
	"context"
	"errors"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTP2CancellationAndConcurrentStreams(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	client, server, _ := setupHTTP2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocked" {
			close(entered)
			<-r.Context().Done()
			close(canceled)
			return
		}
		if r.Header.Get("X-Stream") != r.URL.Query().Get("id") {
			t.Error("stream headers crossed")
		}
		// Fixed response values exercise isolation without reflecting arbitrary input.
		var reply string
		switch r.URL.Query().Get("id") {
		case "a":
			reply = "a"
		case "b":
			reply = "b"
		case "c":
			reply = "c"
		case "d":
			reply = "d"
		case "e":
			reply = "e"
		case "f":
			reply = "f"
		case "g":
			reply = "g"
		case "h":
			reply = "h"
		}
		w.Write([]byte(reply))
	}), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var readBytes atomic.Int64
	reader := &countingReader{n: &readBytes}
	req, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/blocked", io.NopCloser(io.LimitReader(reader, 65<<20)))
	failed := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		failed <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("stream never reached upstream before EOF")
	}
	// The upstream deliberately consumes no body. A healthy multiplexed RPC
	// must still finish, and flow control must keep this upload bounded.
	const count = 8
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		go func(id string) {
			req, _ := http.NewRequest("GET", server.URL+"/healthy?id="+id, nil)
			req.Header.Set("X-Stream", id)
			resp, err := client.Do(req)
			if err != nil {
				results <- err
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err == nil && string(body) != id {
				err = errors.New("stream response crossed")
			}
			results <- err
		}(string(rune('a' + i)))
	}
	for i := 0; i < count; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if n := readBytes.Load(); n > 16<<20 {
		t.Fatalf("blocked upload read %d bytes; backpressure failed", n)
	}
	cancel()
	select {
	case err := <-failed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client cancel stalled")
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not reach upstream")
	}
	resp, err := client.Get(server.URL + "/healthy?id=")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}

type countingReader struct{ n *atomic.Int64 }

func (r *countingReader) Read(b []byte) (int, error) {
	clear(b)
	r.n.Add(int64(len(b)))
	return len(b), nil
}

func TestHTTP2ConnectAuthorityPinned(t *testing.T) {
	var gotHost string
	client, server, _ := setupHTTP2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotHost = r.Host; w.Write([]byte("ok")) }), nil)
	req, _ := http.NewRequest("GET", server.URL+"/rpc", nil)
	req.Host = "other-credential.example"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if gotHost != req.URL.Host {
		t.Fatalf("upstream authority %q expected %q", gotHost, req.URL.Host)
	}
	if resp.ProtoMajor != 2 {
		t.Fatal(resp.Proto)
	}
}

func TestHTTP2LimitsAbortOnlyOversizedStream(t *testing.T) {
	client, server, p := setupHTTP2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upload" {
			_, _ = io.Copy(io.Discard, r.Body)
			return
		}
		w.Header().Set("Trailer", "Grpc-Status")
		if r.URL.Path == "/large" {
			w.Write(make([]byte, 4096))
		} else {
			w.Write([]byte("ok"))
		}
		w.Header().Set("Grpc-Status", "0")
	}), nil)
	// Configure before the first request/stream starts.
	p.maxResponseBytes = 1024
	p.maxRequestBytes = 1024
	req, _ := http.NewRequest("POST", server.URL+"/upload", io.NopCloser(io.LimitReader(repeatingReader{}, 4096)))
	resp, err := client.Do(req)
	if err == nil {
		_, readErr := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 400 && readErr == nil {
			t.Fatalf("oversized upload ended successfully: status %d", resp.StatusCode)
		}
	}
	resp, err = client.Get(server.URL + "/large")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil && resp.StatusCode == 200 {
		t.Fatal("oversized response ended successfully")
	}
	if resp.Trailer.Get("Grpc-Status") == "0" {
		t.Fatal("truncated stream reported successful gRPC status")
	}
	reused := false
	req, _ = http.NewRequest("GET", server.URL+"/ok", nil)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "ok" || !reused {
		t.Fatalf("healthy stream after abort: %q %v reused=%v", body, err, reused)
	}
}

func TestHTTP2AuthorizedActiveStreamCanFinishAfterRevocation(t *testing.T) {
	var revoked atomic.Bool
	resolver := &fakeSessionResolver{resolve: func(token, hint string) (*brokercore.ProxyScope, error) {
		if revoked.Load() {
			return nil, brokercore.ErrInvalidSession
		}
		return &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"}, nil
	}}
	client, server, _ := setupHTTP2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		io.Copy(w, r.Body)
	}), resolver)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req, _ := http.NewRequest("POST", server.URL, reader)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	revoked.Store(true)
	done := make(chan error, 1)
	go func() { _, err := writer.Write([]byte("already authorized")); writer.Close(); done <- err }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "already authorized" {
		t.Fatalf("active stream %q %v", body, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
