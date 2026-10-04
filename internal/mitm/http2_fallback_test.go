package mitm

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestHTTP2KnownLengthRequestTrailersSurviveHTTP1Upstream(t *testing.T) {
	got := make(chan http.Header, 1)
	client, server, p := setupHTTP2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.ContentLength != -1 {
			t.Errorf("upstream framing %s length=%d", r.Proto, r.ContentLength)
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		got <- r.Trailer.Clone()
		w.Write([]byte("ok"))
	}), nil)
	p.upstream.ForceAttemptHTTP2 = false
	p.upstream.TLSClientConfig.NextProtos = []string{"http/1.1"}
	req, _ := http.NewRequest("POST", server.URL, strings.NewReader("payload"))
	req.Trailer = http.Header{"X-Request-Bin": {"AAH+/w=="}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("downstream protocol %s", resp.Proto)
	}
	if trailers := <-got; trailers.Get("X-Request-Bin") != "AAH+/w==" {
		t.Fatalf("H2 to H1 request trailer lost: %v", trailers)
	}
}

func TestHTTP2ResponseTrailersSurviveHTTP1Downstream(t *testing.T) {
	for _, announce := range []bool{true, false} {
		t.Run(map[bool]string{true: "declared", false: "late"}[announce], func(t *testing.T) {
			client, server, _ := setupHTTP2Proxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 {
					t.Errorf("upstream protocol %s", r.Proto)
				}
				w.Header().Set("Content-Length", "7")
				if announce {
					w.Header().Set("Trailer", "X-Response-Bin")
				}
				w.Write([]byte("payload"))
				w.(http.Flusher).Flush()
				if announce {
					w.Header().Set("X-Response-Bin", "AAH+/w==")
				} else {
					w.Header().Set(http.TrailerPrefix+"X-Response-Bin", "AAH+/w==")
				}
			}), nil)
			transport := client.Transport.(*http.Transport)
			transport.ForceAttemptHTTP2 = false
			transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || string(body) != "payload" {
				t.Fatalf("response %q %v", body, err)
			}
			if resp.ProtoMajor != 1 || resp.ContentLength != -1 {
				t.Fatalf("downstream framing %s length=%d", resp.Proto, resp.ContentLength)
			}
			if resp.Trailer.Get("X-Response-Bin") != "AAH+/w==" {
				t.Fatalf("H2 to H1 response trailer lost: %v", resp.Trailer)
			}
		})
	}
}
