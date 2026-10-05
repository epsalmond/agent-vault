package mitm

import (
	"io"
	"net/http"
	"strings"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"golang.org/x/net/http/httpguts"
)

func connectionHeaderNames(h http.Header) map[string]bool {
	names := make(map[string]bool)
	for _, line := range h.Values("Connection") {
		for _, name := range strings.Split(line, ",") {
			names[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	return names
}

func acceptsTrailers(h http.Header) bool {
	if connectionHeaderNames(h)["Te"] {
		return false
	}
	for _, line := range h.Values("Te") {
		for _, value := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(value), "trailers") {
				return true
			}
		}
	}
	return false
}

func requestTrailers(r *http.Request, inject *brokercore.InjectResult) http.Header {
	blocked := connectionHeaderNames(r.Header)
	for k := range inject.Headers {
		blocked[http.CanonicalHeaderKey(k)] = true
	}
	// Header substitutions can also inject a credential into a client-named
	// field. Prevent a trailing value from conflicting with that field.
	for _, sub := range inject.Substitutions {
		for _, surface := range sub.In {
			if surface != "header" {
				continue
			}
			for k, values := range r.Header {
				for _, value := range values {
					if strings.Contains(value, sub.Placeholder) {
						blocked[http.CanonicalHeaderKey(k)] = true
					}
				}
			}
		}
	}
	trailers := make(http.Header)
	for k, v := range r.Trailer {
		name := http.CanonicalHeaderKey(k)
		if brokercore.IsHopByHop(name) || brokercore.IsBrokerScopedRequestHeader(name) || blocked[name] || !httpguts.ValidTrailerHeader(name) {
			continue
		}
		trailers[name] = v
	}
	return trailers
}

// trailerBody updates only the preapproved trailer fields. The transport
// reads trailers after Read returns EOF, so values never race its encoder.
type trailerBody struct {
	io.ReadCloser
	source http.Header
	target http.Header
}

func (b *trailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		for k := range b.target {
			b.target[k] = b.source.Values(k)
		}
	}
	return n, err
}

func allowedResponseTrailer(name string, blocked map[string]bool) bool {
	name = http.CanonicalHeaderKey(name)
	return !brokercore.ShouldStripResponseHeader(name) && !blocked[name] && httpguts.ValidTrailerHeader(name)
}
