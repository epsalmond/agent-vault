package brokercore

import (
	"context"
	"errors"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

type countingDynamic struct{ calls int }

func (d *countingDynamic) Resolve(context.Context, string, string) (string, bool, error) {
	d.calls++
	return "fake", true, nil
}

func TestTimedAccessDeniesBeforeCredentialResolutionAndDynamicRenewal(t *testing.T) {
	s := newFakeCredStore()
	s.setServices(t, "v1", []broker.Service{{Name: "catalog", Host: "catalog.example", Auth: broker.Auth{Type: "bearer", Token: "CATALOG_KEY"}}})
	dynamic := &countingDynamic{}
	p := NewStoreCredentialProvider(s, make32(1))
	p.Dynamic = dynamic
	var gotScope *ProxyScope
	var gotService string
	p.AccessAuthorizer = func(_ context.Context, scope *ProxyScope, service string) error {
		gotScope, gotService = scope, service
		return ErrAccessRequired
	}
	scope := &ProxyScope{AgentID: "a1", VaultID: "v1", VaultName: "default", VaultRole: "proxy"}
	_, err := p.InjectScoped(context.Background(), scope, "catalog.example", 443, "/")
	if !errors.Is(err, ErrAccessRequired) || gotScope != scope || gotService != "catalog" || s.getCredentialCalls != 0 || dynamic.calls != 0 {
		t.Fatalf("denied request touched credentials: err=%v service=%s lookups=%d dynamic=%d", err, gotService, s.getCredentialCalls, dynamic.calls)
	}
}
