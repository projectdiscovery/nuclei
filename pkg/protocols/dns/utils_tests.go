package dns

import (
	"errors"
	"testing"

	"github.com/projectdiscovery/retryabledns"
)

// helper to create a test resolver
func newTestResolver(t *testing.T) *retryabledns.Client {
	resolver, err := retryabledns.New([]string{"1.1.1.1:53"}, 1)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}
	return resolver
}

func TestTryToResolveHost_SuccessARecord(t *testing.T) {
	resolver := newTestResolver(t)

	ip, err := tryToResolveHost("example.com", resolver)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ip == "" {
		t.Fatal("expected non-empty IP for example.com")
	}
	t.Logf("resolved example.com -> %s", ip)
}

func TestTryToResolveHost_SuccessAAAARecord(t *testing.T) {
	resolver := newTestResolver(t)

	ip, err := tryToResolveHost("ipv6.google.com", resolver)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ip == "" {
		t.Fatal("expected non-empty IPv6 address for ipv6.google.com")
	}
	t.Logf("resolved ipv6.google.com -> %s", ip)
}

func TestTryToResolveHost_IPNotFound(t *testing.T) {
	resolver := newTestResolver(t)

	_, err := tryToResolveHost("nonexistent-subdomain.ef37979f-9fff-43f8-b267-822108d4291c.com", resolver)
	if !errors.Is(err, IPNotFoundError) && err == nil {
		t.Fatalf("expected IPNotFoundError or DNS error, got: %v", err)
	}
}

func TestTryToResolveHost_InvalidDomain(t *testing.T) {
	resolver := newTestResolver(t)

	_, err := tryToResolveHost("invalid_domain_###", resolver)
	if err == nil {
		t.Fatal("expected error for invalid domain name, got nil")
	}
}

func TestTryToResolveHost_NilResolver(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic with nil resolver, but did not panic")
		}
	}()
	_, _ = tryToResolveHost("example.com", nil)
}
