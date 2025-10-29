package dns

import (
	"testing"

	"github.com/projectdiscovery/retryabledns"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	require.NotEmpty(t, ip)
	require.Contains(t, ip, ".")
}

func TestTryToResolveHost_SuccessAAAARecord(t *testing.T) {
	resolver := newTestResolver(t)

	ip, err := tryToResolveHost("ipv6.google.com", resolver)
	require.NoError(t, err)
	require.NotEmpty(t, ip)
	require.Contains(t, ip, ":")
}

func TestTryToResolveHost_IPNotFound(t *testing.T) {
	resolver := newTestResolver(t)

	_, err := tryToResolveHost("nonexistent-subdomain.ef37979f-9fff-43f8-b267-822108d4291c.com", resolver)
	require.Error(t, err, "expected IPNotFoundError or DNS error for non-existent domain")
}

func TestTryToResolveHost_InvalidDomain(t *testing.T) {
	resolver := newTestResolver(t)

	_, err := tryToResolveHost("invalid_domain_###", resolver)
	require.Error(t, err)
}

func TestTryToResolveHost_NilResolver(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic with nil resolver, but did not panic")
		}
	}()
	_, _ = tryToResolveHost("example.com", nil)
}
