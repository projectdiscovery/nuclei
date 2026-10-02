package runner

import (
	"errors"
	"strings"
	"testing"

	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/stretchr/testify/require"
)

func TestAppendPDCPHealthCheckSkippedWithoutCreds(t *testing.T) {
	var b strings.Builder
	appendPDCPHealthCheck(&b, func() (*pdcpauth.PDCPCredentials, error) {
		return nil, pdcpauth.ErrNoCreds
	}, func(key, server, tool string) (*pdcpauth.PDCPCredentials, error) {
		t.Fatal("validate should not be called")
		return nil, nil
	})
	require.Empty(t, b.String())
}

func TestAppendPDCPHealthCheckOk(t *testing.T) {
	var b strings.Builder
	appendPDCPHealthCheck(&b, func() (*pdcpauth.PDCPCredentials, error) {
		return &pdcpauth.PDCPCredentials{APIKey: "key", Server: "https://api.example"}, nil
	}, func(key, server, tool string) (*pdcpauth.PDCPCredentials, error) {
		require.Equal(t, "key", key)
		require.Equal(t, "https://api.example", server)
		return &pdcpauth.PDCPCredentials{Username: "alice", Email: "a@b.c", APIKey: key, Server: server}, nil
	})
	require.Equal(t, "PDCP API (https://api.example) => Ok (@alice)\n", b.String())
}

func TestAppendPDCPHealthCheckKo(t *testing.T) {
	var b strings.Builder
	appendPDCPHealthCheck(&b, func() (*pdcpauth.PDCPCredentials, error) {
		return &pdcpauth.PDCPCredentials{APIKey: "bad", Server: "https://api.example"}, nil
	}, func(key, server, tool string) (*pdcpauth.PDCPCredentials, error) {
		return nil, errors.New("invalid status code: 401")
	})
	require.Equal(t, "PDCP API (https://api.example) => Ko (invalid status code: 401)\n", b.String())
}
