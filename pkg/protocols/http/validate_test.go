package http

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateRedirectsCombinations(t *testing.T) {
	t.Run("redirects and host-redirects conflict", func(t *testing.T) {
		req := &Request{Redirects: true, HostRedirects: true}
		err := req.validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "'redirects' and 'host-redirects' can't be used together")
	})

	t.Run("redirects alone is valid", func(t *testing.T) {
		req := &Request{Redirects: true}
		err := req.validate()
		require.NoError(t, err)
	})

	t.Run("host-redirects alone is valid", func(t *testing.T) {
		req := &Request{HostRedirects: true}
		err := req.validate()
		require.NoError(t, err)
	})

	t.Run("protocol-redirects without redirects or host-redirects is invalid", func(t *testing.T) {
		req := &Request{ProtocolRedirects: true}
		err := req.validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "'protocol-redirects' requires 'redirects' or 'host-redirects'")
	})

	t.Run("protocol-redirects with redirects is valid", func(t *testing.T) {
		req := &Request{Redirects: true, ProtocolRedirects: true}
		err := req.validate()
		require.NoError(t, err)
	})

	t.Run("protocol-redirects with host-redirects is valid", func(t *testing.T) {
		req := &Request{HostRedirects: true, ProtocolRedirects: true}
		err := req.validate()
		require.NoError(t, err)
	})

	t.Run("no redirect options is valid", func(t *testing.T) {
		req := &Request{}
		err := req.validate()
		require.NoError(t, err)
	})
}
