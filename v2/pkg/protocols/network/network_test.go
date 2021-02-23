package network

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestNetworkCompileMake(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-network"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Hostname}}", "{{Hostname}}:8082", "tls://{{Hostname}}:443"},
		ReadSize: 1024,
		Inputs:   []*Input{{Data: "test-data"}},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: map[string]interface{}{"severity": "low", "name": "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile network request")

	require.Equal(t, 3, len(request.addresses), "could not get correct number of input address")
	t.Run("check-host", func(t *testing.T) {
		require.Equal(t, "{{Hostname}}", request.addresses[0].ip, "could not get correct host")
	})
	t.Run("check-host-with-port", func(t *testing.T) {
		require.Equal(t, "{{Hostname}}", request.addresses[1].ip, "could not get correct host with port")
		require.Equal(t, "8082", request.addresses[1].port, "could not get correct port for host")
	})
	t.Run("check-tls-with-port", func(t *testing.T) {
		require.Equal(t, "{{Hostname}}", request.addresses[2].ip, "could not get correct host with port")
		require.Equal(t, "443", request.addresses[2].port, "could not get correct port for host")
		require.True(t, request.addresses[2].tls, "could not get correct port for host")
	})
}
