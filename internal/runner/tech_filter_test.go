package runner

import (
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/stretchr/testify/require"
)

func TestFingerprintURLForInput(t *testing.T) {
	require.Equal(t, "http://a/", fingerprintURLForInput("http://a/", nil))
	require.Equal(t, "", fingerprintURLForInput("example.com", nil))

	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.NoError(t, err)
	t.Cleanup(func() { _ = hm.Close() })
	require.NoError(t, hm.Set("example.com", []byte("https://example.com")))
	helper := &input.Helper{InputsHTTP: hm, InputsHTTPProbed: true}
	require.Equal(t, "https://example.com", fingerprintURLForInput("example.com", helper))
}
