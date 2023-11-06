package pdcp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadCreds(t *testing.T) {
	// temporarily change PDCP file location for testing
	PDCPCredFile = "creds.yaml"
	h := &PDCPCredHandler{}
	value, err := h.GetCreds()
	require.Nil(t, err)
	require.NotNil(t, value)
	require.Equal(t, "test", value.Username)
	require.Equal(t, "testpassword", value.APIKey)
	require.Equal(t, "https://scanme.sh", value.Server)
}
