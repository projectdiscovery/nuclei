package pdcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var exampleCred = `
- username: test
  api-key: testpassword
  server: https://scanme.sh
`

func TestLoadCreds(t *testing.T) {
	// temporarily change PDCP file location for testing
	f, err := os.CreateTemp("", "creds-test-*")
	require.Nil(t, err)
	_, _ = f.WriteString(strings.TrimSpace(exampleCred))
	defer os.Remove(f.Name())
	PDCPCredFile = f.Name()
	PDCPDir = filepath.Dir(f.Name())
	h := &PDCPCredHandler{}
	value, err := h.GetCreds()
	require.Nil(t, err)
	require.NotNil(t, value)
	require.Equal(t, "test", value.Username)
	require.Equal(t, "testpassword", value.APIKey)
	require.Equal(t, "https://scanme.sh", value.Server)
}
