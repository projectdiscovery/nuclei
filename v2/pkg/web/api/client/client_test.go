package client

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	client := New(WithBasicAuth("user", "pass"))
	require.NotNil(t, client)
}
func TestClient(t *testing.T) {
	client := New(WithBasicAuth("user", "pass"))
	result, err := client.Templates.GetTemplates(GetTemplatesRequest{
		Search: "jira",
	})
	require.NoError(t, err, "could not get templates")
	require.Greater(t, len(result), 0)
}
