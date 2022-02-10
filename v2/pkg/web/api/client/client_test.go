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
	setup := NewMockHttpServer(t)
	defer setup()

	client := New(WithBasicAuth("user", "pass"))
	client.Templates.GetTemplates(GetTemplatesRequest{
		Search: "jira",
	})
}
