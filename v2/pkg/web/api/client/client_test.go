package client

import "testing"

func TestClient(t *testing.T) {
	client := New(WithBasicAuth("user", "pass"))
	client.Templates.GetTemplates(GetTemplatesRequest{
		Search: "jira",
	})
}
