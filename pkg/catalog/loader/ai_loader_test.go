package loader

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func newAITemplateServer(t *testing.T, templateID string, gotKey *atomic.Value) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey.Store(r.Header.Get("X-Api-Key"))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"completion":  "id: test\n",
			"template_id": templateID,
		})
	}))
	t.Cleanup(srv.Close)

	oldEndpoint, oldClient := aiTemplateGeneratorAPIEndpoint, aiTemplateHTTPClient
	t.Cleanup(func() { aiTemplateGeneratorAPIEndpoint, aiTemplateHTTPClient = oldEndpoint, oldClient })
	aiTemplateGeneratorAPIEndpoint = srv.URL
	t.Setenv("PDCP_API_KEY", "test-key")
	if templateID != "" {
		// Trust the test certificate, to check the template_id only.
		aiTemplateHTTPClient = srv.Client()
	}
}

func TestAITemplateVerifiesTLS(t *testing.T) {
	var gotKey atomic.Value
	newAITemplateServer(t, "", &gotKey)

	_, _, err := generateAITemplate("check for exposed admin panels")
	require.ErrorContains(t, err, "certificate")
	require.Nil(t, gotKey.Load(), "the API key went to an untrusted server")
}

func TestAITemplateRejectsUnsafeID(t *testing.T) {
	for _, id := range []string{"../../.config/nuclei/config", "a/b", `a\b`, "a.b", "a b"} {
		var gotKey atomic.Value
		newAITemplateServer(t, id, &gotKey)
		_, _, err := generateAITemplate("check for exposed admin panels")
		require.Error(t, err, id)
	}

	var gotKey atomic.Value
	newAITemplateServer(t, "Abc-123_x", &gotKey)
	_, templateID, err := generateAITemplate("check for exposed admin panels")
	require.NoError(t, err)
	require.Equal(t, "Abc-123_x", templateID)
}
