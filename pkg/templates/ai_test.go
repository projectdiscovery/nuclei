package templates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/ai"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

const testPrompt = "flag responses that are a working admin login form"

func seededTemplate(t *testing.T, enabled bool) (*Template, *protocols.ExecutorOptions) {
	t.Helper()

	request := &ai.Request{Prompt: testPrompt}
	cacheDir := t.TempDir()

	fragment := `http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
`
	const model = "gpt-4o"
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, request.CacheKey(model)+".yaml"), []byte(fragment), 0600))

	template := &Template{ID: "exposed-admin-panel", RequestsAI: []*ai.Request{request}}
	options := &protocols.ExecutorOptions{
		Options: &types.Options{EnableAITemplates: enabled, AICacheDirectory: cacheDir, AIModel: model},
	}

	return template, options
}

func TestExpandAIRequestsProducesHTTPRequests(t *testing.T) {
	template, options := seededTemplate(t, true)

	require.NoError(t, template.expandAIRequests(options))
	require.Len(t, template.RequestsHTTP, 1)
	require.Equal(t, templateTypes.HTTPProtocol, template.Type())
	require.Equal(t, 1, template.Requests(), "expanded prompts must not be counted twice")
}

func TestExpandAIRequestsIsIdempotent(t *testing.T) {
	template, options := seededTemplate(t, true)

	require.NoError(t, template.expandAIRequests(options))
	require.NoError(t, template.expandAIRequests(options))
	require.Len(t, template.RequestsHTTP, 1)
}

func TestExpandAIRequestsSkippedWhenCapabilityDisabled(t *testing.T) {
	template, options := seededTemplate(t, false)

	require.NoError(t, template.expandAIRequests(options))
	require.Empty(t, template.RequestsHTTP, "prompts must not be expanded without -enable-ai-templates")
	require.Equal(t, 1, template.Requests(), "unexpanded prompts still count so the capability check reports them")

	missing := template.MissingLoadCapabilities(CapabilitiesFromOptions(options.Options))
	require.Contains(t, missing, CapabilityAI)
}
