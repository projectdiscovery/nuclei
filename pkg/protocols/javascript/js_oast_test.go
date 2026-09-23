package javascript

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/render"
)

func TestGeneratorPayloadInteractshMarkerRendersBeforeArgs(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.InteractionsCoolDownPeriod = 0
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	request := &Request{
		Args: map[string]interface{}{
			"cb": "{{payload}}",
		},
		Payloads: map[string]interface{}{
			"payload": []string{"{{interactsh-url}}"},
		},
		Code: `module.exports = { success: true }`,
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: "javascript-payload-interactsh",
	})
	client, err := interactsh.New(&interactsh.Options{
		ServerURL:           options.InteractshURL,
		CacheSize:           options.InteractionsCacheSize,
		Eviction:            time.Duration(options.InteractionsEviction) * time.Second,
		CooldownPeriod:      time.Duration(options.InteractionsCoolDownPeriod) * time.Second,
		PollDuration:        time.Duration(options.InteractionsPollDuration) * time.Second,
		DisableHttpFallback: true,
	})
	require.NoError(t, err, "could not create interactsh client")
	t.Cleanup(func() {
		client.Close()
	})
	executerOpts.Interactsh = client

	require.NoError(t, request.Compile(executerOpts))

	payloadValue, ok := request.generator.NewIterator().Value()
	require.True(t, ok, "could not get generated payload value")

	payloadValues := generators.BuildPayloadFromOptions(options)
	renderedPayload, err := render.RenderMap(render.MapInput{
		Source:     payloadValue,
		Data:       payloadValues,
		Values:     generators.MergeMaps(payloadValue, payloadValues),
		Interactsh: request.options.Interactsh,
	})
	require.NoError(t, err, "could not render generated payload")
	require.Len(t, renderedPayload.InteractURLs, 1, "payload marker should allocate one interactsh URL")

	args, argURLs, err := request.evaluateArgs(renderedPayload.Values, executerOpts, false)
	require.NoError(t, err, "could not evaluate javascript args")
	require.Empty(t, argURLs, "already-rendered payload value should not allocate again from args")
	require.Equal(t, renderedPayload.InteractURLs[0], args["cb"])
	require.NotContains(t, args["cb"], "{{interactsh-url}}")
}
