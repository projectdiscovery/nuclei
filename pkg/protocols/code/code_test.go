//go:build linux || darwin

package code

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
)

func newTestRequest(t *testing.T, engine []string, source string) (*Request, *testutils.TemplateInfo) {
	t.Helper()
	info := &testutils.TemplateInfo{
		ID:   "testing-code",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	}
	return &Request{Engine: engine, Source: source}, info
}

func executeRequest(t *testing.T, request *Request, info *testutils.TemplateInfo) (output.InternalEvent, error) {
	t.Helper()
	return executeRequestWithOptions(t, request, info, nil)
}

func executeRequestWithOptions(t *testing.T, request *Request, info *testutils.TemplateInfo, configure func(*types.Options)) (output.InternalEvent, error) {
	t.Helper()
	// copy the shared defaults before mutating so this flag does not leak into
	// other tests and make them order-dependent.
	options := testutils.DefaultOptions.Copy()
	options.EnableCodeTemplates = true
	if configure != nil {
		configure(options)
	}
	testutils.Init(options)

	executerOpts := testutils.NewMockExecuterOptions(options, info)
	executerOpts.Verified = true
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile code request")

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), "")
	execErr := request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	return gotEvent, execErr
}

func TestCodeProtocol(t *testing.T) {
	request, info := newTestRequest(t, []string{"sh"}, "echo test")
	gotEvent, err := executeRequest(t, request, info)
	require.Nil(t, err, "could not run code request")
	require.NotEmpty(t, gotEvent, "could not get event items")
}

func TestCodeProtocolInheritsProxy(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*types.Options)
		want      string
	}{
		{
			name: "http proxy",
			configure: func(o *types.Options) {
				o.AliveHttpProxy = "http://user:pass@127.0.0.1:8080"
			},
			want: "http://user:pass@127.0.0.1:8080|http://user:pass@127.0.0.1:8080|http://user:pass@127.0.0.1:8080",
		},
		{
			name: "socks5 proxy",
			configure: func(o *types.Options) {
				o.AliveSocksProxy = "socks5://127.0.0.1:1080"
			},
			want: "socks5://127.0.0.1:1080|socks5://127.0.0.1:1080|socks5://127.0.0.1:1080",
		},
		{
			name: "no proxy",
			want: "||",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range proxyEnvNames {
				t.Setenv(name, "")
			}
			request, info := newTestRequest(t, []string{"sh"}, `echo "$HTTP_PROXY|$https_proxy|$ALL_PROXY"`)
			gotEvent, err := executeRequestWithOptions(t, request, info, tc.configure)
			require.NoError(t, err)
			require.Equal(t, tc.want, gotEvent["response"])
			for _, name := range proxyEnvNames {
				require.NotContains(t, gotEvent, name, "proxy env must not leak into the result event")
			}
		})
	}
}

func TestCodeProtocolProxyOverridesTemplateVariable(t *testing.T) {
	const proxy = "http://user:pass@127.0.0.1:8080"
	const fromTemplate = "http://template.invalid:1"

	for _, name := range proxyEnvNames {
		t.Setenv(name, "inherited.invalid")
	}

	options := testutils.DefaultOptions.Copy()
	options.EnableCodeTemplates = true
	options.AliveHttpProxy = proxy
	testutils.Init(options)

	request, info := newTestRequest(t, []string{"sh"}, `echo "$HTTP_PROXY"`)
	executerOpts := testutils.NewMockExecuterOptions(options, info)
	executerOpts.Verified = true
	executerOpts.Variables = variables.Variable{
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	executerOpts.Variables.Set("HTTP_PROXY", fromTemplate)
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), "")
	err := request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	require.NoError(t, err)

	// -proxy wins over the inherited environment and the template variable
	require.Equal(t, proxy, strings.TrimSpace(gotEvent["response"].(string)))
	// the template variable stays visible to the template, the proxy value does not
	require.Equal(t, fromTemplate, gotEvent["HTTP_PROXY"])
	require.NotContains(t, gotEvent, "https_proxy")
}

func TestCodeProtocolSuccessResponse(t *testing.T) {
	request, info := newTestRequest(t, []string{"sh"}, "echo hello-world")
	gotEvent, err := executeRequest(t, request, info)
	require.Nil(t, err)
	require.Equal(t, "hello-world", gotEvent["response"])
	_, hasStderr := gotEvent["stderr"]
	require.False(t, hasStderr, "stderr should not be present on success")
}

func TestCodeProtocolStderrCapture(t *testing.T) {
	request, info := newTestRequest(t, []string{"sh"}, "echo error-output >&2")
	gotEvent, err := executeRequest(t, request, info)
	require.Nil(t, err)
	require.Contains(t, gotEvent["stderr"], "error-output")
}

func TestCodeProtocolFailingScript(t *testing.T) {
	request, info := newTestRequest(t, []string{"sh"}, "echo fail-message >&2; exit 1")
	gotEvent, err := executeRequest(t, request, info)
	require.Nil(t, err, "ExecuteWithResults should not return an error for non-zero exit codes")
	require.NotEmpty(t, gotEvent, "event should still be generated on script failure")
	require.Contains(t, gotEvent["stderr"], "fail-message")
	require.Empty(t, gotEvent["response"], "stdout should be empty when script only writes to stderr")
}

func TestCodeProtocolMixedOutput(t *testing.T) {
	request, info := newTestRequest(t, []string{"sh"}, "echo stdout-data; echo stderr-data >&2")
	gotEvent, err := executeRequest(t, request, info)
	require.Nil(t, err)
	require.Equal(t, "stdout-data", gotEvent["response"])
	require.Contains(t, gotEvent["stderr"], "stderr-data")
}

func TestCodeProtocolDoesNotTrackOptionOverriddenInteractshVariable(t *testing.T) {
	gotEvent := executeCodeProtocolWithCallbackOverride(t, func(options *types.Options, _ *protocols.ExecutorOptions) {
		require.NoError(t, options.Vars.Set("callback=option-callback"))
	})

	require.Equal(t, "option-callback", gotEvent["callback"])
	require.Equal(t, "option-callback", gotEvent["response"])
	require.NotContains(t, gotEvent, "interactsh-url")
	require.NotContains(t, gotEvent, "interactsh-id")
}

func TestCodeProtocolDoesNotTrackConstantOverriddenInteractshVariable(t *testing.T) {
	gotEvent := executeCodeProtocolWithCallbackOverride(t, func(_ *types.Options, executerOpts *protocols.ExecutorOptions) {
		executerOpts.Constants = map[string]interface{}{
			"callback": "constant-callback",
		}
	})

	require.Equal(t, "constant-callback", gotEvent["callback"])
	require.Equal(t, "constant-callback", gotEvent["response"])
	require.NotContains(t, gotEvent, "interactsh-url")
	require.NotContains(t, gotEvent, "interactsh-id")
}

func executeCodeProtocolWithCallbackOverride(t *testing.T, configure func(*types.Options, *protocols.ExecutorOptions)) output.InternalEvent {
	t.Helper()

	options := testutils.DefaultOptions.Copy()
	// code templates are gated behind -code and signature verification, so
	// enable both for this helper the same way executeRequest does.
	options.EnableCodeTemplates = true
	options.InteractionsCoolDownPeriod = 0
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	request, info := newTestRequest(t, []string{"sh"}, "echo $callback")
	executerOpts := testutils.NewMockExecuterOptions(options, info)
	executerOpts.Verified = true
	configure(options, executerOpts)
	executerOpts.Variables = variables.Variable{
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1),
	}
	executerOpts.Variables.Set("callback", "{{interactsh-url}}")

	serverURL, httpClient := testutils.NewInteractshServer(t)
	client, err := interactsh.New(&interactsh.Options{
		ServerURL:           serverURL,
		HTTPClient:          httpClient,
		CacheSize:           options.InteractionsCacheSize,
		Eviction:            time.Duration(options.InteractionsEviction) * time.Second,
		CooldownPeriod:      time.Duration(options.InteractionsCoolDownPeriod) * time.Second,
		PollDuration:        time.Duration(options.InteractionsPollDuration) * time.Second,
		DisableHttpFallback: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
	})
	executerOpts.Interactsh = client

	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), "")
	err = request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	require.NoError(t, err)

	return gotEvent
}
