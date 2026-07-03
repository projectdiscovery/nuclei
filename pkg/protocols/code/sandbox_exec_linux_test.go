//go:build linux

package code

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestCodeProtocolBubblewrapExecution(t *testing.T) {
	if !bubblewrapFunctional(context.Background()) {
		t.Skip("bubblewrap is installed but cannot create sandboxes in this environment")
	}

	options := testutils.DefaultOptions.Copy()
	options.DisableSandbox = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	info := &testutils.TemplateInfo{
		ID:   "code-bwrap-test",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	}
	request := &Request{
		Engine: []string{"sh"},
		Source: "echo bubblewrap-ok",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, info)
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), "")
	require.NoError(t, request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	}))
	require.Equal(t, "bubblewrap-ok", gotEvent["response"])
}

func TestCodeProtocolBubblewrapDeniesHostFileRead(t *testing.T) {
	if !bubblewrapFunctional(context.Background()) {
		t.Skip("bubblewrap is installed but cannot create sandboxes in this environment")
	}

	options := testutils.DefaultOptions.Copy()
	options.DisableSandbox = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	info := &testutils.TemplateInfo{
		ID:   "code-bwrap-deny",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	}
	request := &Request{
		Engine: []string{"sh"},
		Source: "cat /etc/passwd",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, info)
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), "")
	require.NoError(t, request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	}))

	response, _ := gotEvent["response"].(string)
	stderr, _ := gotEvent["stderr"].(string)
	require.NotContains(t, response+stderr, "root:")
}

func TestCodeProtocolDisableSandboxFallsBackToBareEval(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.DisableSandbox = true
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	info := &testutils.TemplateInfo{
		ID:   "code-no-sandbox",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	}
	request := &Request{
		Engine: []string{"sh"},
		Source: "echo bare-eval",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, info)
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), "")
	require.NoError(t, request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	}))
	require.Equal(t, "bare-eval", gotEvent["response"])
}
