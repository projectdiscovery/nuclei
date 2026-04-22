//go:build linux || darwin

package code

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
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
	options := testutils.DefaultOptions
	testutils.Init(options)

	executerOpts := testutils.NewMockExecuterOptions(options, info)
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
