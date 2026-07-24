package offlinehttp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	urlutil "github.com/projectdiscovery/utils/url"
)

func TestExecuteWithResultsUsesReqRespResponse(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &Request{}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "offline-export",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
	})
	ops := &operators.Operators{
		Matchers: []*matchers.Matcher{{
			Part:  "body",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{`"id":"1"`},
		}},
	}
	require.NoError(t, ops.Compile())
	executerOpts.Operators = []*operators.Operators{ops}
	require.NoError(t, request.Compile(executerOpts))

	parsedURL, err := urlutil.ParseAbsoluteURL("http://localhost:8087/scans", false)
	require.NoError(t, err)

	rawResponse := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"id\":\"1\"}\n"
	input := contextargs.New(t.Context())
	input.MetaInput.Input = parsedURL.String()
	input.MetaInput.ReqResp = &types.RequestResponse{
		URL: *parsedURL,
		Response: &types.HttpResponse{
			Raw: rawResponse,
		},
	}

	var gotEvent *output.InternalWrappedEvent
	err = request.ExecuteWithResults(input, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event
	})
	require.NoError(t, err)
	require.NotNil(t, gotEvent)
	require.True(t, gotEvent.HasOperatorResult())
	require.True(t, gotEvent.OperatorsResult.Matched)
}

func TestExecuteWithResultsSkipsWhenNoResponseOnReqResp(t *testing.T) {
	options := testutils.DefaultOptions
	options.BulkSize = 1
	testutils.Init(options)

	request := &Request{}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "offline-export-empty",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
	})
	executerOpts.Operators = []*operators.Operators{{}}
	require.NoError(t, request.Compile(executerOpts))

	parsedURL, err := urlutil.ParseAbsoluteURL("http://example.com/", false)
	require.NoError(t, err)

	input := contextargs.New(t.Context())
	// URL-shaped input would fail filepath walk; without Response we fall through.
	input.MetaInput.Input = parsedURL.String()
	input.MetaInput.ReqResp = &types.RequestResponse{URL: *parsedURL}

	err = request.ExecuteWithResults(input, nil, nil, func(event *output.InternalWrappedEvent) {
		t.Fatalf("unexpected event: %#v", event)
	})
	// getInputPaths on a URL yields no files; should not panic and should return nil.
	require.NoError(t, err)
}
