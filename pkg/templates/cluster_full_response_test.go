package templates

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
)

func TestClusterMarksFullResponseOnlyWhenNeeded(t *testing.T) {
	bodyOnly := &httpprotocol.Request{}
	executer := &ClusterExecuter{
		requests: bodyOnly,
		operators: []*clusteredOperator{
			{operator: &operators.Operators{Matchers: []*matchers.Matcher{{Part: "body"}}}},
			{operator: &operators.Operators{Matchers: []*matchers.Matcher{{Part: "all"}}}},
		},
	}
	executer.markClusteredResponse()
	require.False(t, bodyOnly.FullResponseRequired())

	withResponse := &httpprotocol.Request{}
	executer.requests = withResponse
	executer.operators = append(executer.operators, &clusteredOperator{
		operator: &operators.Operators{Matchers: []*matchers.Matcher{{Part: "response"}}},
	})
	executer.markClusteredResponse()
	require.True(t, withResponse.FullResponseRequired())
}

func TestClusterCompileMatchesSiblingOnFullResponse(t *testing.T) {
	options := *testutils.DefaultOptions
	options.ResponseSaveSize = 1 << 20
	testutils.Init(&options)
	executerOpts := testutils.NewMockExecuterOptions(&options, &testutils.TemplateInfo{
		ID:   "cluster-body",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "cluster"},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Marker", "header-marker")
		_, _ = io.WriteString(w, "hello-body")
	}))
	t.Cleanup(ts.Close)

	request := &httpprotocol.Request{
		Method: httpprotocol.HTTPMethodTypeHolder{MethodType: httpprotocol.HTTPGet},
		Path:   []string{"{{BaseURL}}"},
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{
			Part:  "body",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"hello-body"},
		}}},
	}
	sibling := &operators.Operators{Matchers: []*matchers.Matcher{{
		Part:  "response",
		Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
		Words: []string{"hello-body"},
	}}}
	require.NoError(t, sibling.Compile())

	var written []*output.ResultEvent
	executerOpts.Output.(*testutils.MockOutputWriter).WriteCallback = func(event *output.ResultEvent) {
		written = append(written, event)
	}
	cluster := &ClusterExecuter{
		options:  executerOpts,
		requests: request,
		operators: []*clusteredOperator{{
			templateID:   "sibling",
			templateInfo: executerOpts.TemplateInfo,
			operator:     sibling,
		}},
	}
	require.NoError(t, cluster.Compile())
	require.True(t, request.FullResponseRequired())

	input := contextargs.NewWithInput(context.Background(), ts.URL)
	matched, err := cluster.Execute(scan.NewScanContext(context.Background(), input))
	require.NoError(t, err)
	require.True(t, matched)
	require.NotEmpty(t, written)
	require.Contains(t, written[0].Response, "hello-body")
	require.Contains(t, written[0].Response, "HTTP/1.1")
	require.Contains(t, written[0].Response, "header-marker")
}
