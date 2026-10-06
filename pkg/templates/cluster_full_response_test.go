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

func TestClusterTemplatesMarksSiblingResponse(t *testing.T) {
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

	bodyRequest := &httpprotocol.Request{
		Method: httpprotocol.HTTPMethodTypeHolder{MethodType: httpprotocol.HTTPGet},
		Path:   []string{"{{BaseURL}}"},
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{
			Part:  "body",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"hello-body"},
		}}},
	}
	responseRequest := &httpprotocol.Request{
		Method: httpprotocol.HTTPMethodTypeHolder{MethodType: httpprotocol.HTTPGet},
		Path:   []string{"{{BaseURL}}"},
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{
			Part:  "response",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"hello-body"},
		}}},
	}
	require.NoError(t, bodyRequest.Compile(executerOpts))
	require.NoError(t, responseRequest.Compile(executerOpts))
	require.False(t, bodyRequest.FullResponseRequired())

	info := model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "cluster"}
	bodyTemplate := &Template{ID: "body-template", Info: info, RequestsHTTP: []*httpprotocol.Request{bodyRequest}}
	responseTemplate := &Template{ID: "response-template", Info: info, RequestsHTTP: []*httpprotocol.Request{responseRequest}}
	bodyTemplate.Options = executerOpts
	responseTemplate.Options = executerOpts

	var written []*output.ResultEvent
	executerOpts.Output.(*testutils.MockOutputWriter).WriteCallback = func(event *output.ResultEvent) {
		written = append(written, event)
	}

	// ClusterTemplates is what a scan calls after compilation. It must mark the
	// shared request without a later Compile on the cluster.
	final, count, _ := ClusterTemplates([]*Template{bodyTemplate, responseTemplate}, executerOpts)
	require.Equal(t, 2, count)
	require.Len(t, final, 1)
	require.True(t, bodyRequest.FullResponseRequired())

	input := contextargs.NewWithInput(context.Background(), ts.URL)
	matched, err := final[0].Executer.Execute(scan.NewScanContext(context.Background(), input))
	require.NoError(t, err)
	require.True(t, matched)

	var sibling *output.ResultEvent
	for _, event := range written {
		if event.TemplateID == "response-template" {
			sibling = event
		}
	}
	require.NotNil(t, sibling)
	require.Contains(t, sibling.Response, "hello-body")
	require.Contains(t, sibling.Response, "HTTP/1.1")
	require.Contains(t, sibling.Response, "header-marker")
}
