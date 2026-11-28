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
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec"
)

// A workflow step drives subtemplates through ctx.OnResult: it sets the
// callback on the ScanContext it hands to ExecuteWithResults and relies on the
// callback firing to mark the step matched and to launch subtemplates. A
// clustered step must honour that callback exactly like a single template does,
// otherwise its subtemplates silently never run.
func TestClusterExecuterExecuteWithResultsFiresOnResult(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "MATCH-ME body")
	}))
	t.Cleanup(ts.Close)

	writer := testutils.NewMockOutputWriter(options.OmitTemplate)
	writer.WriteCallback = func(event *output.ResultEvent) {}

	info := model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "cluster"}
	newTemplate := func(id string) *Template {
		request := &httpprotocol.Request{
			Method: httpprotocol.HTTPMethodTypeHolder{MethodType: httpprotocol.HTTPGet},
			Path:   []string{"{{BaseURL}}"},
			Operators: operators.Operators{Matchers: []*matchers.Matcher{{
				Part:  "body",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"MATCH-ME"},
			}}},
		}
		executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: id, Info: info})
		executerOpts.Output = writer
		require.NoError(t, request.Compile(executerOpts))

		executer, err := tmplexec.NewTemplateExecuter([]protocols.Request{request}, executerOpts)
		require.NoError(t, err)
		require.NoError(t, executer.Compile())

		tmpl := &Template{ID: id, Info: info, RequestsHTTP: []*httpprotocol.Request{request}, Executer: executer}
		tmpl.Options = executerOpts
		return tmpl
	}

	first := newTemplate("first-template")
	second := newTemplate("second-template")

	final, count, _ := ClusterTemplates([]*Template{first, second}, first.Options)
	require.Equal(t, 2, count, "the two identical templates should cluster")
	require.Len(t, final, 1)

	input := contextargs.NewWithInput(context.Background(), ts.URL)
	ctx := scan.NewScanContext(context.Background(), input)

	// This is how a workflow step collects matches and decides to run
	// subtemplates: through the callback on the context it passes in.
	onResultIDs := make(map[string]bool)
	ctx.OnResult = func(event *output.InternalWrappedEvent) {
		if event.OperatorsResult == nil {
			return
		}
		onResultIDs[event.InternalEvent["template-id"].(string)] = true
	}

	results, err := final[0].Executer.ExecuteWithResults(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, results, "the clustered templates should match")

	require.True(t, onResultIDs["first-template"], "OnResult must fire for the first clustered template")
	require.True(t, onResultIDs["second-template"], "OnResult must fire for the second clustered template")
}
