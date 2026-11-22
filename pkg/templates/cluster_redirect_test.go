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

// A cluster sends its first member's request for every member, so a template
// with host-redirects must not share a cluster with one that does not follow
// redirects: its matchers would run on the redirect instead of the page.
func TestClusterTemplatesKeepHostRedirectsApart(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			_, _ = io.WriteString(w, "<title>Login Panel</title>")
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	t.Cleanup(ts.Close)

	matched := make(map[string]bool)
	writer := testutils.NewMockOutputWriter(options.OmitTemplate)
	writer.WriteCallback = func(event *output.ResultEvent) {
		matched[event.TemplateID] = true
	}

	info := model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "cluster"}
	newTemplate := func(id string, request *httpprotocol.Request) *Template {
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

	// The plain template comes first, so a shared cluster would send its
	// request, which does not follow the redirect.
	plainTemplate := newTemplate("plain-template", &httpprotocol.Request{
		Method: httpprotocol.HTTPMethodTypeHolder{MethodType: httpprotocol.HTTPGet},
		Path:   []string{"{{BaseURL}}"},
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{
			Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
			Status: []int{http.StatusFound},
		}}},
	})
	hostRedirectsTemplate := newTemplate("host-redirects-template", &httpprotocol.Request{
		Method:        httpprotocol.HTTPMethodTypeHolder{MethodType: httpprotocol.HTTPGet},
		Path:          []string{"{{BaseURL}}"},
		HostRedirects: true,
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{
			Part:  "body",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"<title>Login Panel</title>"},
		}}},
	})

	final, count, _ := ClusterTemplates([]*Template{plainTemplate, hostRedirectsTemplate}, plainTemplate.Options)

	for _, tmpl := range final {
		input := contextargs.NewWithInput(context.Background(), ts.URL)
		_, err := tmpl.Executer.Execute(scan.NewScanContext(context.Background(), input))
		require.NoError(t, err)
	}

	require.True(t, matched["plain-template"], "plain template should see the redirect")
	require.True(t, matched["host-redirects-template"], "host-redirects template should follow the same host redirect")
	require.Zero(t, count, "templates with different host-redirects must not be clustered")
	require.Len(t, final, 2)
}
