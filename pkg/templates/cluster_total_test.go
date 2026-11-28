package templates_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

const clusterTotalName = "cluster"

// A cluster runs the request of its first template, so its total is that
// request's, not one per member: a request with several paths sends each.
// A block that sends race copies doesn't cluster (#8280), so none is here.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestClusterTotalIsTheRequestsTotal(t *testing.T) {
	tests := []struct {
		name    string
		request func() *httpprotocol.Request
		total   int
	}{
		{
			name: "one path",
			request: func() *httpprotocol.Request {
				return &httpprotocol.Request{Path: []string{"{{BaseURL}}/a"}}
			},
			total: 1,
		},
		{
			name: "two paths",
			request: func() *httpprotocol.Request {
				return &httpprotocol.Request{Path: []string{"{{BaseURL}}/a", "{{BaseURL}}/b"}}
			},
			total: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := testutils.DefaultOptions.Copy()
			testutils.Init(options)

			executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
				ID:   "cluster-total",
				Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: clusterTotalName},
			})
			t.Cleanup(executerOpts.RateLimiter.Stop)

			members := make([]*templates.Template, 0, 2)

			for _, id := range []string{"first", "second"} {
				request := test.request()
				request.Method = httpprotocol.HTTPMethodTypeHolder{MethodType: httpprotocol.HTTPGet}
				require.NoError(t, request.Compile(executerOpts))

				member := &templates.Template{ID: id, RequestsHTTP: []*httpprotocol.Request{request}}
				member.Options = executerOpts
				members = append(members, member)
			}

			final, count, _ := templates.ClusterTemplates(members, executerOpts)

			require.Equal(t, 2, count, "templates clustered")
			require.Len(t, final, 1)
			require.Equal(t, test.total, final[0].TotalRequests)
			require.Equal(t, test.total, final[0].Executer.Requests())
		})
	}
}
