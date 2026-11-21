package offlinehttp //nolint:testpackage // it builds the unexported Request

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// With -bs below 1 the file pool must still be built, so the request runs one
// response at a time.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestExecuteWithResultsBulkSizeBelowOne(t *testing.T) {
	for _, bulkSize := range []int{0, -1} {
		t.Run(strconv.Itoa(bulkSize), func(t *testing.T) {
			options := testutils.DefaultOptions.Copy()
			options.BulkSize = bulkSize
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })

			executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
				ID:   "offline-bulk",
				Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "offline-bulk"},
			})
			ops := &operators.Operators{
				Matchers: []*matchers.Matcher{{
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"hello"},
				}},
			}
			require.NoError(t, ops.Compile())
			executerOpts.Operators = []*operators.Operators{ops}

			request := &Request{}
			require.NoError(t, request.Compile(executerOpts))

			path := filepath.Join(t.TempDir(), "response.txt")
			response := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
			require.NoError(t, os.WriteFile(path, []byte(response), 0o600))

			var matched int

			input := contextargs.NewWithInput(t.Context(), path)
			err := request.ExecuteWithResults(input, nil, nil, func(event *output.InternalWrappedEvent) {
				matched += len(event.Results)
			})
			require.NoError(t, err)
			require.Equal(t, 1, matched)
		})
	}
}
