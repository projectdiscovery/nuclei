package flow_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

var errRefused = errors.New("connection refused")

const skippedFlowTemplate = `id: flow-skipped

info:
  name: flow skipped
  author: test
  severity: info

flow: http(1) && http(2)

http:
  - method: GET
    path:
      - "http://127.0.0.1:1/a"
    matchers:
      - type: status
        status:
          - 200
  - method: GET
    path:
      - "http://127.0.0.1:1/b"
    matchers:
      - type: status
        status:
          - 200
`

// A flow whose request is skipped for an unresponsive address reports the skip
// in its failure event and returns no error, which the engine would warn
// about (#8196).
//
//nolint:paralleltest // setup() fills a package-level executerOpts
func TestFlowReportsUnresponsiveSkip(t *testing.T) {
	setup()

	cache := hosterrorscache.New(1, hosterrorscache.DefaultMaxHostsCount, nil)
	t.Cleanup(cache.Close)
	cache.MarkFailedOrRemove("http", contextargs.NewWithInput(context.Background(), "http://127.0.0.1:1"), errRefused)
	require.True(t, cache.Check("http", contextargs.NewWithInput(context.Background(), "http://127.0.0.1:1")))

	options := testutils.DefaultOptions.Copy()
	options.MatcherStatus = true
	executerOpts.Options = options
	executerOpts.HostErrorsCache = cache
	mock, ok := executerOpts.Output.(*testutils.MockOutputWriter)
	require.True(t, ok)

	var failures []string

	mock.WriteCallback = func(event *output.ResultEvent) {
		failures = append(failures, event.Error)
	}

	path := filepath.Join(t.TempDir(), "flow-skipped.yaml")
	require.NoError(t, os.WriteFile(path, []byte(skippedFlowTemplate), 0o600))
	template, err := templates.Parse(path, nil, executerOpts)
	require.NoError(t, err)
	require.NoError(t, template.Executer.Compile())

	input := contextargs.NewWithInput(context.Background(), "http://127.0.0.1:18081")
	_, err = template.Executer.Execute(scan.NewScanContext(context.Background(), input))

	require.NoError(t, err)
	require.Equal(t, []string{"host was skipped as it was found unresponsive"}, failures)
}

// allRequestsFlowTemplate runs both its requests in turn; the second goes to
// the address formatted into it.
const allRequestsFlowTemplate = `id: flow-all-requests

info:
  name: flow all requests
  author: test
  severity: info

flow: http()

http:
  - method: GET
    path:
      - "http://127.0.0.1:1/a"
    matchers:
      - type: status
        status:
          - 200
  - method: GET
    path:
      - "%s/b"
    matchers:
      - type: status
        status:
          - 200
`

// A flow that runs all its http requests in turn still sends the ones after a
// request skipped for an unresponsive address, as they may go elsewhere.
//
//nolint:paralleltest // setup() fills a package-level executerOpts
func TestFlowSendsRequestsAfterUnresponsiveSkip(t *testing.T) {
	setup()

	var hits atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(server.Close)

	cache := hosterrorscache.New(1, hosterrorscache.DefaultMaxHostsCount, nil)
	t.Cleanup(cache.Close)
	cache.MarkFailedOrRemove("http", contextargs.NewWithInput(t.Context(), "http://127.0.0.1:1"), errRefused)

	executerOpts.Options = testutils.DefaultOptions.Copy()
	executerOpts.HostErrorsCache = cache

	path := filepath.Join(t.TempDir(), "flow-all-requests.yaml")
	require.NoError(t, os.WriteFile(path, fmt.Appendf(nil, allRequestsFlowTemplate, server.URL), 0o600))
	template, err := templates.Parse(path, nil, executerOpts)
	require.NoError(t, err)
	require.NoError(t, template.Executer.Compile())

	input := contextargs.NewWithInput(t.Context(), server.URL)
	_, err = template.Executer.Execute(scan.NewScanContext(t.Context(), input))

	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load(), "the request after the skipped one must be sent")
}
