package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/catchall"
)

const appShell = `<!doctype html><html><head><title>Acme</title></head><body><div id="root"></div></body></html>`

// singlePageApp serves its shell for every path except the files it really
// has, and counts the requests it receives.
func singlePageApp(t *testing.T, files map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if body, ok := files[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(appShell))
	}))
	t.Cleanup(ts.Close)
	return ts, &requests
}

// matchesEnv runs a loose .env template, the kind that fires on any HTML page,
// and reports whether it produced a result.
func matchesEnv(t *testing.T, target string, detector *catchall.Detector, tags string, word string) bool {
	t.Helper()
	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "loose-env",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.High}, Name: "loose-env", Tags: stringslice.StringSlice{Value: []string{tags}}},
	})
	executerOpts.CatchAll = detector
	request := &Request{
		Path:   []string{"{{BaseURL}}/.env"},
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
		Operators: operators.Operators{Matchers: []*matchers.Matcher{
			{Type: matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher}, Status: []int{http.StatusOK}},
			{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Words: []string{word}},
		}, MatchersCondition: "and"},
	}
	require.NoError(t, request.Compile(executerOpts))

	var matched bool
	err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), target), output.InternalEvent{}, output.InternalEvent{}, func(event *output.InternalWrappedEvent) {
		matched = matched || event.HasResults()
	})
	require.NoError(t, err)
	return matched
}

func TestCatchAllPageMatchIsDropped(t *testing.T) {
	ts, _ := singlePageApp(t, nil)

	require.True(t, matchesEnv(t, ts.URL, nil, "exposure", "<html"), "without calibration the app shell passes for .env")
	require.False(t, matchesEnv(t, ts.URL, catchall.New(0), "exposure", "<html"))
}

func TestRealFileOnCatchAllHostIsKept(t *testing.T) {
	ts, _ := singlePageApp(t, map[string]string{"/.env": "DB_HOST=db\nDB_PASSWORD=hunter2\n"})

	require.True(t, matchesEnv(t, ts.URL, catchall.New(0), "exposure", "DB_PASSWORD"))
}

func TestHostWideTemplateKeepsCatchAllMatch(t *testing.T) {
	ts, _ := singlePageApp(t, nil)

	require.True(t, matchesEnv(t, ts.URL, catchall.New(0), "tech", `<title>Acme</title>`), "the app is still Acme on its catch-all page")
}

func TestNoMatchSendsNoProbes(t *testing.T) {
	ts, requests := singlePageApp(t, nil)

	require.False(t, matchesEnv(t, ts.URL, catchall.New(0), "exposure", "DB_PASSWORD"))
	require.EqualValues(t, 1, requests.Load(), "calibration only probes a host once a template matched")
}
