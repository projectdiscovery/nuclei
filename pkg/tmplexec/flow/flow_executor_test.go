package flow_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

var executerOpts *protocols.ExecutorOptions

func setup() {
	options := testutils.DefaultOptions
	testutils.Init(options)
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)

	executerOpts = &protocols.ExecutorOptions{
		Output:       testutils.NewMockOutputWriter(options.OmitTemplate),
		Options:      options,
		Progress:     progressImpl,
		ProjectFile:  nil,
		IssuesClient: nil,
		Browser:      nil,
		Catalog:      disk.NewCatalog(config.DefaultConfig.TemplatesDirectory),
		RateLimiter:  ratelimit.New(context.Background(), uint(options.RateLimit), time.Second),
		Parser:       templates.NewParser(),
	}
	workflowLoader, err := workflow.NewLoader(executerOpts)
	if err != nil {
		log.Fatalf("Could not create workflow loader: %s\n", err)
	}
	executerOpts.WorkflowLoader = workflowLoader
}

func TestFlowTemplateWithIndex(t *testing.T) {
	// test
	setup()
	Template, err := templates.Parse("testcases/nuclei-flow-dns.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifier if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "hackerone.com")
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestFlowTemplateWithID(t *testing.T) {
	setup()
	// apart from parse->compile->execution this testcase checks support for use custom id for protocol request and invocation of
	// the same in js
	Template, err := templates.Parse("testcases/nuclei-flow-dns-id.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifier if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	target := contextargs.NewWithInput(context.Background(), "hackerone.com")
	ctx := scan.NewScanContext(context.Background(), target)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestFlowWithProtoPrefix(t *testing.T) {
	// test
	setup()

	// apart from parse->compile->execution this testcase checks
	// mix of custom protocol request id and index is supported in js
	// and also validates availability of protocol response variables in template context
	Template, err := templates.Parse("testcases/nuclei-flow-dns-prefix.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifier if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "hackerone.com")
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestFlowWithConditionNegative(t *testing.T) {
	setup()

	// apart from parse->compile->execution this testcase checks
	// if bitwise operator (&&) are properly executed and working
	Template, err := templates.Parse("testcases/condition-flow.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifier if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "scanme.sh")
	ctx := scan.NewScanContext(context.Background(), input)
	// expect no results and verify that dns request is executed and http is not
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.False(t, gotresults)
}

func TestFlowWithConditionPositive(t *testing.T) {
	setup()

	// apart from parse->compile->execution this testcase checks
	// if bitwise operator (&&) are properly executed and working
	Template, err := templates.Parse("testcases/condition-flow.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifier if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "cloud.projectdiscovery.io")
	ctx := scan.NewScanContext(context.Background(), input)
	// positive match . expect results also verify that both dns() and http() were executed
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestFlowWithNoMatchers(t *testing.T) {
	setup()
	// when using conditional flow with no matchers at all
	// we implicitly assume that request was successful and internally changed the result to true (for scope of condition only)

	Template, err := templates.Parse("testcases/condition-flow-no-operators.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifier if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	anotherInput := contextargs.NewWithInput(context.Background(), "cloud.projectdiscovery.io")
	anotherCtx := scan.NewScanContext(context.Background(), anotherInput)
	// positive match . expect results also verify that both dns() and http() were executed
	gotresults, err := Template.Executer.Execute(anotherCtx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)

	t.Run("Contains Extractor", func(t *testing.T) {
		Template, err := templates.Parse("testcases/condition-flow-extractors.yaml", nil, executerOpts)
		require.Nil(t, err, "could not parse template")

		require.True(t, Template.Flow != "", "not a flow template") // this is classifier if template is flow or not

		err = Template.Executer.Compile()
		require.Nil(t, err, "could not compile template")

		input := contextargs.NewWithInput(context.Background(), "scanme.sh")
		ctx := scan.NewScanContext(context.Background(), input)
		// positive match . expect results also verify that both dns() and http() were executed
		gotresults, err := Template.Executer.Execute(ctx)
		require.Nil(t, err, "could not execute template")
		require.True(t, gotresults)
	})
}

func newThreeStepServer() *httptest.Server {
	router := httprouter.New()
	router.GET("/step1", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "step1-ok")
	})
	router.GET("/step2", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "step2-ok token=abc123secret")
	})
	router.GET("/step3", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "step3-ok")
	})
	return httptest.NewServer(router)
}

func newThreeStepServerWithPayloads() *httptest.Server {
	router := httprouter.New()
	router.GET("/step1", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "step1-ok")
	})
	router.POST("/login", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("X-Auth-Token", "tok3nvalue99")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "login-ok")
	})
	router.GET("/admin", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		if r.URL.Query().Get("token") == "tok3nvalue99" {
			_, _ = fmt.Fprint(w, "admin-ok")
		} else {
			_, _ = fmt.Fprint(w, "admin-unauthorized")
		}
	})
	return httptest.NewServer(router)
}

// TestFlowRequestCondition reproduces issue #5095:
// with flow: http() and 3 raw requests, numbered variables like
// body_1, body_2 from earlier requests should be accessible in matchers
// that run on the 3rd request's event.
func TestFlowRequestCondition(t *testing.T) {
	setup()
	ts := newThreeStepServer()
	defer ts.Close()

	t.Run("without flow (baseline)", func(t *testing.T) {
		tmpl, err := templates.Parse("testcases/noflow-request-condition.yaml", nil, executerOpts)
		require.Nil(t, err, "could not parse template")
		require.Empty(t, tmpl.Flow, "should NOT be a flow template")

		err = tmpl.Executer.Compile()
		require.Nil(t, err, "could not compile template")

		input := contextargs.NewWithInput(context.Background(), ts.URL)
		ctx := scan.NewScanContext(context.Background(), input)
		gotresults, err := tmpl.Executer.Execute(ctx)
		require.Nil(t, err, "could not execute template")
		require.True(t, gotresults, "expected match without flow")
	})

	t.Run("with flow", func(t *testing.T) {
		tmpl, err := templates.Parse("testcases/flow-request-condition.yaml", nil, executerOpts)
		require.Nil(t, err, "could not parse template")
		require.NotEmpty(t, tmpl.Flow, "should be a flow template")

		err = tmpl.Executer.Compile()
		require.Nil(t, err, "could not compile template")

		input := contextargs.NewWithInput(context.Background(), ts.URL)
		ctx := scan.NewScanContext(context.Background(), input)
		gotresults, err := tmpl.Executer.Execute(ctx)
		require.Nil(t, err, "could not execute template")
		require.True(t, gotresults, "expected match with flow (issue #5095)")
	})
}

func newMultiPayloadServer() *httptest.Server {
	router := httprouter.New()
	router.GET("/step1", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = fmt.Fprint(w, "step1-ok")
	})
	router.POST("/login", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = fmt.Fprint(w, "login-ok")
	})
	router.GET("/data", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = fmt.Fprint(w, "data-ok")
	})
	return httptest.NewServer(router)
}

// TestFlowMultiPayloadIteration tests that request condition variables
// survive across multiple pitchfork payload iterations (generator restarts).
func TestFlowMultiPayloadIteration(t *testing.T) {
	setup()
	ts := newMultiPayloadServer()
	defer ts.Close()

	tmpl, err := templates.Parse("testcases/flow-multi-payload-iteration.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	err = tmpl.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), ts.URL)
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := tmpl.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults, "expected match with flow + multi payload iteration")
}

// TestFlowRequestConditionWithPayloads is the same as above but with
// pitchfork payloads and header-based extraction, matching the exact
// pattern from issue #5095.
func TestFlowRequestConditionWithPayloads(t *testing.T) {
	setup()
	ts := newThreeStepServerWithPayloads()
	defer ts.Close()

	t.Run("without flow (baseline)", func(t *testing.T) {
		tmpl, err := templates.Parse("testcases/noflow-request-condition-payloads.yaml", nil, executerOpts)
		require.Nil(t, err, "could not parse template")

		err = tmpl.Executer.Compile()
		require.Nil(t, err, "could not compile template")

		input := contextargs.NewWithInput(context.Background(), ts.URL)
		ctx := scan.NewScanContext(context.Background(), input)
		gotresults, err := tmpl.Executer.Execute(ctx)
		require.Nil(t, err, "could not execute template")
		require.True(t, gotresults, "expected match without flow (payloads)")
	})

	t.Run("with flow", func(t *testing.T) {
		tmpl, err := templates.Parse("testcases/flow-request-condition-payloads.yaml", nil, executerOpts)
		require.Nil(t, err, "could not parse template")

		err = tmpl.Executer.Compile()
		require.Nil(t, err, "could not compile template")

		input := contextargs.NewWithInput(context.Background(), ts.URL)
		ctx := scan.NewScanContext(context.Background(), input)
		gotresults, err := tmpl.Executer.Execute(ctx)
		require.Nil(t, err, "could not execute template")
		require.True(t, gotresults, "expected match with flow + payloads (issue #5095)")
	})
}

type countingProgress struct {
	testutils.MockProgressClient
	total, requests atomic.Int64
}

func (p *countingProgress) AddToTotal(delta int64)                { p.total.Add(delta) }
func (p *countingProgress) IncrementRequests()                    { p.requests.Add(1) }
func (p *countingProgress) SetRequests(count uint64)              { p.requests.Add(int64(count)) }
func (p *countingProgress) IncrementFailedRequestsBy(count int64) { p.requests.Add(count) }

// TestFlowProgressEndsComplete checks that a flow ends with every request in
// the total processed, counting skipped requests as processed and repeated
// runs in the total, and that it sends exactly what the flow runs.
func TestFlowProgressEndsComplete(t *testing.T) {
	setup()
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer ts.Close()

	tests := []struct {
		name  string
		flow  string
		sent  int64
		total int64
	}{
		{name: "all requests", flow: "http(1); http(2); http(3);", sent: 3, total: 3},
		{name: "skipped requests", flow: "http(1);", sent: 1, total: 3},
		{name: "skipped and repeated", flow: `http(1); if (template["status_code"] == 999) { http(2); } http(3); http(3);`, sent: 3, total: 4},
		{name: "by id", flow: `http("a");`, sent: 1, total: 3},
		{name: "no arguments", flow: "http();", sent: 3, total: 3},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			p := &countingProgress{}
			opts := *executerOpts
			opts.Progress = p

			path := filepath.Join(t.TempDir(), fmt.Sprintf("flow-progress-%d.yaml", i))
			tmpl := fmt.Sprintf(`id: flow-progress-%d
info: {name: flow-progress, author: pdteam, severity: info}
flow: |
  %s
http:
  - id: a
    method: GET
    path: ["{{BaseURL}}/a"]
  - id: b
    method: GET
    path: ["{{BaseURL}}/b"]
  - id: c
    method: GET
    path: ["{{BaseURL}}/c"]
`, i, tc.flow)
			require.NoError(t, os.WriteFile(path, []byte(tmpl), 0o600))

			template, err := templates.Parse(path, nil, &opts)
			require.NoError(t, err, "could not parse template")
			require.NoError(t, template.Executer.Compile(), "could not compile template")
			p.total.Store(int64(template.Executer.Requests()))

			ctx := scan.NewScanContext(context.Background(), contextargs.NewWithInput(context.Background(), ts.URL))
			_, err = template.Executer.Execute(ctx)
			require.NoError(t, err, "could not execute template")

			require.Equal(t, tc.sent, hits.Load(), "unexpected requests sent")
			require.Equal(t, tc.total, p.total.Load(), "unexpected total")
			require.Equal(t, tc.total, p.requests.Load(), "progress should end complete")
		})
	}
}
