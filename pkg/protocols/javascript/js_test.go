package javascript_test

import (
	"context"
	"log"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	javascript "github.com/projectdiscovery/nuclei/v3/pkg/protocols/javascript"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

var (
	testcases = []string{
		"testcases/ms-sql-detect.yaml",
		"testcases/redis-pass-brute.yaml",
		"testcases/ssh-server-fingerprint.yaml",
	}
	executerOpts *protocols.ExecutorOptions
)

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

func TestCompile(t *testing.T) {
	setup()
	for index, tpl := range testcases {
		// parse template
		template, err := templates.Parse(tpl, nil, executerOpts)
		require.Nilf(t, err, "failed to parse %v", tpl)

		// compile template
		err = template.Executer.Compile()
		require.Nilf(t, err, "failed to compile %v", tpl)

		switch index {
		case 0:
			// requests count should be 1
			require.Equal(t, 1, template.TotalRequests, "template : %v", tpl)
		case 1:
			// requests count should be 6 i.e 5 generator payloads + 1 precondition request
			require.Equal(t, 5+1, template.TotalRequests, "template : %v", tpl)
		case 2:
			// requests count should be 1
			require.Equal(t, 1, template.TotalRequests, "template : %v", tpl)
		}
	}
}

func TestExecuteWithResultsReturnsArgEvaluationErrorWithoutPanic(t *testing.T) {
	options := testutils.DefaultOptions
	tmplInfo := &testutils.TemplateInfo{ID: "execute-with-results-arg-evaluation-error"}

	testutils.Init(options)

	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	executorOptions := testutils.NewMockExecuterOptions(options, tmplInfo)
	executorOptions.JsCompiler = templates.GetJsCompiler()
	executorOptions.Verified = true

	request := &javascript.Request{
		Args: map[string]interface{}{
			"token": "{{base64()}}",
		},
		Code: `module.exports = { success: true, response: "ok" }`,
	}
	require.NoError(t, request.Compile(executorOptions))

	target := contextargs.NewWithInput(context.Background(), "https://example.com:443")

	var err error
	require.NotPanics(t, func() {
		err = request.ExecuteWithResults(target, nil, nil, func(*output.InternalWrappedEvent) {
			t.Fatal("unexpected callback on argument evaluation failure")
		})
	})
	require.ErrorContains(t, err, `failed to evaluate expression "base64()"`)
}

func TestExecuteWithResultsRejectsUnverifiedTemplate(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	executorOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "unverified-javascript"})
	executorOptions.JsCompiler = templates.GetJsCompiler()

	request := &javascript.Request{Code: `module.exports = { success: true, response: "unexpected" }`}
	require.NoError(t, request.Compile(executorOptions))

	target := contextargs.NewWithInput(context.Background(), "https://example.com:443")
	err := request.ExecuteWithResults(target, nil, nil, func(*output.InternalWrappedEvent) {
		t.Fatal("unexpected callback for unverified javascript template")
	})
	require.ErrorContains(t, err, "refusing to execute unverified javascript template")
}

func TestJavascriptRequestsTakeFromRateLimiter(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	executorOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "javascript-rate-limit"})
	executorOptions.JsCompiler = templates.GetJsCompiler()
	executorOptions.Verified = true
	executorOptions.RateLimiter.Stop()
	executorOptions.RateLimiter = ratelimit.New(context.Background(), 1, 300*time.Millisecond)
	t.Cleanup(executorOptions.RateLimiter.Stop)

	request := &javascript.Request{
		ID:   "javascript-rate-limit",
		Code: "function run() { return { success: true, response: \"ok\" }; }\nrun();",
	}
	require.NoError(t, request.Compile(executorOptions))

	start := time.Now()
	for range 4 {
		target := contextargs.NewWithInput(context.Background(), "https://example.com:443")
		require.NoError(t, request.ExecuteWithResults(target, nil, nil, func(*output.InternalWrappedEvent) {}))
	}
	// 4 executions at 1 per 300ms cannot finish in under ~900ms when limited
	require.GreaterOrEqual(t, time.Since(start), 800*time.Millisecond)
}

func TestRequestsCountsEveryPort(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	tests := []struct {
		name         string
		port         string
		payloads     map[string]interface{}
		preCondition string
		want         int
	}{
		{name: "no port", want: 1},
		{name: "single port", port: "80", want: 1},
		{name: "multiple ports", port: "80, 443,8080", want: 3},
		{name: "duplicate ports", port: "80,80", want: 1},
		{name: "ports with payloads", port: "80,443", payloads: map[string]interface{}{"user": []interface{}{"a", "b", "c"}}, want: 6},
		{name: "ports with pre-condition", port: "80,443", preCondition: "true", want: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executorOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "requests-per-port"})
			request := &javascript.Request{
				Args:         map[string]interface{}{},
				Payloads:     tt.payloads,
				PreCondition: tt.preCondition,
				Code:         `true`,
			}
			if tt.port != "" {
				request.Args["Port"] = tt.port
			}
			require.NoError(t, request.Compile(executorOptions))
			require.Equal(t, tt.want, request.Requests())
		})
	}
}

type countingProgress struct {
	testutils.MockProgressClient
	requests atomic.Int64
	errors   atomic.Int64
}

func (p *countingProgress) IncrementRequests()        { p.requests.Add(1) }
func (p *countingProgress) SetRequests(count uint64)  { p.requests.Add(int64(count)) }
func (p *countingProgress) IncrementErrorsBy(n int64) { p.errors.Add(n) }
func (p *countingProgress) IncrementFailedRequestsBy(n int64) {
	p.requests.Add(n)
	p.errors.Add(n)
}

func TestPreConditionRequestsAreCounted(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	tests := []struct {
		name         string
		port         string
		preCondition string
		payloads     map[string]interface{}
		wantErrors   int64
	}{
		{name: "pass", preCondition: "true"},
		{name: "pass with payloads", preCondition: "true", payloads: map[string]interface{}{"user": []interface{}{"a", "b", "c"}}},
		{name: "fail", preCondition: "false"},
		{name: "fail with payloads", preCondition: "false", payloads: map[string]interface{}{"user": []interface{}{"a", "b", "c"}}},
		{name: "error with payloads", preCondition: "throw new Error('boom')", payloads: map[string]interface{}{"user": []interface{}{"a", "b", "c"}}, wantErrors: 3},
		{name: "fail with payloads on two ports", port: "80,443", preCondition: "false", payloads: map[string]interface{}{"user": []interface{}{"a", "b", "c"}}},
		{name: "error with payloads on two ports", port: "80,443", preCondition: "throw new Error('boom')", payloads: map[string]interface{}{"user": []interface{}{"a", "b", "c"}}, wantErrors: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executorOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "pre-condition-count"})
			executorOptions.JsCompiler = templates.GetJsCompiler()
			executorOptions.Verified = true
			progress := &countingProgress{}
			executorOptions.Progress = progress

			request := &javascript.Request{
				Args:         map[string]interface{}{},
				PreCondition: tt.preCondition,
				Payloads:     tt.payloads,
				Code:         `true`,
			}
			if tt.port != "" {
				request.Args["Port"] = tt.port
			}
			require.NoError(t, request.Compile(executorOptions))

			target := contextargs.NewWithInput(context.Background(), "127.0.0.1:1")
			_ = request.ExecuteWithResults(target, nil, nil, func(*output.InternalWrappedEvent) {})

			require.Equal(t, int64(request.Requests()), progress.requests.Load())
			require.Equal(t, tt.wantErrors, progress.errors.Load())
		})
	}
}
