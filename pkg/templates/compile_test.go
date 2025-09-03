package templates_test

import (
	"context"
	"fmt"
	"log"
	netHttp "net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
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

func Test_ParseFromURL(t *testing.T) {
	router := httprouter.New()
	router.GET("/match-1.yaml", func(w netHttp.ResponseWriter, r *netHttp.Request, _ httprouter.Params) {
		b, err := os.ReadFile("tests/match-1.yaml")
		if err != nil {
			w.Write([]byte(err.Error())) // nolint: errcheck
		}
		w.Write(b) // nolint: errcheck
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	var expectedTemplate = &templates.Template{
		ID: "basic-get",
		Info: model.Info{
			Name:           "Basic GET Request",
			Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		RequestsHTTP: []*http.Request{{
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Type: matchers.MatcherTypeHolder{
						MatcherType: matchers.WordsMatcher,
					},
					Words: []string{"This is test matcher text"},
				}},
			},
			Path:       []string{"{{BaseURL}}"},
			AttackType: generators.AttackTypeHolder{},
			Method: http.HTTPMethodTypeHolder{
				MethodType: http.HTTPGet,
			},
		}},
		TotalRequests: 1,
		Executer:      nil,
		Path:          ts.URL + "/match-1.yaml",
	}
	setup()
	got, err := templates.Parse(ts.URL+"/match-1.yaml", nil, executerOpts)
	require.Nilf(t, err, "could not parse template (%s)", fmt.Sprint(err))
	require.Nil(t, err, "could not parse template")
	require.Equal(t, expectedTemplate.ID, got.ID)
	require.Equal(t, expectedTemplate.Info, got.Info)
	require.Equal(t, expectedTemplate.TotalRequests, got.TotalRequests)
	require.Equal(t, expectedTemplate.Path, got.Path)
	require.Equal(t, expectedTemplate.RequestsHTTP[0].Path, got.RequestsHTTP[0].Path)
	require.Equal(t, expectedTemplate.RequestsHTTP[0].Operators.Matchers[0].Words, got.RequestsHTTP[0].Operators.Matchers[0].Words)
	require.Equal(t, len(expectedTemplate.RequestsHTTP), len(got.RequestsHTTP))
}

func Test_ParseFromFile(t *testing.T) {
	filePath := "tests/match-1.yaml"
	expectedTemplate := &templates.Template{
		ID: "basic-get",
		Info: model.Info{
			Name:           "Basic GET Request",
			Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		RequestsHTTP: []*http.Request{{
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Type: matchers.MatcherTypeHolder{
						MatcherType: matchers.WordsMatcher,
					},
					Words: []string{"This is test matcher text"},
				}},
			},
			Path:       []string{"{{BaseURL}}"},
			AttackType: generators.AttackTypeHolder{},
			Method: http.HTTPMethodTypeHolder{
				MethodType: http.HTTPGet,
			},
		}},
		TotalRequests: 1,
		Executer:      nil,
		Path:          "tests/match-1.yaml",
	}
	setup()
	got, err := templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, err, "could not parse template")
	require.Equal(t, expectedTemplate.ID, got.ID)
	require.Equal(t, expectedTemplate.Info, got.Info)
	require.Equal(t, expectedTemplate.TotalRequests, got.TotalRequests)
	require.Equal(t, expectedTemplate.Path, got.Path)
	require.Equal(t, expectedTemplate.RequestsHTTP[0].Path, got.RequestsHTTP[0].Path)
	require.Equal(t, expectedTemplate.RequestsHTTP[0].Operators.Matchers[0].Words, got.RequestsHTTP[0].Operators.Matchers[0].Words)
	require.Equal(t, len(expectedTemplate.RequestsHTTP), len(got.RequestsHTTP))

	// Test cache
	got, err = templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, err, "could not parse template")
	require.Equal(t, expectedTemplate.ID, got.ID)
}

func Test_ParseWorkflow(t *testing.T) {
	filePath := "tests/workflow.yaml"
	expectedTemplate := &templates.Template{
		ID: "workflow-example",
		Info: model.Info{
			Name:           "Test Workflow Template",
			Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		Workflow: workflows.Workflow{
			Workflows: []*workflows.WorkflowTemplate{{Template: "tests/match-1.yaml"}, {Template: "tests/match-1.yaml"}},
			Options:   &protocols.ExecutorOptions{},
		},
		CompiledWorkflow: &workflows.Workflow{},
		SelfContained:    false,
		StopAtFirstMatch: false,
		Signature:        http.SignatureTypeHolder{},
		Variables:        variables.Variable{},
		TotalRequests:    0,
		Executer:         nil,
		Path:             "tests/workflow.yaml",
	}
	setup()
	got, err := templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, err, "could not parse template")
	require.Equal(t, expectedTemplate.ID, got.ID)
	require.Equal(t, expectedTemplate.Info, got.Info)
	require.Equal(t, expectedTemplate.TotalRequests, got.TotalRequests)
	require.Equal(t, expectedTemplate.Path, got.Path)
	require.Equal(t, expectedTemplate.Workflow.Workflows[0].Template, got.Workflow.Workflows[0].Template)
	require.Equal(t, len(expectedTemplate.Workflows), len(got.Workflows))
}

func Test_WrongTemplate(t *testing.T) {
	setup()

	filePath := "tests/no-author.yaml"
	got, err := templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, got, "could not parse template")
	require.ErrorContains(t, err, "no template author field provided")

	filePath = "tests/no-req.yaml"
	got, err = templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, got, "could not parse template")
	require.ErrorContains(t, err, "no requests defined ")
}

func TestWrongWorkflow(t *testing.T) {
	setup()

	filePath := "tests/workflow-invalid.yaml"
	got, err := templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, got, "could not parse template")
	require.ErrorContains(t, err, "workflows cannot have other protocols")
}

func Test_SharedCompiledCache_SharedAcrossParsers(t *testing.T) {
	setup()
	p1 := templates.NewSharedParserWithCompiledCache()
	p2 := templates.NewSharedParserWithCompiledCache()

	exec1 := &protocols.ExecutorOptions{
		Output:      testutils.NewMockOutputWriter(testutils.DefaultOptions.OmitTemplate),
		Options:     testutils.DefaultOptions,
		Progress:    executerOpts.Progress,
		Catalog:     executerOpts.Catalog,
		RateLimiter: executerOpts.RateLimiter,
		Parser:      p1,
	}
	// reinit options fully for isolation
	opts2 := testutils.DefaultOptions
	testutils.Init(opts2)
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)
	exec2 := &protocols.ExecutorOptions{
		Output:      testutils.NewMockOutputWriter(opts2.OmitTemplate),
		Options:     opts2,
		Progress:    progressImpl,
		Catalog:     executerOpts.Catalog,
		RateLimiter: executerOpts.RateLimiter,
		Parser:      p2,
	}

	filePath := "tests/match-1.yaml"

	got1, err := templates.Parse(filePath, nil, exec1)
	require.NoError(t, err)
	require.NotNil(t, got1)

	got2, err := templates.Parse(filePath, nil, exec2)
	require.NoError(t, err)
	require.NotNil(t, got2)

	require.Equal(t, p1.CompiledCache(), p2.CompiledCache())
	require.Greater(t, p1.CompiledCount(), 0)
	require.Equal(t, p1.CompiledCount(), p2.CompiledCount())
}

func Test_SharedCompiledCache_OptionsIsolation(t *testing.T) {
	setup()
	p1 := templates.NewSharedParserWithCompiledCache()
	p2 := templates.NewSharedParserWithCompiledCache()

	exec1 := &protocols.ExecutorOptions{
		Output:      testutils.NewMockOutputWriter(testutils.DefaultOptions.OmitTemplate),
		Options:     testutils.DefaultOptions,
		Progress:    executerOpts.Progress,
		Catalog:     executerOpts.Catalog,
		RateLimiter: executerOpts.RateLimiter,
		Parser:      p1,
	}
	// reinit options fully for isolation
	opts2 := testutils.DefaultOptions
	testutils.Init(opts2)
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)
	exec2 := &protocols.ExecutorOptions{
		Output:      testutils.NewMockOutputWriter(opts2.OmitTemplate),
		Options:     opts2,
		Progress:    progressImpl,
		Catalog:     executerOpts.Catalog,
		RateLimiter: executerOpts.RateLimiter,
		Parser:      p2,
	}

	filePath := "tests/match-1.yaml"

	got1, err := templates.Parse(filePath, nil, exec1)
	require.NoError(t, err)
	require.NotNil(t, got1)

	got2, err := templates.Parse(filePath, nil, exec2)
	require.NoError(t, err)
	require.NotNil(t, got2)

	require.NotEqual(t, got1.Options, got2.Options)
}

// compiled cache does not retain engine-scoped fields
func Test_CompiledCache_SanitizesOptions(t *testing.T) {
	setup()
	p := templates.NewSharedParserWithCompiledCache()
	exec := executerOpts
	exec.Parser = p
	filePath := "tests/match-1.yaml"

	got, err := templates.Parse(filePath, nil, exec)
	require.NoError(t, err)
	require.NotNil(t, got)

	cached, raw, err := p.CompiledCache().Has(filePath)
	require.NoError(t, err)
	require.NotNil(t, cached)
	require.Nil(t, raw)

	// cached template must not hold engine-scoped references
	require.Nil(t, cached.Options.Options)
	require.Empty(t, cached.Options.TemplateVerifier)
	require.Empty(t, cached.Options.TemplateID)
	require.Empty(t, cached.Options.TemplatePath)
	require.False(t, cached.Options.StopAtFirstMatch)
}

// different engines see different Options pointers
func Test_EngineIsolation_NoCrossLeaks(t *testing.T) {
	setup()
	p1 := templates.NewSharedParserWithCompiledCache()
	p2 := templates.NewSharedParserWithCompiledCache()

	// engine 1
	exec1 := &protocols.ExecutorOptions{
		Output:      executerOpts.Output,
		Options:     executerOpts.Options,
		Progress:    executerOpts.Progress,
		Catalog:     executerOpts.Catalog,
		RateLimiter: executerOpts.RateLimiter,
		Parser:      p1,
	}
	// engine 2 with a fresh options instance
	opts2 := testutils.DefaultOptions
	testutils.Init(opts2)
	progress2, _ := progress.NewStatsTicker(0, false, false, false, 0)
	exec2 := &protocols.ExecutorOptions{
		Output:      testutils.NewMockOutputWriter(opts2.OmitTemplate),
		Options:     opts2,
		Progress:    progress2,
		Catalog:     executerOpts.Catalog,
		RateLimiter: executerOpts.RateLimiter,
		Parser:      p2,
	}

	filePath := "tests/match-1.yaml"

	got1, err := templates.Parse(filePath, nil, exec1)
	require.NoError(t, err)
	got2, err := templates.Parse(filePath, nil, exec2)
	require.NoError(t, err)

	// template options must be distinct per engine
	require.NotEqual(t, got1.Options, got2.Options)

	// http request options must bind to engine-specific ExecutorOptions copies (not shared)
	require.NotEmpty(t, got1.RequestsHTTP)
	require.NotEmpty(t, got2.RequestsHTTP)
	r1 := got1.RequestsHTTP[0]
	r2 := got2.RequestsHTTP[0]
	// ensure options structs are not the same pointer
	require.NotSame(t, r1.Options().Options, r2.Options().Options)
	// mutate engine2 options and ensure it doesn't affect engine1
	r2.Options().Options.RateLimit = 999
	require.NotEqual(t, r1.Options().Options.RateLimit, r2.Options().Options.RateLimit)

	// compiled cache instance shared, but without engine leakage
	require.Equal(t, p1.CompiledCache(), p2.CompiledCache())
}
