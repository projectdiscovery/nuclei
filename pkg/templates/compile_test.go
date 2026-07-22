package templates_test

import (
	"context"
	"fmt"
	"log"
	netHttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
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
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/globalmatchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
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

func Test_ParseWorkflowWithGlobalMatchers(t *testing.T) {
	setup()
	previousGlobalMatchers := executerOpts.Options.EnableGlobalMatchersTemplates
	executerOpts.Options.EnableGlobalMatchersTemplates = true
	defer func() {
		executerOpts.Options.EnableGlobalMatchersTemplates = previousGlobalMatchers
		executerOpts.GlobalMatchers = nil
	}()
	executerOpts.GlobalMatchers = globalmatchers.New()

	filePath := "tests/workflow-global-matchers.yaml"
	got, err := templates.Parse(filePath, nil, executerOpts)
	require.NoError(t, err, "could not parse workflow template")
	require.NotNil(t, got, "workflow template should not be nil")
	require.NotNil(t, got.CompiledWorkflow, "compiled workflow should not be nil")
	require.Len(t, got.CompiledWorkflow.Workflows, 2)
	require.Len(t, got.CompiledWorkflow.Workflows[0].Executers, 1)
	require.Len(t, got.CompiledWorkflow.Workflows[1].Executers, 0)
}

func Test_ParseWorkflowAllowsFileAndSelfContainedSubtemplatesWhenEnabled(t *testing.T) {
	setup()
	previousFileTemplates := executerOpts.Options.EnableFileTemplates
	previousSelfContainedTemplates := executerOpts.Options.EnableSelfContainedTemplates
	defer func() {
		executerOpts.Options.EnableFileTemplates = previousFileTemplates
		executerOpts.Options.EnableSelfContainedTemplates = previousSelfContainedTemplates
	}()

	executerOpts.Options.EnableFileTemplates = true
	executerOpts.Options.EnableSelfContainedTemplates = true

	got, err := templates.Parse("tests/workflow-capability-gates.yaml", nil, executerOpts)
	require.NoError(t, err, "could not parse workflow template")
	require.NotNil(t, got.CompiledWorkflow, "compiled workflow should not be nil")
	require.Len(t, got.CompiledWorkflow.Workflows, 1)

	workflow := got.CompiledWorkflow.Workflows[0]
	require.Len(t, workflow.Executers, 1)
	require.Len(t, workflow.Subtemplates, 1)
	require.Len(t, workflow.Subtemplates[0].Executers, 1)
}

func Test_ParseWorkflowRecordsUnsignedCodeSubtemplateOnlyAsCodeSkip(t *testing.T) {
	setup()
	previousCodeTemplates := executerOpts.Options.EnableCodeTemplates
	previousDisableUnsigned := executerOpts.Options.DisableUnsignedTemplates
	defer func() {
		executerOpts.Options.EnableCodeTemplates = previousCodeTemplates
		executerOpts.Options.DisableUnsignedTemplates = previousDisableUnsigned
	}()

	executerOpts.Options.EnableCodeTemplates = false
	executerOpts.Options.DisableUnsignedTemplates = false

	dir := t.TempDir()
	codeTemplatePath := filepath.Join(dir, "unsigned-code.yaml")
	err := os.WriteFile(codeTemplatePath, []byte(`id: workflow-unsigned-code

info:
  name: Workflow Unsigned Code
  author: pdteam
  severity: info

code:
  - engine:
      - sh
    source: |
      echo workflow-unsigned-code
`), 0o600)
	require.NoError(t, err)

	workflowPath := filepath.Join(dir, "workflow.yaml")
	err = os.WriteFile(workflowPath, []byte(fmt.Sprintf(`id: workflow-unsigned-code-gate

info:
  name: Workflow Unsigned Code Gate
  author: pdteam
  severity: info

workflows:
  - template: %q
`, codeTemplatePath)), 0o600)
	require.NoError(t, err)

	initialUnverifiedCode := stats.GetValue(templates.SkippedUnverifiedCodeTemplateStats)
	initialUnverified := stats.GetValue(templates.SkippedUnverifiedTemplateStats)

	got, err := templates.Parse(workflowPath, nil, executerOpts)
	require.NoError(t, err)
	require.NotNil(t, got.CompiledWorkflow)
	require.Len(t, got.CompiledWorkflow.Workflows, 1)
	require.Empty(t, got.CompiledWorkflow.Workflows[0].Executers)
	require.Equal(t, initialUnverifiedCode+1, stats.GetValue(templates.SkippedUnverifiedCodeTemplateStats))
	require.Equal(t, initialUnverified, stats.GetValue(templates.SkippedUnverifiedTemplateStats))
}

func Test_ParseWorkflowRecordsUnsignedJavascriptSubtemplateOnlyAsJavascriptSkip(t *testing.T) {
	setup()
	previousDisableUnsigned := executerOpts.Options.DisableUnsignedTemplates
	defer func() {
		executerOpts.Options.DisableUnsignedTemplates = previousDisableUnsigned
	}()

	executerOpts.Options.DisableUnsignedTemplates = false

	dir := t.TempDir()
	javascriptTemplatePath := filepath.Join(dir, "unsigned-javascript.yaml")
	err := os.WriteFile(javascriptTemplatePath, []byte(`id: workflow-unsigned-javascript

info:
  name: Workflow Unsigned Javascript
  author: pdteam
  severity: info

javascript:
  - code: |
      Export("workflow-unsigned-javascript")
`), 0o600)
	require.NoError(t, err)

	workflowPath := filepath.Join(dir, "workflow.yaml")
	err = os.WriteFile(workflowPath, []byte(fmt.Sprintf(`id: workflow-unsigned-javascript-gate

info:
  name: Workflow Unsigned Javascript Gate
  author: pdteam
  severity: info

workflows:
  - template: %q
`, javascriptTemplatePath)), 0o600)
	require.NoError(t, err)

	initialUnverifiedJavascript := stats.GetValue(templates.SkippedUnverifiedJavascriptTemplateStats)
	initialUnverified := stats.GetValue(templates.SkippedUnverifiedTemplateStats)

	got, err := templates.Parse(workflowPath, nil, executerOpts)
	require.NoError(t, err)
	require.NotNil(t, got.CompiledWorkflow)
	require.Len(t, got.CompiledWorkflow.Workflows, 1)
	require.Empty(t, got.CompiledWorkflow.Workflows[0].Executers)
	require.Equal(t, initialUnverifiedJavascript+1, stats.GetValue(templates.SkippedUnverifiedJavascriptTemplateStats))
	require.Equal(t, initialUnverified, stats.GetValue(templates.SkippedUnverifiedTemplateStats))
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
