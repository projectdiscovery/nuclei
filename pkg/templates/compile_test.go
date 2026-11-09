package templates_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	netHttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/globalmatchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	templatesigner "github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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

func Test_ParseWorkflowLoadsTemplatesWithSubtemplatesOnlyForFilteredSubtemplates(t *testing.T) {
	dir := t.TempDir()
	path := func(id string) string { return filepath.Join(dir, id+".yaml") }
	for _, id := range []string{"BA", "BB", "BC", "BC_A", "L1", "L2", "L3", "L4"} {
		err := os.WriteFile(path(id), []byte(fmt.Sprintf(`id: %s

info:
  name: %s
  author: pdteam
  severity: info
  tags: %s-tag

http:
  - method: GET
    path:
      - "{{BaseURL}}/%s"
`, id, id, strings.ToLower(id), id)), 0o600)
		require.NoError(t, err)
	}
	workflowPath := filepath.Join(dir, "workflow.yaml")
	err := os.WriteFile(workflowPath, []byte(fmt.Sprintf(`id: workflow-filters

info:
  name: Workflow Filters
  author: pdteam
  severity: info

workflows:
  - template: %q
    subtemplates:
      - template: %q
      - template: %q
  - template: %q
    subtemplates:
      - template: %q
  - template: %q
    subtemplates:
      - template: %q
        subtemplates:
          - template: %q
  - template: %q
    matchers:
      - name: found
        subtemplates:
          - template: %q
`, path("BA"), path("L1"), path("L2"), path("BB"), path("L3"), path("BC"), path("BC_A"), path("L4"), path("BB"), path("L1"))), 0o600)
	require.NoError(t, err)

	tests := []struct {
		name    string
		ids     []string
		tags    []string
		authors []string
		loaded  []string
	}{
		{name: "no filters", loaded: []string{"BA", "L1", "L2", "BB", "L3", "BC", "BC_A", "L4", "BB", "L1"}},
		{name: "id of a subtemplate", ids: []string{"L1"}, loaded: []string{"BA", "L1", "BB", "L1"}},
		{name: "tag of a subtemplate", tags: []string{"l1-tag"}, loaded: []string{"BA", "L1", "BB", "L1"}},
		{name: "id of a nested subtemplate", ids: []string{"L4"}, loaded: []string{"BC", "BC_A", "L4"}},
		{name: "id of a template with subtemplates", ids: []string{"BB"}, loaded: []string{"BB", "BB"}},
		{name: "author of no template", authors: []string{"nobody"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup()
			options := executerOpts.Options
			previousIds, previousTags, previousAuthors := options.IncludeIds, options.Tags, options.Authors
			defer func() {
				options.IncludeIds, options.Tags, options.Authors = previousIds, previousTags, previousAuthors
			}()
			options.IncludeIds, options.Tags, options.Authors = tc.ids, tc.tags, tc.authors
			workflowLoader, err := workflow.NewLoader(executerOpts)
			require.NoError(t, err)
			executerOpts.WorkflowLoader = workflowLoader

			got, err := templates.Parse(workflowPath, nil, executerOpts)
			require.NoError(t, err)
			require.NotNil(t, got.CompiledWorkflow)

			var loaded []string
			var walk func(steps []*workflows.WorkflowTemplate)
			walk = func(steps []*workflows.WorkflowTemplate) {
				for _, step := range steps {
					if len(step.Executers) > 0 {
						loaded = append(loaded, strings.TrimSuffix(filepath.Base(step.Template), ".yaml"))
					}
					walk(step.Subtemplates)
					for _, matcher := range step.Matchers {
						walk(matcher.Subtemplates)
					}
				}
			}
			walk(got.CompiledWorkflow.Workflows)
			require.Equal(t, tc.loaded, loaded)
		})
	}
}

func Test_ParseWorkflowLoadsStepsOfFilteredSubtemplatesUnlessExcluded(t *testing.T) {
	// tags steps search the templates directory
	templatesDir := t.TempDir()
	cfg := config.DefaultConfig
	previousTemplatesDir := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(previousTemplatesDir) })
	cfg.SetTemplatesDir(templatesDir)

	path := func(id string) string { return filepath.Join(templatesDir, id+".yaml") }
	for _, tpl := range []struct{ id, severity, tag string }{
		{"BA", "low", "ba-tag"},
		{"L1", "info", "l1-tag"},
		{"other", "info", "other-tag"},
	} {
		err := os.WriteFile(path(tpl.id), fmt.Appendf(nil, `id: %s

info:
  name: %s
  author: pdteam
  severity: %s
  tags: %s

http:
  - method: GET
    path:
      - "{{BaseURL}}/%s"
`, tpl.id, tpl.id, tpl.severity, tpl.tag, tpl.id), 0o600)
		require.NoError(t, err)
	}
	workflowPath := filepath.Join(t.TempDir(), "workflow.yaml")
	err := os.WriteFile(workflowPath, fmt.Appendf(nil, `id: workflow-step-filters

info:
  name: Workflow Step Filters
  author: pdteam
  severity: info

workflows:
  - tags: ba-tag
    subtemplates:
      - template: %q
  - template: %q
    subtemplates:
      - template: %q
`, path("L1"), path("BA"), path("L1")), 0o600)
	require.NoError(t, err)

	tests := []struct {
		name   string
		filter func(options *types.Options)
		// executers of the tags step, its subtemplate, the template step and
		// its subtemplate
		loaded []int
	}{
		{name: "no filters", loaded: []int{1, 1, 1, 1}},
		{name: "id of the subtemplate", filter: func(o *types.Options) {
			o.IncludeIds = []string{"L1"}
		}, loaded: []int{1, 1, 1, 1}},
		{name: "tag of the subtemplate", filter: func(o *types.Options) {
			o.Tags = []string{"l1-tag"}
		}, loaded: []int{1, 1, 1, 1}},
		{name: "id of the step template", filter: func(o *types.Options) {
			o.IncludeIds = []string{"BA"}
		}, loaded: []int{1, 0, 1, 0}},
		{name: "excluded tag of the step template", filter: func(o *types.Options) {
			o.IncludeIds, o.ExcludeTags = []string{"L1"}, []string{"ba-tag"}
		}, loaded: []int{0, 1, 0, 1}},
		{name: "included excluded tag of the step template", filter: func(o *types.Options) {
			o.IncludeIds, o.ExcludeTags, o.IncludeTags = []string{"L1"}, []string{"ba-tag"}, []string{"ba-tag"}
		}, loaded: []int{1, 1, 1, 1}},
		{name: "excluded id of the step template", filter: func(o *types.Options) {
			o.IncludeIds, o.ExcludeIds = []string{"L1"}, []string{"BA"}
		}, loaded: []int{0, 1, 0, 1}},
		{name: "excluded id of the step template and its subtemplate", filter: func(o *types.Options) {
			o.IncludeIds, o.ExcludeIds = []string{"BA", "L1"}, []string{"BA"}
		}, loaded: []int{0, 1, 0, 1}},
		{name: "excluded id of the included step template", filter: func(o *types.Options) {
			o.IncludeIds, o.ExcludeIds = []string{"BA"}, []string{"BA"}
		}, loaded: []int{0, 0, 0, 0}},
		// a step does not report its own results, so its severity only
		// matters when no subtemplate loaded
		{name: "excluded severity of the step template", filter: func(o *types.Options) {
			o.ExcludeSeverities = severity.Severities{severity.Low}
		}, loaded: []int{1, 1, 1, 1}},
		{name: "excluded severity of the subtemplate", filter: func(o *types.Options) {
			o.ExcludeSeverities = severity.Severities{severity.Info}
		}, loaded: []int{1, 0, 1, 0}},
		{name: "excluded severity of the step template and its subtemplate", filter: func(o *types.Options) {
			o.ExcludeSeverities = severity.Severities{severity.Low, severity.Info}
		}, loaded: []int{0, 0, 0, 0}},
		{name: "excluded path of the step template", filter: func(o *types.Options) {
			o.IncludeIds, o.ExcludedTemplates = []string{"L1"}, []string{path("BA")}
		}, loaded: []int{0, 1, 0, 1}},
		{name: "author of no template", filter: func(o *types.Options) {
			o.Authors = []string{"nobody"}
		}, loaded: []int{0, 0, 0, 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup()
			options := executerOpts.Options.Copy()
			if tc.filter != nil {
				tc.filter(options)
			}
			executerOpts.Options = options
			workflowLoader, err := workflow.NewLoader(executerOpts)
			require.NoError(t, err)
			executerOpts.WorkflowLoader = workflowLoader
			warnings := recordWarnings(t)
			skippedSteps := stats.GetValue(templates.SkippedWorkflowStepStats)

			got, err := templates.Parse(workflowPath, nil, executerOpts)
			require.NoError(t, err)
			require.NotNil(t, got.CompiledWorkflow)
			loaded := make([]int, 0, 2*len(got.CompiledWorkflow.Workflows))
			for _, step := range got.CompiledWorkflow.Workflows {
				loaded = append(loaded, len(step.Executers), len(step.Subtemplates[0].Executers))
			}
			require.Equal(t, tc.loaded, loaded)

			// a step that loads nothing is counted, and with -v logged, as its
			// loaded subtemplate will not run
			var blockedSteps int64
			for i, step := range []string{"tags ba-tag", path("BA")} {
				blocked := loaded[2*i] == 0 && loaded[2*i+1] > 0
				if blocked {
					blockedSteps++
				}
				require.Equal(t, blocked, warnings.contain(workflowPath, step, "subtemplates will not run"), step)
			}
			require.Equal(t, blockedSteps, stats.GetValue(templates.SkippedWorkflowStepStats)-skippedSteps)
		})
	}
}

// warningRecorder records the warnings gologger writes.
type warningRecorder struct {
	mu    sync.Mutex
	lines []string
}

// recordWarnings records the warnings gologger writes until t ends.
func recordWarnings(t *testing.T) *warningRecorder {
	t.Helper()
	recorder := &warningRecorder{}
	gologger.DefaultLogger.SetWriter(recorder)
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	t.Cleanup(func() {
		// gologger's own defaults: it has no getter to save the previous ones
		gologger.DefaultLogger.SetWriter(writer.NewCLI())
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	})
	return recorder
}

func (w *warningRecorder) Write(data []byte, level levels.Level) {
	if level != levels.LevelWarning {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, string(data))
}

// contain reports whether a recorded warning contains all of parts.
func (w *warningRecorder) contain(parts ...string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.ContainsFunc(w.lines, func(line string) bool {
		return !slices.ContainsFunc(parts, func(part string) bool { return !strings.Contains(line, part) })
	})
}

func Test_ParseWorkflowExcludesIdListedInExcludeTags(t *testing.T) {
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "dup.yaml")
	err := os.WriteFile(templatePath, []byte(`id: dup

info:
  name: dup
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`), 0o600)
	require.NoError(t, err)

	workflowPath := filepath.Join(dir, "workflow.yaml")
	err = os.WriteFile(workflowPath, fmt.Appendf(nil, `id: wf

info:
  name: wf
  author: pdteam

workflows:
  - template: %q
`, templatePath), 0o600)
	require.NoError(t, err)

	tests := []struct {
		name        string
		excludeTags []string
	}{
		{name: "exclude id"},
		{name: "exclude id and same tag", excludeTags: []string{"dup"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup()

			options := executerOpts.Options.Copy()
			options.ExcludeIds, options.ExcludeTags = []string{"dup"}, tc.excludeTags
			executerOpts.Options = options
			workflowLoader, err := workflow.NewLoader(executerOpts)
			require.NoError(t, err)

			executerOpts.WorkflowLoader = workflowLoader

			got, err := templates.Parse(workflowPath, nil, executerOpts)
			require.NoError(t, err)
			require.NotNil(t, got.CompiledWorkflow)
			require.Len(t, got.CompiledWorkflow.Workflows, 1)
			require.Empty(t, got.CompiledWorkflow.Workflows[0].Executers)
		})
	}
}

func Test_ParseWorkflowLoadsTemplateWithUnknownMatcherCondition(t *testing.T) {
	setup()
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "template.yaml")
	err := os.WriteFile(templatePath, []byte(`id: workflow-unknown-condition-template

info:
  name: Workflow Unknown Condition Template
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`), 0o600)
	require.NoError(t, err)
	workflowPath := filepath.Join(dir, "workflow.yaml")
	err = os.WriteFile(workflowPath, []byte(fmt.Sprintf(`id: workflow-unknown-condition

info:
  name: Workflow Unknown Condition
  author: pdteam
  severity: info

workflows:
  - template: %q
    matchers:
      - name:
          - a
          - b
        condition: xor
        subtemplates:
          - template: %q
`, templatePath, templatePath)), 0o600)
	require.NoError(t, err)

	got, err := templates.Parse(workflowPath, nil, executerOpts)
	require.NoError(t, err)
	require.NotNil(t, got.CompiledWorkflow)
	require.Len(t, got.CompiledWorkflow.Workflows, 1)
	require.Len(t, got.CompiledWorkflow.Workflows[0].Executers, 1)
}

func TestParseTemplateExecutesJavascriptInitAfterVerification(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = "parse-verified-javascript-init"
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	signer := ciTemplateSigner(t)
	withDefaultTemplateSigner(t, signer)

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.TemplatePath = "verified-javascript-init.yaml"
	templateSource := `id: verified-javascript-init

info:
  name: Verified Javascript Init
  author: pdteam
  severity: info

javascript:
  - init: |
      set("init-status", "executed")
    code: |
      Export("verified-javascript-init")
`
	template, err := templates.ParseTemplateFromReader(strings.NewReader(signTemplateForTest(t, signer, templateSource)), nil, executerOptions)
	require.NoError(t, err)
	require.True(t, template.Verified)
	require.True(t, template.Options.Verified)
	require.Equal(t, "executed", template.RequestsJavascript[0].Args["init-status"])
}

func TestParseTemplateExecutesPreprocessedJavascriptInitAfterVerification(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = "parse-verified-preprocessed-javascript-init"
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	signer := ciTemplateSigner(t)
	withDefaultTemplateSigner(t, signer)

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.TemplatePath = "verified-preprocessed-javascript-init.yaml"
	templateSource := `id: verified-preprocessed-javascript-init

info:
  name: Verified Preprocessed Javascript Init {{randstr}}
  author: pdteam
  severity: info

javascript:
  - init: |
      set("init-status", "{{randstr}}")
    code: |
      Export("verified-preprocessed-javascript-init")
`
	template, err := templates.ParseTemplateFromReader(strings.NewReader(signTemplateForTest(t, signer, templateSource)), nil, executerOptions)
	require.NoError(t, err)
	require.True(t, template.Verified)
	require.True(t, template.Options.Verified)
	require.NotEmpty(t, template.RequestsJavascript[0].Args["init-status"])
	require.NotEqual(t, "{{randstr}}", template.RequestsJavascript[0].Args["init-status"])
}

func verificationDigestForTest(data string, importedContents ...string) [sha256.Size]byte {
	dataDigest := sha256.Sum256([]byte(data))
	componentDigests := append([]byte(nil), dataDigest[:]...)
	for _, contents := range importedContents {
		importDigest := sha256.Sum256([]byte(contents))
		componentDigests = append(componentDigests, importDigest[:]...)
	}
	return sha256.Sum256(componentDigests)
}

func trustedVerificationForTest(data string, importedContents ...string) *protocols.TemplateVerification {
	verifier := templatesigner.DefaultTemplateVerifiers[0]
	return &protocols.TemplateVerification{
		Verified:            true,
		Verifier:            verifier.Identifier(),
		VerifierFingerprint: verifier.Fingerprint(),
		ContentDigest:       verificationDigestForTest(data, importedContents...),
	}
}

// ciTemplateSigner returns a signer backed by the CI test keypair.
func ciTemplateSigner(t *testing.T) *templatesigner.TemplateSigner {
	t.Helper()

	s, err := templatesigner.NewTemplateSignerFromFiles("signer/testdata/ci.crt", "signer/testdata/ci-private-key.pem")
	require.NoError(t, err)

	return s
}

// withDefaultTemplateSigner prepends the given signer to the default
// verifiers for the duration of the test.
func withDefaultTemplateSigner(t *testing.T, s *templatesigner.TemplateSigner) {
	t.Helper()

	original := templatesigner.DefaultTemplateVerifiers
	templatesigner.DefaultTemplateVerifiers = append([]*templatesigner.TemplateSigner{s}, original...)
	t.Cleanup(func() {
		templatesigner.DefaultTemplateVerifiers = original
	})
}

// signTemplateForTest returns src with a valid signature appended by the
// given signer. When importPaths are non-empty the signature also binds the
// contents of those files, read from disk at signing time.
func signTemplateForTest(t *testing.T, s *templatesigner.TemplateSigner, src string, importPaths ...string) string {
	t.Helper()

	signable := &templates.Template{ImportedFiles: importPaths}
	signature, err := s.Sign([]byte(src), signable)
	require.NoError(t, err)

	return src + "\n" + signature
}

func TestParseTemplateVerificationUsesLoadedImportContents(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	loadedCode := `Export("loaded-import")`
	importPath := filepath.Join(t.TempDir(), "import.js")
	require.NoError(t, os.WriteFile(importPath, []byte(loadedCode), 0o600))
	options.LoadHelperFileFunction = func(helperFile, _ string, _ catalog.Catalog) (io.ReadCloser, error) {
		require.Equal(t, importPath, helperFile)
		return io.NopCloser(strings.NewReader(loadedCode)), nil
	}
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.TemplatePath = "loaded-import.yaml"
	templateSource := fmt.Sprintf(`id: loaded-import

info:
  name: Loaded Import
  author: pdteam
  severity: info

javascript:
  - code: %q
`, importPath)

	signer := ciTemplateSigner(t)
	withDefaultTemplateSigner(t, signer)

	template, err := templates.ParseTemplateFromReader(strings.NewReader(signTemplateForTest(t, signer, templateSource, importPath)), nil, executerOptions)
	require.NoError(t, err)
	require.True(t, template.Verified)
	require.Equal(t, loadedCode, template.RequestsJavascript[0].Code)
}

func TestParseTemplateRejectsCachedVerificationWithMismatchedVerifierFingerprint(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.TemplatePath = "revoked-verifier.yaml"
	templateSource := `id: revoked-verifier

info:
  name: Revoked Verifier
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`
	executerOptions.TemplateVerificationCallback = func(templatePath string) *protocols.TemplateVerification {
		require.Equal(t, executerOptions.TemplatePath, templatePath)
		verifier := templatesigner.DefaultTemplateVerifiers[0]
		rotatedFingerprint := verifier.Fingerprint()
		rotatedFingerprint[0] ^= 0xff
		return &protocols.TemplateVerification{
			Verified:            true,
			Verifier:            verifier.Identifier(),
			VerifierFingerprint: rotatedFingerprint,
			ContentDigest:       verificationDigestForTest(templateSource),
		}
	}

	template, err := templates.ParseTemplateFromReader(strings.NewReader(templateSource), nil, executerOptions)
	require.NoError(t, err)
	require.False(t, template.Verified)
}

func TestParseTemplateIgnoresCachedVerificationForCodeTemplates(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.TemplatePath = "poisoned-code-template.yaml"
	templateSource := `id: poisoned-code-template

info:
  name: Poisoned Code Template
  author: pdteam
  severity: info

code:
  - engine:
      - sh
    source: |
      echo poisoned
`
	// A forged cache entry: self-consistent digest, real verifier
	// fingerprint and Verified=true. Writing index.gob is all an attacker
	// needs; the signature of the template itself is never checked if this
	// entry is trusted.
	executerOptions.TemplateVerificationCallback = func(templatePath string) *protocols.TemplateVerification {
		require.Equal(t, executerOptions.TemplatePath, templatePath)
		return trustedVerificationForTest(templateSource)
	}

	template, err := templates.ParseTemplateFromReader(strings.NewReader(templateSource), nil, executerOptions)
	require.NoError(t, err)
	require.False(t, template.Verified)
	require.False(t, template.Options.Verified)
}

func TestParseTemplateIgnoresCachedVerificationForJavascriptTemplates(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.TemplatePath = "poisoned-javascript-template.yaml"
	templateSource := `id: poisoned-javascript-template

info:
  name: Poisoned Javascript Template
  author: pdteam
  severity: info

javascript:
  - init: |
      set("init-status", "executed")
    code: |
      Export("poisoned-javascript-template")
`
	executerOptions.TemplateVerificationCallback = func(templatePath string) *protocols.TemplateVerification {
		require.Equal(t, executerOptions.TemplatePath, templatePath)
		return trustedVerificationForTest(templateSource)
	}

	template, err := templates.ParseTemplateFromReader(strings.NewReader(templateSource), nil, executerOptions)
	require.NoError(t, err)
	require.False(t, template.Verified)
	require.False(t, template.Options.Verified)
	require.NotContains(t, template.RequestsJavascript[0].Args, "init-status")
}

func TestParseTemplateIgnoresCachedVerificationForHttpTemplates(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.TemplatePath = "poisoned-http-template.yaml"
	templateSource := `id: poisoned-http-template

info:
  name: Poisoned HTTP Template
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`
	executerOptions.TemplateVerificationCallback = func(templatePath string) *protocols.TemplateVerification {
		require.Equal(t, executerOptions.TemplatePath, templatePath)
		return trustedVerificationForTest(templateSource)
	}

	template, err := templates.ParseTemplateFromReader(strings.NewReader(templateSource), nil, executerOptions)
	require.NoError(t, err)
	require.False(t, template.Verified)
	require.False(t, template.Options.Verified)
}

func parseUnsignedWithPoisonedCache(t *testing.T, source, templatePath string) *templates.Template {
	t.Helper()

	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.TemplatePath = templatePath
	executerOptions.TemplateVerificationCallback = func(gotPath string) *protocols.TemplateVerification {
		require.Equal(t, templatePath, gotPath)
		return trustedVerificationForTest(source)
	}

	template, err := templates.ParseTemplateFromReader(strings.NewReader(source), nil, executerOptions)
	require.NoError(t, err)
	require.False(t, template.Verified)
	require.False(t, template.Options.Verified)
	return template
}

func TestParseTemplateIgnoresCachedVerificationForFlowTemplates(t *testing.T) {
	template := parseUnsignedWithPoisonedCache(t, `id: poisoned-flow-template

info:
  name: Poisoned Flow Template
  author: pdteam
  severity: info

flow: http(1)

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`, "poisoned-flow-template.yaml")
	require.True(t, template.IsFlowTemplate())
	require.Equal(t, "http(1)", template.Options.Flow)
	require.NotNil(t, template.Executer)
	require.False(t, template.HasJavascriptRequest())
}

func TestParseTemplateIgnoresCachedVerificationForWorkflowTemplates(t *testing.T) {
	setup()

	source, err := os.ReadFile("tests/workflow.yaml")
	require.NoError(t, err)

	executerOptions := executerOpts.Copy()
	executerOptions.Parser = templates.NewParser()
	executerOptions.TemplatePath = "tests/workflow.yaml"
	executerOptions.TemplateVerificationCallback = func(templatePath string) *protocols.TemplateVerification {
		require.Equal(t, executerOptions.TemplatePath, templatePath)
		return trustedVerificationForTest(string(source))
	}

	template, err := templates.Parse("tests/workflow.yaml", nil, executerOptions)
	require.NoError(t, err)
	require.False(t, template.Verified)
	require.False(t, template.Options.Verified)
	require.NotNil(t, template.CompiledWorkflow)
	require.Len(t, template.CompiledWorkflow.Workflows, 2)
}

func TestParseTemplateIgnoresCachedVerificationForPreprocessedHttpTemplates(t *testing.T) {
	template := parseUnsignedWithPoisonedCache(t, `id: poisoned-preprocessed-http

info:
  name: Poisoned Preprocessed HTTP
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/{{randstr}}"
`, "poisoned-preprocessed-http.yaml")
	require.True(t, template.HasHTTPRequest())
	require.NotContains(t, template.RequestsHTTP[0].Path[0], "{{randstr}}")
}

func TestParseTemplateIgnoresCachedVerificationFromDisk(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	templateSource := `id: poisoned-disk-http

info:
  name: Poisoned Disk HTTP
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`
	templatePath := filepath.Join(t.TempDir(), "poisoned-disk-http.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(templateSource), 0o600))

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.Parser = templates.NewParser()
	executerOptions.TemplateVerificationCallback = func(gotPath string) *protocols.TemplateVerification {
		require.Equal(t, templatePath, gotPath)
		return trustedVerificationForTest(templateSource)
	}

	template, err := templates.Parse(templatePath, nil, executerOptions)
	require.NoError(t, err)
	require.False(t, template.Verified)
	require.False(t, template.Options.Verified)
}

func TestParseFromURLIgnoresCachedVerification(t *testing.T) {
	source, err := os.ReadFile("tests/match-1.yaml")
	require.NoError(t, err)

	router := httprouter.New()
	router.GET("/match-1.yaml", func(w netHttp.ResponseWriter, _ *netHttp.Request, _ httprouter.Params) {
		_, _ = w.Write(source)
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	setup()
	templatePath := server.URL + "/match-1.yaml"
	executerOptions := executerOpts.Copy()
	executerOptions.Parser = templates.NewParser()
	executerOptions.TemplateVerificationCallback = func(gotPath string) *protocols.TemplateVerification {
		require.Equal(t, templatePath, gotPath)
		return trustedVerificationForTest(string(source))
	}

	template, err := templates.Parse(templatePath, nil, executerOptions)
	require.NoError(t, err)
	require.False(t, template.Verified)
	require.False(t, template.Options.Verified)
	require.Equal(t, "basic-get", template.ID)
}

func TestParseDoesNotTreatContentSwapAsVerified(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	signer := ciTemplateSigner(t)
	withDefaultTemplateSigner(t, signer)

	signedSource := `id: signed-http-before-swap

info:
  name: Signed HTTP Before Swap
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/signed"
`
	swappedSource := `id: swapped-unsigned-javascript

info:
  name: Swapped Unsigned Javascript
  author: pdteam
  severity: info

javascript:
  - init: |
      set("init-status", "executed")
    code: |
      Export("swapped-unsigned-javascript")
`
	templatePath := filepath.Join(t.TempDir(), "swap.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(signTemplateForTest(t, signer, signedSource)), 0o600))
	fileInfo, err := os.Stat(templatePath)
	require.NoError(t, err)

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.Parser = templates.NewParser()

	first, err := templates.Parse(templatePath, nil, executerOptions)
	require.NoError(t, err)
	require.True(t, first.Verified)
	require.Equal(t, "signed-http-before-swap", first.ID)

	require.NoError(t, os.WriteFile(templatePath, []byte(swappedSource), 0o600))
	require.NoError(t, os.Chtimes(templatePath, fileInfo.ModTime(), fileInfo.ModTime()))

	second, err := templates.Parse(templatePath, nil, executerOptions)
	require.NoError(t, err)
	if second.ID == "swapped-unsigned-javascript" {
		require.False(t, second.Verified)
		require.False(t, second.Options.Verified)
		require.NotContains(t, second.RequestsJavascript[0].Args, "init-status")
		return
	}

	require.Equal(t, "signed-http-before-swap", second.ID)
	require.True(t, second.Verified)
	require.False(t, second.HasJavascriptRequest())
}

func TestParseTemplateCompilesUnsignedJavascriptInit(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	template, err := templates.ParseTemplateFromReader(strings.NewReader(`id: unsigned-malformed-javascript-init

info:
  name: Unsigned Malformed Javascript Init
  author: pdteam
  severity: info

javascript:
  - init: |
      {
    code: |
      Export("unsigned-malformed-javascript-init")
`), nil, executerOptions)
	require.Nil(t, template)
	require.ErrorContains(t, err, "could not compile init code")
}

func TestParseTemplateDoesNotExecuteUnsignedJavascriptInit(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	template, err := templates.ParseTemplateFromReader(strings.NewReader(`id: unsigned-javascript-init

info:
  name: Unsigned Javascript Init
  author: pdteam
  severity: info

javascript:
  - init: |
      set("init-status", "executed")
    code: |
      Export("unsigned-javascript-init")
`), nil, executerOptions)
	require.NoError(t, err)
	require.False(t, template.Verified)
	require.NotContains(t, template.RequestsJavascript[0].Args, "init-status")
}

func TestParseCachedTemplatePreservesVerification(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	signer := ciTemplateSigner(t)
	withDefaultTemplateSigner(t, signer)

	templateSource := `id: cached-verified-javascript

info:
  name: Cached Verified Javascript
  author: pdteam
  severity: info

javascript:
  - code: |
      Export("cached-verified-javascript")
`
	templatePath := filepath.Join(t.TempDir(), "cached-verified-javascript.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(signTemplateForTest(t, signer, templateSource)), 0o600))

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.Parser = templates.NewParser()

	first, err := templates.Parse(templatePath, nil, executerOptions)
	require.NoError(t, err)
	require.True(t, first.Options.Verified)

	cached, err := templates.Parse(templatePath, nil, executerOptions)
	require.NoError(t, err)
	require.True(t, cached.Verified)
	require.True(t, cached.Options.Verified)
}

func TestParseReusesSharedParsedTemplateAcrossEngineCaches(t *testing.T) {
	var sourceReads atomic.Int32
	templateSource := `id: shared-parsed-template

info:
  name: Shared parsed template
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    body: |
      first line
      second line
`
	server := httptest.NewServer(netHttp.HandlerFunc(func(w netHttp.ResponseWriter, _ *netHttp.Request) {
		sourceReads.Add(1)
		_, _ = w.Write([]byte(templateSource))
	}))
	t.Cleanup(server.Close)

	setup()
	templatePath := server.URL + "/template.yaml"
	sharedParser := templates.NewParser()
	_, err := sharedParser.ParseTemplate(templatePath, executerOpts.Catalog)
	require.NoError(t, err)

	compiledTemplates := make([]*templates.Template, 5)
	parseErrors := make([]error, len(compiledTemplates))
	var waitGroup sync.WaitGroup
	for i := range compiledTemplates {
		engineOptions := executerOpts.Copy()
		engineOptions.Parser = templates.NewParserWithParsedCache(sharedParser.Cache())
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			compiledTemplates[i], parseErrors[i] = templates.Parse(templatePath, nil, engineOptions)
		}()
	}
	waitGroup.Wait()

	for i := range compiledTemplates {
		require.NoError(t, parseErrors[i])
		require.NotNil(t, compiledTemplates[i])
	}

	require.Equal(t, int32(1), sourceReads.Load())
	cachedTemplate, err := sharedParser.Cache().Get(templatePath)
	require.NoError(t, err)
	require.NotNil(t, cachedTemplate)
	require.NotContains(t, cachedTemplate.RequestsHTTP[0].Body, "\r\n")
	for i := 1; i < len(compiledTemplates); i++ {
		require.NotSame(t, compiledTemplates[0], compiledTemplates[i])
		require.NotSame(t, compiledTemplates[0].RequestsHTTP[0], compiledTemplates[i].RequestsHTTP[0])
		require.NotSame(t, compiledTemplates[0].RequestsHTTP[0].Options(), compiledTemplates[i].RequestsHTTP[0].Options())
	}
	require.NotSame(t, cachedTemplate.RequestsHTTP[0], compiledTemplates[0].RequestsHTTP[0])
}

func TestParseCompiledCacheAfterMetadataLoad(t *testing.T) {
	for _, word := range []string{"fixed-token", "{{randstr}}"} {
		t.Run(word, func(t *testing.T) {
			setup()
			path := filepath.Join(t.TempDir(), "metadata-cache.yaml")
			data := fmt.Sprintf(`id: metadata-cache
info:
  name: Metadata cache
  author: pdteam
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words: ["%s"]
`, word)
			require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
			parser := templates.NewParser()
			options := executerOpts.Copy()
			options.Parser = parser
			// The SDK loader reads metadata before requesting a compiled template.
			metadata, err := parser.ParseTemplate(path, options.Catalog)
			require.NoError(t, err)
			require.Nil(t, metadata.(*templates.Template).Options)
			first, err := templates.Parse(path, nil, options)
			require.NoError(t, err)
			cached, err := parser.CompiledCache().Get(path)
			require.NoError(t, err)
			require.NotNil(t, cached)
			require.NotNil(t, cached.Options)
			require.Nil(t, cached.Options.Output)
			require.Nil(t, cached.Options.RateLimiter)
			require.Nil(t, cached.Options.TemplateVerificationCallback)
			require.Nil(t, metadata.(*templates.Template).Options, "preparing execution must not mutate metadata")

			secondOptions := options.Copy()
			secondOptions.Output = testutils.NewMockOutputWriter(false)
			second, err := templates.Parse(path, nil, secondOptions)
			require.NoError(t, err)
			require.Same(t, secondOptions.Output, second.RequestsHTTP[0].Options().Output)
			require.NotSame(t, first.RequestsHTTP[0], second.RequestsHTTP[0])
			after, err := parser.CompiledCache().Get(path)
			require.NoError(t, err)
			require.Same(t, cached, after, "cache hit must not re-enter parseFromSource and replace the entry")
			require.Equal(t, first.RequestsHTTP[0].Matchers[0].Words, second.RequestsHTTP[0].Matchers[0].Words)
			if word == "{{randstr}}" {
				require.NotEqual(t, word, first.RequestsHTTP[0].Matchers[0].Words[0])
			}
		})
	}
}

func TestParseCompiledCacheDoesNotRetainExecutionOptions(t *testing.T) {
	setup()

	templatePath := "tests/match-1.yaml"
	parser := templates.NewParser()
	firstOptions := executerOpts.Copy()
	firstOptions.Parser = parser

	first, err := templates.Parse(templatePath, nil, firstOptions)
	require.NoError(t, err)
	require.NotNil(t, first.Executer)

	cached, err := parser.CompiledCache().Get(templatePath)
	require.NoError(t, err)
	require.NotNil(t, cached)
	require.Nil(t, cached.Executer)
	require.Nil(t, cached.CompiledWorkflow)
	require.Nil(t, cached.Options.TemplateVerificationCallback)
	require.Nil(t, cached.Options.Output)
	require.Nil(t, cached.Options.RateLimiter)
	require.Nil(t, cached.Options.Catalog)
	require.Nil(t, cached.Options.AuthProvider)
	require.Empty(t, cached.Options.TemporaryDirectory)
	require.Nil(t, cached.RequestsHTTP[0].Options())

	secondOutput := testutils.NewMockOutputWriter(firstOptions.Options.OmitTemplate)
	secondOptions := executerOpts.Copy()
	secondOptions.Parser = parser
	secondOptions.Output = secondOutput

	second, err := templates.Parse(templatePath, nil, secondOptions)
	require.NoError(t, err)
	require.NotNil(t, second.Executer)
	require.Same(t, secondOutput, second.RequestsHTTP[0].Options().Output)
	require.Same(t, secondOptions.RateLimiter, second.RequestsHTTP[0].Options().RateLimiter)
	require.NotSame(t, cached.RequestsHTTP[0], second.RequestsHTTP[0])
	require.NotSame(t, cached.RequestsHTTP[0].Options(), second.RequestsHTTP[0].Options())
}

func TestParseCompiledCacheClonesVariablesAndConstants(t *testing.T) {
	setup()

	templatePath := filepath.Join(t.TempDir(), "vars.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(`id: cache-vars

info:
  name: Cache Vars
  author: pdteam
  severity: info

variables:
  token: original

constants:
  flag: keep

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`), 0o600))

	parser := templates.NewParser()
	firstOptions := executerOpts.Copy()
	firstOptions.Parser = parser
	first, err := templates.Parse(templatePath, nil, firstOptions)
	require.NoError(t, err)
	require.Equal(t, "original", first.Options.Variables.GetAll()["token"])

	cached, err := parser.CompiledCache().Get(templatePath)
	require.NoError(t, err)
	require.NotNil(t, cached)
	require.Equal(t, "original", cached.Options.Variables.GetAll()["token"])
	require.Equal(t, "keep", cached.Options.Constants["flag"])

	first.Options.Variables.Set("token", "from-first")
	first.Options.Constants["flag"] = "from-first"
	require.Equal(t, "original", cached.Options.Variables.GetAll()["token"])
	require.Equal(t, "keep", cached.Options.Constants["flag"])

	secondOptions := executerOpts.Copy()
	secondOptions.Parser = parser
	second, err := templates.Parse(templatePath, nil, secondOptions)
	require.NoError(t, err)
	second.Options.Variables.Set("token", "mutated")
	second.Options.Constants["flag"] = "mutated"
	require.Equal(t, "original", cached.Options.Variables.GetAll()["token"])
	require.Equal(t, "keep", cached.Options.Constants["flag"])
	require.Equal(t, "from-first", first.Options.Variables.GetAll()["token"])
	require.Equal(t, "from-first", first.Options.Constants["flag"])
	require.Equal(t, "mutated", second.Options.Variables.GetAll()["token"])
	require.Equal(t, "mutated", second.Options.Constants["flag"])
}

func TestParseCompiledCacheRebuildsWorkflowPerExecution(t *testing.T) {
	setup()

	templatePath := "tests/workflow.yaml"
	parser := templates.NewParser()
	firstOptions := executerOpts.Copy()
	firstOptions.Parser = parser

	first, err := templates.Parse(templatePath, nil, firstOptions)
	require.NoError(t, err)
	require.NotNil(t, first.CompiledWorkflow)

	cached, err := parser.CompiledCache().Get(templatePath)
	require.NoError(t, err)
	require.NotNil(t, cached)
	require.Nil(t, cached.CompiledWorkflow)
	require.Nil(t, cached.Options.WorkflowLoader)

	secondOptions := executerOpts.Copy()
	secondOptions.Parser = parser
	second, err := templates.Parse(templatePath, nil, secondOptions)
	require.NoError(t, err)
	require.NotNil(t, second.CompiledWorkflow)
	require.NotSame(t, first.CompiledWorkflow, second.CompiledWorkflow)
	require.NotSame(t, first.CompiledWorkflow.Workflows[0], second.CompiledWorkflow.Workflows[0])
	require.Same(t, secondOptions.RateLimiter, second.CompiledWorkflow.Workflows[0].Executers[0].Options.RateLimiter)
}

func TestParseCompiledCacheRebuildsWorkflowMatchersPerExecution(t *testing.T) {
	setup()

	dir := t.TempDir()
	firstTemplatePath := filepath.Join(dir, "first.yaml")
	err := os.WriteFile(firstTemplatePath, []byte(`id: workflow-matcher-first

info:
  name: Workflow Matcher First
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - first
`), 0o600)
	require.NoError(t, err)

	secondTemplatePath := filepath.Join(dir, "second.yaml")
	err = os.WriteFile(secondTemplatePath, []byte(`id: workflow-matcher-second

info:
  name: Workflow Matcher Second
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - second
`), 0o600)
	require.NoError(t, err)

	workflowPath := filepath.Join(dir, "workflow.yaml")
	err = os.WriteFile(workflowPath, []byte(fmt.Sprintf(`id: workflow-matcher-cache

info:
  name: Workflow Matcher Cache
  author: pdteam
  severity: info

workflows:
  - template: %q
    matchers:
      - name: first
        subtemplates:
          - template: %q
`, firstTemplatePath, secondTemplatePath)), 0o600)
	require.NoError(t, err)

	parser := templates.NewParser()
	firstOptions := executerOpts.Copy()
	firstOptions.Parser = parser

	first, err := templates.Parse(workflowPath, nil, firstOptions)
	require.NoError(t, err)
	require.NotNil(t, first.CompiledWorkflow)

	cached, err := parser.CompiledCache().Get(workflowPath)
	require.NoError(t, err)
	require.NotNil(t, cached)
	require.Empty(t, cached.Workflow.Workflows[0].Matchers[0].Subtemplates[0].Executers)

	secondOptions := executerOpts.Copy()
	secondOptions.Parser = parser
	second, err := templates.Parse(workflowPath, nil, secondOptions)
	require.NoError(t, err)
	require.NotNil(t, second.CompiledWorkflow)
	require.NotSame(t, first.CompiledWorkflow.Workflows[0].Matchers[0], second.CompiledWorkflow.Workflows[0].Matchers[0])
	require.Len(t, second.CompiledWorkflow.Workflows[0].Matchers[0].Subtemplates[0].Executers, 1)
}

func TestParseCompiledCacheRegistersGlobalMatcherFromCache(t *testing.T) {
	setup()

	parser := templates.NewParser()
	templatePath := "tests/global-matcher.yaml"
	firstOptions := executerOpts.Copy()
	firstOptions.Options = firstOptions.Options.Copy()
	firstOptions.Parser = parser
	firstOptions.Options.EnableGlobalMatchersTemplates = false

	first, err := templates.Parse(templatePath, nil, firstOptions)
	require.NoError(t, err)
	require.NotNil(t, first)

	secondOptions := executerOpts.Copy()
	secondOptions.Options = secondOptions.Options.Copy()
	secondOptions.Parser = parser
	secondOptions.Options.EnableGlobalMatchersTemplates = true
	secondOptions.GlobalMatchers = globalmatchers.New()

	second, err := templates.Parse(templatePath, nil, secondOptions)
	require.NoError(t, err)
	require.Nil(t, second)

	var matched bool
	secondOptions.GlobalMatchers.Match(
		output.InternalEvent{
			"body":          "test",
			"template-id":   "origin",
			"template-info": model.Info{},
			"template-path": "origin.yaml",
		},
		func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
			body, _ := data["body"].(string)
			return matcher.MatchWords(body, data)
		},
		nil,
		false,
		func(_ output.InternalEvent, result *operators.Result) {
			matched = result != nil
		},
	)
	require.True(t, matched)
}

func TestParseCompiledCacheIgnoresEntryWithoutOptions(t *testing.T) {
	setup()

	parser := templates.NewParser()
	templatePath := "tests/match-1.yaml"
	parser.CompiledCache().StoreWithoutRaw(templatePath, &templates.Template{ID: "invalid-cache-entry"}, nil)

	options := executerOpts.Copy()
	options.Parser = parser

	parsed, err := templates.Parse(templatePath, nil, options)
	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.Equal(t, "basic-get", parsed.ID)
}

func TestParseSharedTemplatePreservesRuntimePreprocessing(t *testing.T) {
	var sourceReads int
	templateSource := `id: shared-preprocessed-template

info:
  name: Shared preprocessed template
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/{{randstr}}"
`
	server := httptest.NewServer(netHttp.HandlerFunc(func(w netHttp.ResponseWriter, _ *netHttp.Request) {
		sourceReads++
		_, _ = w.Write([]byte(templateSource))
	}))
	t.Cleanup(server.Close)

	setup()
	templatePath := server.URL + "/template.yaml"
	sharedParser := templates.NewParser()
	_, err := sharedParser.ParseTemplate(templatePath, executerOpts.Catalog)
	require.NoError(t, err)

	compiledPaths := make([]string, 2)
	for i := range compiledPaths {
		engineOptions := executerOpts.Copy()
		engineOptions.Parser = templates.NewParserWithParsedCache(sharedParser.Cache())
		compiled, parseErr := templates.Parse(templatePath, nil, engineOptions)
		require.NoError(t, parseErr)
		compiledPaths[i] = compiled.RequestsHTTP[0].Path[0]
		require.NotContains(t, compiledPaths[i], "{{randstr}}")
	}

	require.Equal(t, 1, sourceReads)
	require.NotEqual(t, compiledPaths[0], compiledPaths[1])
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

// TestParseConcurrentSharedParserIsRaceFree covers the loader path, which parses
// templates concurrently through a single shared parser.
func TestParseConcurrentSharedParserIsRaceFree(t *testing.T) {
	setup()

	dir := t.TempDir()
	paths := make([]string, 0, 16)
	for i := 0; i < 16; i++ {
		path := filepath.Join(dir, fmt.Sprintf("concurrent-%d.yaml", i))
		require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf(`id: concurrent-%d
info:
  name: Concurrent %d
  author: pdteam
  severity: info

variables:
  token: original

http:
  - method: GET
    path:
      - "{{BaseURL}}"`, i, i)), 0o600))
		paths = append(paths, path)
	}

	parser := templates.NewParser()

	var wg sync.WaitGroup
	for round := 0; round < 3; round++ {
		for _, path := range paths {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				options := executerOpts.Copy()
				options.Parser = parser
				parsed, err := templates.Parse(path, nil, options)
				require.NoError(t, err)
				require.NotNil(t, parsed)
			}(path)
		}
	}
	wg.Wait()
}

// A cache hit rebuilds the template's options from the caller's, so every option
// derived from the template itself has to be carried back over. Anything that
// compiles an executer from those options reads Flow; without it, every step
// runs regardless of the flow expression and the last step's matcher alone
// decides whether the template reports.
func TestParseCompiledCachePreservesTemplateDerivedOptions(t *testing.T) {
	setup()

	path := filepath.Join(t.TempDir(), "flow-cache.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`id: flow-cache
info:
  name: Flow cache
  author: pdteam
  severity: info
stop-at-first-match: true
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}/precondition"
    matchers:
      - type: status
        status: [200]
        internal: true
  - method: GET
    path:
      - "{{BaseURL}}/check"
    matchers:
      - type: status
        status: [404]
`), 0o600))

	first, second := parseTwiceFromCompiledCache(t, path)

	require.NotEmpty(t, first.Options.Flow)
	require.Equal(t, first.Options.Flow, second.Options.Flow)
	require.True(t, second.Options.StopAtFirstMatch)
	require.NotZero(t, second.Options.ProtocolType)
	require.Equal(t, first.Options.ProtocolType, second.Options.ProtocolType)
	// A flow template orders its own steps, so it is never multi-protocol.
	require.False(t, second.Options.IsMultiProtocol)
}

// IsMultiProtocol is set while compiling the template's requests, and Cluster
// reads it to keep multi-protocol templates out of clusters.
func TestParseCompiledCachePreservesMultiProtocol(t *testing.T) {
	setup()

	first, second := parseTwiceFromCompiledCache(t, "tests/multiproto.yaml")

	require.True(t, first.Options.IsMultiProtocol)
	require.True(t, second.Options.IsMultiProtocol)
}

// Offline HTTP keeps the matcher list on Options.Operators. A cache hit rebuilds
// options from the caller, so that list has to be copied back too.
func TestParseCompiledCachePreservesOfflineOperators(t *testing.T) {
	setup()

	previous := executerOpts.Options.OfflineHTTP
	executerOpts.Options.OfflineHTTP = true
	t.Cleanup(func() {
		executerOpts.Options.OfflineHTTP = previous
	})

	first, second := parseTwiceFromCompiledCache(t, "tests/match-1.yaml")

	require.NotEmpty(t, first.Options.Operators)
	require.Equal(t, len(first.Options.Operators), len(second.Options.Operators))
}

// parseTwiceFromCompiledCache parses path twice on one parser and asserts the
// second parse was served from the compiled cache.
func parseTwiceFromCompiledCache(t *testing.T, path string) (first, second *templates.Template) {
	t.Helper()

	parser := templates.NewParser()
	options := executerOpts.Copy()
	options.Parser = parser

	first, err := templates.Parse(path, nil, options)
	require.NoError(t, err)
	cached, err := parser.CompiledCache().Get(path)
	require.NoError(t, err)
	require.NotNil(t, cached)

	second, err = templates.Parse(path, nil, options.Copy())
	require.NoError(t, err)
	after, err := parser.CompiledCache().Get(path)
	require.NoError(t, err)
	require.Same(t, cached, after, "second parse must be served from the compiled cache")

	return first, second
}
