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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
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

func TestParseTemplateExecutesJavascriptInitAfterVerification(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = "parse-verified-javascript-init"
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

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
	executerOptions.TemplateVerificationCallback = func(templatePath string) *protocols.TemplateVerification {
		require.Equal(t, executerOptions.TemplatePath, templatePath)
		return trustedVerificationForTest(templateSource)
	}

	template, err := templates.ParseTemplateFromReader(strings.NewReader(templateSource), nil, executerOptions)
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
	executerOptions.TemplateVerificationCallback = func(templatePath string) *protocols.TemplateVerification {
		require.Equal(t, executerOptions.TemplatePath, templatePath)
		return trustedVerificationForTest(templateSource)
	}

	template, err := templates.ParseTemplateFromReader(strings.NewReader(templateSource), nil, executerOptions)
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

func TestParseTemplateVerificationUsesLoadedImportContents(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	loadedCode := `Export("loaded-import")`
	diskCode := `Export("disk-import")`
	importPath := filepath.Join(t.TempDir(), "import.js")
	require.NoError(t, os.WriteFile(importPath, []byte(diskCode), 0o600))
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
	executerOptions.TemplateVerificationCallback = func(templatePath string) *protocols.TemplateVerification {
		require.Equal(t, executerOptions.TemplatePath, templatePath)
		return trustedVerificationForTest(templateSource, loadedCode)
	}

	template, err := templates.ParseTemplateFromReader(strings.NewReader(templateSource), nil, executerOptions)
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

javascript:
  - init: |
      set("init-status", "executed")
    code: |
      Export("revoked-verifier")
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
	require.NotContains(t, template.RequestsJavascript[0].Args, "init-status")
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
	require.NoError(t, os.WriteFile(templatePath, []byte(templateSource), 0o600))

	executerOptions := testutils.NewMockExecuterOptions(options, nil)
	executerOptions.Parser = templates.NewParser()
	executerOptions.TemplateVerificationCallback = func(path string) *protocols.TemplateVerification {
		require.Equal(t, templatePath, path)
		return trustedVerificationForTest(templateSource)
	}

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
		engineOptions.TemplateVerificationCallback = func(string) *protocols.TemplateVerification {
			return trustedVerificationForTest(templateSource)
		}
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			compiledTemplates[i], parseErrors[i] = templates.Parse(templatePath, nil, engineOptions)
		}()
	}
	waitGroup.Wait()

	for i := range compiledTemplates {
		require.NoError(t, parseErrors[i])
		require.True(t, compiledTemplates[i].Verified)
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
	require.Nil(t, cached.RequestsHTTP[0].Options().Output)
	require.Nil(t, cached.RequestsHTTP[0].Options().RateLimiter)

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
