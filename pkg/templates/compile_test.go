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
