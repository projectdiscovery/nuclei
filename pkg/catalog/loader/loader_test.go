package loader

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	metadataindex "github.com/projectdiscovery/nuclei/v3/pkg/catalog/index"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
	"github.com/stretchr/testify/require"
)

func TestLoadTemplates(t *testing.T) {
	catalog := disk.NewCatalog("")

	store, err := New(&Config{
		Templates: []string{"cves/CVE-2021-21315.yaml"},
		Catalog:   catalog,
	})
	require.Nil(t, err, "could not load templates")
	require.Equal(t, []string{"cves/CVE-2021-21315.yaml"}, store.finalTemplates, "could not get correct templates")

	templatesDirectory := "/test"
	config.DefaultConfig.TemplatesDirectory = templatesDirectory
	t.Run("blank", func(t *testing.T) {
		store, err := New(&Config{
			Catalog: catalog,
		})
		require.Nil(t, err, "could not load templates")
		require.Equal(t, []string{templatesDirectory}, store.finalTemplates, "could not get correct templates")
	})
	t.Run("only-tags", func(t *testing.T) {
		store, err := New(&Config{
			Tags:    []string{"cves"},
			Catalog: catalog,
		})
		require.Nil(t, err, "could not load templates")
		require.Equal(t, []string{templatesDirectory}, store.finalTemplates, "could not get correct templates")
	})
	t.Run("tags-with-path", func(t *testing.T) {
		store, err := New(&Config{
			Tags:    []string{"cves"},
			Catalog: catalog,
		})
		require.Nil(t, err, "could not load templates")
		require.Equal(t, []string{templatesDirectory}, store.finalTemplates, "could not get correct templates")
	})
}

func TestNewUsesConfiguredMetadataIndex(t *testing.T) {
	indexDir := t.TempDir()
	metadataIndex, err := metadataindex.NewIndex(indexDir)
	require.NoError(t, err)

	store, err := New(&Config{
		Catalog:       disk.NewCatalog(""),
		Logger:        &gologger.Logger{},
		MetadataIndex: metadataIndex,
	})
	require.NoError(t, err)
	require.Same(t, metadataIndex, store.metadataIndex)

	metadataIndex.Set("/tmp/shared.yaml", &metadataindex.Metadata{ID: "shared"})
	store.saveMetadataIndexOnce()
	_, err = os.Stat(filepath.Join(indexDir, metadataindex.IndexFileName))
	require.ErrorIs(t, err, os.ErrNotExist, "borrowed index persistence belongs to its owner")
}

func TestCacheValidatedMetadataReturnsReplacement(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "replacement.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte("id: replacement"), 0o600))
	info, err := os.Stat(templatePath)
	require.NoError(t, err)

	metadataIndex, err := metadataindex.NewIndex(t.TempDir())
	require.NoError(t, err)
	metadataIndex.Set(templatePath, &metadataindex.Metadata{
		ID:       "old",
		FilePath: templatePath,
		ModTime:  info.ModTime(),
	})
	store := &Store{
		config:        &Config{ExecutorOptions: &protocols.ExecutorOptions{Parser: templates.NewParser()}},
		metadataIndex: metadataIndex,
	}

	metadata := store.cacheValidatedMetadata(templatePath, &templates.Template{ID: "replacement"})
	require.Equal(t, "replacement", metadata.ID)
	cached, found := metadataIndex.Get(templatePath)
	require.True(t, found)
	require.Equal(t, "replacement", cached.ID)
}

func TestLoadTemplatesOnlyMetadataLogsCachedTemplateParseErrors(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "invalid.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte("id: invalid\ninfo: [\n"), 0o600))
	info, err := os.Stat(templatePath)
	require.NoError(t, err)

	metadataIndex, err := metadataindex.NewIndex(t.TempDir())
	require.NoError(t, err)
	metadataIndex.Set(templatePath, &metadataindex.Metadata{
		ID:         "invalid",
		FilePath:   templatePath,
		ModTime:    info.ModTime(),
		Validation: metadataindex.ValidationStrict,
	})

	var output bytes.Buffer
	logger := &gologger.Logger{}
	logger.SetFormatter(formatter.NewCLI(false))
	logger.SetWriter(&utils.CaptureWriter{Buffer: &output})
	logger.SetMaxLevel(levels.LevelDebug)

	options := testutils.DefaultOptions.Copy()
	options.Logger = logger
	options.Templates = []string{templatePath}
	catalog := disk.NewCatalog("")
	executerOpts := testutils.NewMockExecuterOptions(options, nil)
	executerOpts.Catalog = catalog
	executerOpts.Parser = templates.NewParser()
	executerOpts.Logger = logger

	loaderConfig := NewConfig(options, catalog, executerOpts)
	loaderConfig.MetadataIndex = metadataIndex
	store, err := New(loaderConfig)
	require.NoError(t, err)

	output.Reset()
	require.NoError(t, store.LoadTemplatesOnlyMetadata())
	require.Contains(t, output.String(), "Could not load template")
}

func TestValidateTemplatesRejectsRuntimeCompilationError(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "invalid-regex-group.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(`id: invalid-regex-group

info:
  name: Invalid Regex Group
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    extractors:
      - type: regex
        group: -1
        regex:
          - "(a)(b)"
`), 0o600))

	options := testutils.DefaultOptions.Copy()
	var output bytes.Buffer
	logger := &gologger.Logger{}
	logger.SetFormatter(formatter.NewCLI(false))
	logger.SetWriter(&utils.CaptureWriter{Buffer: &output})
	logger.SetMaxLevel(levels.LevelDebug)
	options.Logger = logger
	options.ExecutionId = "loader-invalid-regex-group"
	options.Templates = []string{templatePath}
	options.Validate = true
	options.TemplateLoadingConcurrency = 1
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	catalog := disk.NewCatalog("")
	executerOpts := testutils.NewMockExecuterOptions(options, nil)
	executerOpts.Catalog = catalog
	parser := templates.NewParser()
	parser.ShouldValidate = true
	executerOpts.Parser = parser
	executerOpts.Logger = options.Logger

	workflowLoader, err := workflow.NewLoader(executerOpts)
	require.NoError(t, err)
	executerOpts.WorkflowLoader = workflowLoader

	store, err := New(NewConfig(options, catalog, executerOpts))
	require.NoError(t, err)
	require.Error(t, store.ValidateTemplates())
	require.Contains(t, output.String(), "regex extractor group must be >= 0")
}

func TestRemoteTemplates(t *testing.T) {
	catalog := disk.NewCatalog("")

	var nilStringSlice []string
	type args struct {
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		want    *Store
		wantErr bool
	}{
		{
			name: "remote-templates-positive",
			args: args{
				config: &Config{
					TemplateURLs:             []string{"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/technologies/tech-detect.yaml"},
					RemoteTemplateDomainList: []string{"localhost", "raw.githubusercontent.com"},
					Catalog:                  catalog,
				},
			},
			want: &Store{
				finalTemplates: []string{"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/technologies/tech-detect.yaml"},
			},
			wantErr: false,
		},
		{
			name: "remote-templates-negative",
			args: args{
				config: &Config{
					TemplateURLs:             []string{"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/technologies/tech-detect.yaml"},
					RemoteTemplateDomainList: []string{"localhost"},
					Catalog:                  catalog,
				},
			},
			want: &Store{
				finalTemplates: nilStringSlice,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.finalTemplates, tt.want.finalTemplates) {
				t.Errorf("New() = %v, want %v", got.finalTemplates, tt.want.finalTemplates)
			}
		})
	}
}

func TestLoadTemplatesRecordsUnsignedCodeTemplateOnlyAsCodeSkip(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "unsigned-code.yaml")
	err := os.WriteFile(templatePath, []byte(`id: unsigned-code-template

info:
  name: Unsigned Code Template
  author: pdteam
  severity: info

code:
  - engine:
      - sh
    source: |
      echo unsigned-code-template
`), 0o600)
	require.NoError(t, err)

	options := testutils.DefaultOptions.Copy()
	options.Logger = &gologger.Logger{}
	options.ExecutionId = "loader-unsigned-code-template"
	options.EnableCodeTemplates = false
	options.DisableUnsignedTemplates = false
	options.TemplateLoadingConcurrency = 1
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	catalog := disk.NewCatalog("")
	executerOpts := testutils.NewMockExecuterOptions(options, nil)
	executerOpts.Catalog = catalog
	executerOpts.Parser = templates.NewParser()
	executerOpts.Logger = options.Logger

	workflowLoader, err := workflow.NewLoader(executerOpts)
	require.NoError(t, err)
	executerOpts.WorkflowLoader = workflowLoader

	store, err := New(NewConfig(options, catalog, executerOpts))
	require.NoError(t, err)

	initialUnverifiedCode := stats.GetValue(templates.SkippedUnverifiedCodeTemplateStats)
	initialUnverified := stats.GetValue(templates.SkippedUnverifiedTemplateStats)

	loaded, err := store.LoadTemplates([]string{templatePath})
	require.NoError(t, err)
	require.Empty(t, loaded)
	require.Equal(t, initialUnverifiedCode+1, stats.GetValue(templates.SkippedUnverifiedCodeTemplateStats))
	require.Equal(t, initialUnverified, stats.GetValue(templates.SkippedUnverifiedTemplateStats))
}

func TestLoadTemplatesSkipsMetadataParseForCachedIndexEntry(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "cached-index.yaml")
	err := os.WriteFile(templatePath, []byte(`id: cached-index-template

info:
  name: Cached Index Template
  author: pdteam
  severity: info
  tags: cached

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`), 0o600)
	require.NoError(t, err)
	fileInfo, err := os.Stat(templatePath)
	require.NoError(t, err)

	metadataIndex, err := metadataindex.NewIndex(t.TempDir())
	require.NoError(t, err)
	metadataIndex.Set(templatePath, &metadataindex.Metadata{
		ID:           "cached-index-template",
		FilePath:     templatePath,
		ModTime:      fileInfo.ModTime(),
		Name:         "Cached Index Template",
		Authors:      []string{"pdteam"},
		Tags:         []string{"cached"},
		Severity:     "info",
		ProtocolType: "http",
		Validation:   metadataindex.ValidationStrict,
	})

	options := testutils.DefaultOptions.Copy()
	options.Logger = &gologger.Logger{}
	options.ExecutionId = "loader-cached-index-template"
	options.DisableUnsignedTemplates = false
	options.TemplateLoadingConcurrency = 1
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	catalog := disk.NewCatalog("")
	parser := templates.NewParser()
	executerOpts := testutils.NewMockExecuterOptions(options, nil)
	executerOpts.Catalog = catalog
	executerOpts.Parser = parser
	executerOpts.Logger = options.Logger

	workflowLoader, err := workflow.NewLoader(executerOpts)
	require.NoError(t, err)
	executerOpts.WorkflowLoader = workflowLoader

	loaderConfig := NewConfig(options, catalog, executerOpts)
	loaderConfig.MetadataIndex = metadataIndex
	store, err := New(loaderConfig)
	require.NoError(t, err)

	loaded, err := store.LoadTemplates([]string{templatePath})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	require.Equal(t, 0, parser.ParsedCount(), "valid index metadata should avoid the filtering parse")
	require.Equal(t, 1, parser.CompiledCount())

	options.IncludeConditions = []string{`id == "does-not-match"`}
	loaderConfig = NewConfig(options, catalog, executerOpts)
	loaderConfig.MetadataIndex = metadataIndex
	store, err = New(loaderConfig)
	require.NoError(t, err)

	loaded, err = store.LoadTemplates([]string{templatePath})
	require.NoError(t, err)
	require.Empty(t, loaded)
	require.Equal(t, 1, parser.ParsedCount(), "advanced conditions still require the parsed template")
}

func TestLoadTemplatesRevalidatesLaxMetadataInStrictMode(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "lax-metadata.yaml")
	err := os.WriteFile(templatePath, []byte(`id: lax-metadata-template

info:
  name: Lax Metadata Template
  author: pdteam
  severity: info

unknown-field: accepted-only-in-lax-mode

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`), 0o600)
	require.NoError(t, err)

	metadataIndex, err := metadataindex.NewIndex(t.TempDir())
	require.NoError(t, err)
	catalog := disk.NewCatalog("")

	newStore := func(executionID string, noStrictSyntax bool) *Store {
		options := testutils.DefaultOptions.Copy()
		options.Logger = &gologger.Logger{}
		options.ExecutionId = executionID
		options.DisableUnsignedTemplates = false
		options.TemplateLoadingConcurrency = 1
		options.NoStrictSyntax = noStrictSyntax
		testutils.Init(options)
		t.Cleanup(func() {
			testutils.Cleanup(options)
		})

		parser := templates.NewParser()
		parser.NoStrictSyntax = noStrictSyntax
		executerOpts := testutils.NewMockExecuterOptions(options, nil)
		executerOpts.Catalog = catalog
		executerOpts.Parser = parser
		executerOpts.Logger = options.Logger

		workflowLoader, err := workflow.NewLoader(executerOpts)
		require.NoError(t, err)
		executerOpts.WorkflowLoader = workflowLoader

		loaderConfig := NewConfig(options, catalog, executerOpts)
		loaderConfig.MetadataIndex = metadataIndex
		store, err := New(loaderConfig)
		require.NoError(t, err)
		return store
	}

	laxStore := newStore("loader-lax-metadata", true)
	loaded, err := laxStore.LoadTemplates([]string{templatePath})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	require.True(t, metadataIndex.Has(templatePath))

	strictStore := newStore("loader-strict-metadata", false)
	loaded, err = strictStore.LoadTemplates([]string{templatePath})
	require.NoError(t, err)
	require.Empty(t, loaded, "strict loading must not trust metadata validated only in lax mode")
}

func loadSingleTemplateForTest(t *testing.T, templatePath, executionID string) []*templates.Template {
	t.Helper()

	options := testutils.DefaultOptions.Copy()
	options.Logger = &gologger.Logger{}
	options.ExecutionId = executionID
	options.DisableUnsignedTemplates = false
	options.TemplateLoadingConcurrency = 1
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	catalog := disk.NewCatalog("")
	executerOpts := testutils.NewMockExecuterOptions(options, nil)
	executerOpts.Catalog = catalog
	executerOpts.Parser = templates.NewParser()
	executerOpts.Logger = options.Logger

	workflowLoader, err := workflow.NewLoader(executerOpts)
	require.NoError(t, err)
	executerOpts.WorkflowLoader = workflowLoader

	store, err := New(NewConfig(options, catalog, executerOpts))
	require.NoError(t, err)

	loaded, err := store.LoadTemplates([]string{templatePath})
	require.NoError(t, err)
	return loaded
}

func TestLoadTemplatesRecordsUnsignedJavascriptTemplateOnlyAsJavascriptSkip(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "unsigned-javascript.yaml")
	err := os.WriteFile(templatePath, []byte(`id: unsigned-javascript-template

info:
  name: Unsigned Javascript Template
  author: pdteam
  severity: info

javascript:
  - code: |
      Export("unsigned-javascript-template")
`), 0o600)
	require.NoError(t, err)

	initialUnverifiedJavascript := stats.GetValue(templates.SkippedUnverifiedJavascriptTemplateStats)
	initialUnverified := stats.GetValue(templates.SkippedUnverifiedTemplateStats)

	loaded := loadSingleTemplateForTest(t, templatePath, "loader-unsigned-javascript-template")
	require.Empty(t, loaded)
	require.Equal(t, initialUnverifiedJavascript+1, stats.GetValue(templates.SkippedUnverifiedJavascriptTemplateStats))
	require.Equal(t, initialUnverified, stats.GetValue(templates.SkippedUnverifiedTemplateStats))
}

func TestLoadTemplatesTreatsMixedTemplateWithJavascriptAsJavascriptSensitive(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "mixed-javascript.yaml")
	err := os.WriteFile(templatePath, []byte(`id: mixed-javascript-template

info:
  name: Mixed Javascript Template
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - mixed-javascript-template

javascript:
  - code: |
      Export("mixed-javascript-template")
`), 0o600)
	require.NoError(t, err)

	initialUnverifiedJavascript := stats.GetValue(templates.SkippedUnverifiedJavascriptTemplateStats)

	loaded := loadSingleTemplateForTest(t, templatePath, "loader-mixed-javascript-template")
	require.Empty(t, loaded)
	require.Equal(t, initialUnverifiedJavascript+1, stats.GetValue(templates.SkippedUnverifiedJavascriptTemplateStats))
}

func TestLoadTemplatesAllowsUnsignedFlowTemplateWithoutJavascriptProtocol(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "flow-only.yaml")
	err := os.WriteFile(templatePath, []byte(`id: unsigned-flow-template

info:
  name: Unsigned Flow Template
  author: pdteam
  severity: info

flow: http(1)

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - unsigned-flow-template
`), 0o600)
	require.NoError(t, err)

	initialUnverifiedJavascript := stats.GetValue(templates.SkippedUnverifiedJavascriptTemplateStats)

	loaded := loadSingleTemplateForTest(t, templatePath, "loader-unsigned-flow-template")
	require.Len(t, loaded, 1)
	require.Equal(t, "unsigned-flow-template", loaded[0].ID)
	require.Equal(t, initialUnverifiedJavascript, stats.GetValue(templates.SkippedUnverifiedJavascriptTemplateStats))
}

func TestLoadTemplatesDoesNotRequireGlobalMatchersFlagToLoadTemplate(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "global-matchers.yaml")
	err := os.WriteFile(templatePath, []byte(`id: global-matchers-template

info:
  name: Global Matchers Template
  author: pdteam
  severity: info

http:
  - global-matchers: true
    matchers:
      - type: word
        words:
          - global-matchers-template
`), 0o600)
	require.NoError(t, err)

	options := testutils.DefaultOptions.Copy()
	options.Logger = &gologger.Logger{}
	options.ExecutionId = "loader-global-matchers-template"
	options.EnableGlobalMatchersTemplates = false
	options.TemplateLoadingConcurrency = 1
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	catalog := disk.NewCatalog("")
	executerOpts := testutils.NewMockExecuterOptions(options, nil)
	executerOpts.Catalog = catalog
	executerOpts.Parser = templates.NewParser()
	executerOpts.Logger = options.Logger

	workflowLoader, err := workflow.NewLoader(executerOpts)
	require.NoError(t, err)
	executerOpts.WorkflowLoader = workflowLoader

	store, err := New(NewConfig(options, catalog, executerOpts))
	require.NoError(t, err)

	loaded, err := store.LoadTemplates([]string{templatePath})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	require.Equal(t, "global-matchers-template", loaded[0].ID)
}
