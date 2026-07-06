package loader

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
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
