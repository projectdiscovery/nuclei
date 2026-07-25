package runner

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	inputtypes "github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

type targetFilterTestProvider struct {
	inputs []*contextargs.MetaInput
}

func (p *targetFilterTestProvider) Count() int64 {
	return int64(len(p.inputs))
}

func (p *targetFilterTestProvider) Iterate(callback func(*contextargs.MetaInput) bool) {
	for _, input := range p.inputs {
		if !callback(input.Clone()) {
			return
		}
	}
}

func (*targetFilterTestProvider) Set(string, string) {}
func (*targetFilterTestProvider) SetWithProbe(string, string, inputtypes.InputLivenessProbe) error {
	return nil
}
func (*targetFilterTestProvider) SetWithExclusions(string, string) error { return nil }
func (*targetFilterTestProvider) InputType() string                      { return "TargetInputProvider" }
func (*targetFilterTestProvider) Close()                                 {}
func (p *targetFilterTestProvider) TargetInputs() []*contextargs.MetaInput {
	return p.inputs
}

type targetFilterTestCatalog struct{}

func (targetFilterTestCatalog) OpenFile(string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func (targetFilterTestCatalog) GetTemplatePath(target string) ([]string, error) {
	if target == "" {
		return nil, fmt.Errorf("empty selector")
	}
	return []string{"/resolved/" + strings.TrimPrefix(target, "/")}, nil
}

func (catalog targetFilterTestCatalog) GetTemplatesPath(definitions []string) ([]string, map[string]error) {
	var paths []string
	errorsBySelector := make(map[string]error)
	for _, definition := range definitions {
		resolved, err := catalog.GetTemplatePath(definition)
		if err != nil {
			errorsBySelector[definition] = err
			continue
		}
		paths = append(paths, resolved...)
	}
	return paths, errorsBySelector
}

func (targetFilterTestCatalog) ResolvePath(templateName, _ string) (string, error) {
	return "/resolved/" + strings.TrimPrefix(templateName, "/"), nil
}

type countingTargetFilterTestCatalog struct {
	targetFilterTestCatalog
	calls map[string]int
}

func (c *countingTargetFilterTestCatalog) GetTemplatesPath(definitions []string) ([]string, map[string]error) {
	c.calls[canonicalTargetSelectors(definitions)]++
	return c.targetFilterTestCatalog.GetTemplatesPath(definitions)
}

func TestPrepareTargetFiltersKeepsDefaultAndCustomTemplateUnion(t *testing.T) {
	inputs := []*contextargs.MetaInput{
		{
			Input: "https://default.example",
			TargetFilter: &contextargs.TargetFilter{
				HasTemplates: true,
				Templates:    []string{},
				SourceLine:   1,
			},
		},
		{
			Input: "https://custom.example",
			TargetFilter: &contextargs.TargetFilter{
				HasTemplates: true,
				Templates:    []string{"custom.yaml"},
				SourceLine:   2,
			},
		},
	}
	runner := &Runner{
		options:       &types.Options{},
		catalog:       targetFilterTestCatalog{},
		inputProvider: &targetFilterTestProvider{inputs: inputs},
	}
	loaderConfig := &loader.Config{}

	require.NoError(t, runner.prepareTargetFilters(loaderConfig))
	require.Contains(t, loaderConfig.Templates, config.DefaultConfig.TemplatesDirectory)
	require.Contains(t, loaderConfig.Templates, "/resolved/custom.yaml")

	defaultTemplatePath := "/resolved/" + strings.TrimPrefix(config.DefaultConfig.TemplatesDirectory, "/")
	require.True(t, inputs[0].TargetFilter.MatchesTemplate(defaultTemplatePath, nil, severity.Undefined, false))
	require.False(t, inputs[0].TargetFilter.MatchesTemplate("/resolved/custom.yaml", nil, severity.Undefined, false))
	require.False(t, inputs[1].TargetFilter.MatchesTemplate(defaultTemplatePath, nil, severity.Undefined, false))
	require.True(t, inputs[1].TargetFilter.MatchesTemplate("/resolved/custom.yaml", nil, severity.Undefined, false))
}

func TestPrepareTargetFiltersCachesSharedTemplateSelectors(t *testing.T) {
	catalog := &countingTargetFilterTestCatalog{calls: make(map[string]int)}
	inputs := []*contextargs.MetaInput{
		{
			Input: "https://one.example",
			TargetFilter: &contextargs.TargetFilter{
				HasTemplates: true,
				Templates:    []string{"shared.yaml"},
				SourceLine:   1,
			},
		},
		{
			Input: "https://two.example",
			TargetFilter: &contextargs.TargetFilter{
				HasTemplates: true,
				Templates:    []string{"shared.yaml"},
				SourceLine:   2,
			},
		},
	}
	runner := &Runner{
		options:       &types.Options{},
		catalog:       catalog,
		inputProvider: &targetFilterTestProvider{inputs: inputs},
	}

	require.NoError(t, runner.prepareTargetFilters(&loader.Config{}))
	require.Equal(t, 1, catalog.calls[canonicalTargetSelectors([]string{"shared.yaml"})])
	require.True(t, inputs[0].TargetFilter.MatchesTemplate("/resolved/shared.yaml", nil, severity.Undefined, false))
	require.True(t, inputs[1].TargetFilter.MatchesTemplate("/resolved/shared.yaml", nil, severity.Undefined, false))
}

func TestPrepareTargetFiltersPreservesInheritanceAndForcedIncludes(t *testing.T) {
	filter := &contextargs.TargetFilter{}
	options := &types.Options{
		Severities: severity.Severities{severity.High},
	}
	options.Tags = append(options.Tags, "apache")
	options.ExcludeTags = append(options.ExcludeTags, "deprecated")
	options.IncludeTemplates = append(options.IncludeTemplates, "forced.yaml")

	runner := &Runner{
		options: options,
		catalog: targetFilterTestCatalog{},
		inputProvider: &targetFilterTestProvider{inputs: []*contextargs.MetaInput{
			{Input: "https://example.com", TargetFilter: filter},
			{
				Input: "https://override.example.com",
				TargetFilter: &contextargs.TargetFilter{
					HasTags: true,
					Tags:    []string{"nginx"},
				},
			},
		}},
	}
	loaderConfig := &loader.Config{}

	require.NoError(t, runner.prepareTargetFilters(loaderConfig))
	require.True(t, filter.MatchesTemplate("/resolved/normal.yaml", []string{"apache"}, severity.High, false))
	require.False(t, filter.MatchesTemplate("/resolved/normal.yaml", []string{"nginx"}, severity.High, false))
	require.False(t, filter.MatchesTemplate("/resolved/normal.yaml", []string{"apache", "deprecated"}, severity.High, false))
	require.True(t, filter.MatchesTemplate("/resolved/forced.yaml", []string{"deprecated"}, severity.Low, false))
}

func TestResolveTargetTemplatePathsRejectsRemoteSelectorsClearly(t *testing.T) {
	_, err := resolveTargetTemplatePaths(targetFilterTestCatalog{}, []string{"https://example.com/template.yaml"}, 7)
	require.ErrorContains(t, err, `jsonl line 7: remote template selector "https://example.com/template.yaml" is not supported`)
}

func TestPrepareTargetFiltersRejectsGlobalRemoteURLsWithTemplateOverrides(t *testing.T) {
	options := &types.Options{}
	options.TemplateURLs = append(options.TemplateURLs, "https://example.com/global.yaml")
	runner := &Runner{
		options: options,
		catalog: targetFilterTestCatalog{},
		inputProvider: &targetFilterTestProvider{inputs: []*contextargs.MetaInput{
			{
				Input: "https://example.com",
				TargetFilter: &contextargs.TargetFilter{
					HasTemplates: true,
					Templates:    []string{"local.yaml"},
				},
			},
		}},
	}

	err := runner.prepareTargetFilters(&loader.Config{})
	require.ErrorContains(t, err, "global remote template URLs are not supported together with per-target template overrides")
}

func TestPrepareTargetFiltersLeavesGlobalBehaviorUntouchedWithoutOverrides(t *testing.T) {
	filter := &contextargs.TargetFilter{}
	options := &types.Options{}
	options.IncludeTemplates = append(options.IncludeTemplates, "https://example.com/include.yaml")
	runner := &Runner{
		options: options,
		catalog: targetFilterTestCatalog{},
		inputProvider: &targetFilterTestProvider{inputs: []*contextargs.MetaInput{
			{
				Input:        "https://example.com",
				TargetFilter: filter,
			},
		}},
	}
	loaderConfig := &loader.Config{
		Tags:       []string{"global"},
		Severities: severity.Severities{severity.High},
	}

	require.NoError(t, runner.prepareTargetFilters(loaderConfig))
	require.Equal(t, []string{"global"}, loaderConfig.Tags)
	require.Equal(t, severity.Severities{severity.High}, loaderConfig.Severities)
	require.Nil(t, runner.inputProvider.(provider.PerTargetInputProvider).TargetInputs()[0].TargetFilter)
}

func TestPrepareTargetFiltersRejectsAutomaticScanWithOverrides(t *testing.T) {
	runner := &Runner{
		options: &types.Options{AutomaticScan: true},
		catalog: targetFilterTestCatalog{},
		inputProvider: &targetFilterTestProvider{inputs: []*contextargs.MetaInput{
			{
				Input: "https://example.com",
				TargetFilter: &contextargs.TargetFilter{
					HasTags: true,
					Tags:    []string{"apache"},
				},
			},
		}},
	}

	err := runner.prepareTargetFilters(&loader.Config{})
	require.ErrorContains(t, err, "automatic scan is not supported with per-target JSONL overrides")
}

func TestPrepareTargetFiltersRejectsWorkflowsWithOverrides(t *testing.T) {
	options := &types.Options{}
	options.Workflows = append(options.Workflows, "workflow.yaml")
	runner := &Runner{
		options: options,
		catalog: targetFilterTestCatalog{},
		inputProvider: &targetFilterTestProvider{inputs: []*contextargs.MetaInput{
			{
				Input: "https://example.com",
				TargetFilter: &contextargs.TargetFilter{
					HasSeverities: true,
					Severities:    severity.Severities{severity.High},
				},
			},
		}},
	}

	err := runner.prepareTargetFilters(&loader.Config{})
	require.ErrorContains(t, err, "workflows are not supported with per-target JSONL overrides")
}

func TestPrepareTargetFiltersRejectsGlobalMatchersWithOverrides(t *testing.T) {
	runner := &Runner{
		options: &types.Options{EnableGlobalMatchersTemplates: true},
		catalog: targetFilterTestCatalog{},
		inputProvider: &targetFilterTestProvider{inputs: []*contextargs.MetaInput{
			{
				Input: "https://example.com",
				TargetFilter: &contextargs.TargetFilter{
					HasTags: true,
					Tags:    []string{"apache"},
				},
			},
		}},
	}

	err := runner.prepareTargetFilters(&loader.Config{})
	require.ErrorContains(t, err, "global matchers are not supported with per-target JSONL overrides")
}
