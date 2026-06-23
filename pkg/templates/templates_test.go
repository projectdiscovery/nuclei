package templates

import (
	"os"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	codeProtocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/code"
	fileProtocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/file"
	headlessProtocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless"
	httpProtocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/stretchr/testify/require"
)

func TestCachePoolZeroing(t *testing.T) {
	c := NewCache()

	tpl := &Template{ID: "x"}
	raw := []byte("SOME BIG RAW")

	c.Store("id1", tpl, raw, nil)
	gotTpl, gotErr := c.Get("id1")
	if gotErr != nil {
		t.Fatalf("unexpected err: %v", gotErr)
	}
	if gotTpl == nil || gotTpl.ID != "x" {
		t.Fatalf("unexpected tpl: %#v", gotTpl)
	}

	// StoreWithoutRaw should not retain raw
	c.StoreWithoutRaw("id2", tpl, nil)
	gotTpl2, gotErr2 := c.Get("id2")
	if gotErr2 != nil {
		t.Fatalf("unexpected err: %v", gotErr2)
	}
	if gotTpl2 == nil || gotTpl2.ID != "x" {
		t.Fatalf("unexpected tpl2: %#v", gotTpl2)
	}
}

func TestTemplateStruct(t *testing.T) {
	templatePath := "./tests/match-1.yaml"
	bin, err := os.ReadFile(templatePath)
	require.Nil(t, err, "failed to load example template")
	var yamlTemplate Template
	err = yaml.Unmarshal(bin, &yamlTemplate)
	require.Nil(t, err, "failed to unmarshal yaml template")
	jsonBin, err := json.Marshal(yamlTemplate)
	require.Nil(t, err, "failed to marshal template to json")
	var jsonTemplate Template
	err = json.Unmarshal(jsonBin, &jsonTemplate)
	require.Nil(t, err, "failed to unmarshal json template")

	templatePath = "./tests/json-template.json"
	bin, err = os.ReadFile(templatePath)
	require.Nil(t, err, "failed to load example template")
	jsonTemplate = Template{}
	err = json.Unmarshal(bin, &jsonTemplate)
	require.Nil(t, err, "failed to unmarshal json template")
	yamlBin, err := yaml.Marshal(jsonTemplate)
	require.Nil(t, err, "failed to marshal template to yaml")
	yamlTemplate = Template{}
	err = yaml.Unmarshal(yamlBin, &yamlTemplate)
	require.Nil(t, err, "failed to unmarshal yaml template")
}

func TestCapabilitiesFromOptions(t *testing.T) {
	options := &types.Options{
		Headless:                      true,
		EnableCodeTemplates:           true,
		DAST:                          true,
		EnableSelfContainedTemplates:  true,
		EnableGlobalMatchersTemplates: true,
		EnableFileTemplates:           true,
	}

	require.Equal(t, CapabilitySet{
		CapabilityHeadless:       true,
		CapabilityCode:           true,
		CapabilityDAST:           true,
		CapabilitySelfContained:  true,
		CapabilityGlobalMatchers: true,
		CapabilityFile:           true,
	}, CapabilitiesFromOptions(options))
}

func TestDeprecatedStatAliases(t *testing.T) {
	require.Equal(t, TemplateSyntaxWarningStats, SyntaxWarningStats)
	require.Equal(t, TemplateSyntaxErrorStats, SyntaxErrorStats)
	require.Equal(t, TemplateRuntimeWarningStats, RuntimeWarningsStats)
	require.Equal(t, SkippedUnverifiedCodeTemplateStats, SkippedCodeTmplTamperedStats)
	require.Equal(t, ExcludedHeadlessTemplateStats, ExcludedHeadlessTmplStats)
	require.Equal(t, ExcludedWeakMatcherTemplateStats, TemplatesExcludedStats)
	require.Equal(t, ExcludedCodeTemplateStats, ExcludedCodeTmplStats)
	require.Equal(t, ExcludedDASTTemplateStats, ExcludedDastTmplStats)
	require.Equal(t, ExcludedDastTmplStats, ExludedDastTmplStats)
	require.Equal(t, SkippedUnverifiedTemplateStats, SkippedUnsignedStats)
	require.Equal(t, ExcludedSelfContainedTemplateStats, ExcludedSelfContainedStats)
	require.Equal(t, ExcludedFileTemplateStats, ExcludedFileStats)
	require.Equal(t, SkippedRequestSignatureTemplateStats, SkippedRequestSignatureStats)
}

func TestAllCapabilities(t *testing.T) {
	require.Equal(t, []Capability{
		CapabilityHeadless,
		CapabilityCode,
		CapabilityDAST,
		CapabilitySelfContained,
		CapabilityGlobalMatchers,
		CapabilityFile,
	}, AllCapabilities())
}

func TestCapabilityMetadata(t *testing.T) {
	tests := []struct {
		capability   Capability
		expectedStat string
		expectedFlag string
		expectedKind string
	}{
		{
			capability:   CapabilityHeadless,
			expectedStat: ExcludedHeadlessTemplateStats,
			expectedFlag: "-headless",
			expectedKind: "headless",
		},
		{
			capability:   CapabilityCode,
			expectedStat: ExcludedCodeTemplateStats,
			expectedFlag: "-code",
			expectedKind: "code protocol",
		},
		{
			capability:   CapabilityDAST,
			expectedStat: ExcludedDASTTemplateStats,
			expectedFlag: "-dast",
			expectedKind: "DAST",
		},
		{
			capability:   CapabilitySelfContained,
			expectedStat: ExcludedSelfContainedTemplateStats,
			expectedFlag: "-enable-self-contained",
			expectedKind: "self-contained",
		},
		{
			capability:   CapabilityGlobalMatchers,
			expectedStat: ExcludedGlobalMatchersTemplateStats,
			expectedFlag: "-enable-global-matchers",
			expectedKind: "global matchers",
		},
		{
			capability:   CapabilityFile,
			expectedStat: ExcludedFileTemplateStats,
			expectedFlag: "-file",
			expectedKind: "file",
		},
	}

	for _, test := range tests {
		t.Run(string(test.capability), func(t *testing.T) {
			require.Equal(t, test.expectedStat, test.capability.Stat())
			require.Equal(t, test.expectedFlag, test.capability.Flag())
			require.Equal(t, test.expectedKind, test.capability.TemplateKind())
			require.Equal(t,
				test.expectedFlag+" flag is required for "+test.expectedKind+" template \"template.yaml\".",
				test.capability.MissingFlagMessage("template.yaml"),
			)
		})
	}
}

func TestTemplateMissingCapabilitiesReturnsAllMissingCapabilities(t *testing.T) {
	template := &Template{
		SelfContained:    true,
		RequestsFile:     []*fileProtocol.Request{{}},
		RequestsHeadless: []*headlessProtocol.Request{{Fuzzing: []*fuzz.Rule{{}}}},
		RequestsCode:     []*codeProtocol.Request{{}},
		RequestsHTTP: []*httpProtocol.Request{{
			GlobalMatchers: true,
		}},
	}

	require.Equal(t, []Capability{
		CapabilityHeadless,
		CapabilityCode,
		CapabilityDAST,
		CapabilitySelfContained,
		CapabilityGlobalMatchers,
		CapabilityFile,
	}, template.MissingCapabilities(CapabilitySet{}))
	require.Empty(t, template.MissingCapabilities(CapabilitySet{
		CapabilityHeadless:       true,
		CapabilityCode:           true,
		CapabilityDAST:           true,
		CapabilitySelfContained:  true,
		CapabilityGlobalMatchers: true,
		CapabilityFile:           true,
	}))
}

func TestTemplateMissingLoadCapabilitiesAllowsGlobalMatchers(t *testing.T) {
	template := &Template{
		RequestsHTTP: []*httpProtocol.Request{{
			GlobalMatchers: true,
		}},
	}

	require.Equal(t, []Capability{CapabilityGlobalMatchers}, template.MissingCapabilities(CapabilitySet{}))
	require.Empty(t, template.MissingLoadCapabilities(CapabilitySet{}))
}

func TestDeprecatedRequirementsAndIsEnabledForWrappers(t *testing.T) {
	template := &Template{
		SelfContained: true,
		RequestsFile:  []*fileProtocol.Request{{}},
	}

	require.Equal(t, Requirements{
		SelfContained: true,
		File:          true,
	}, template.Requirements())
	require.False(t, template.IsEnabledFor(Capabilities{File: true}))
	require.True(t, template.IsEnabledFor(Capabilities{
		SelfContained: true,
		File:          true,
	}))
}

func TestTemplateMissingCapabilitiesDetectsRequestSelfContained(t *testing.T) {
	template := &Template{
		RequestsHTTP: []*httpProtocol.Request{{
			SelfContained: true,
		}},
	}

	require.Equal(t, []Capability{CapabilitySelfContained}, template.MissingCapabilities(CapabilitySet{}))
	require.Empty(t, template.MissingCapabilities(CapabilitySet{CapabilitySelfContained: true}))
}

func TestTemplateMissingCapabilitiesIgnoresNilHTTPRequests(t *testing.T) {
	template := &Template{
		RequestsHTTP: []*httpProtocol.Request{nil},
	}

	require.Empty(t, template.MissingCapabilities(CapabilitySet{}))
}

func TestIsFuzzableRequestIgnoresNilRequests(t *testing.T) {
	template := &Template{
		RequestsHTTP:     []*httpProtocol.Request{nil},
		RequestsHeadless: []*headlessProtocol.Request{nil},
	}

	require.False(t, template.IsFuzzableRequest())
}
