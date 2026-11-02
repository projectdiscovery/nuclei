package workflow

import (
	"maps"
	"slices"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
	"github.com/stretchr/testify/require"
)

type countingCatalog struct {
	catalog.Catalog
	paths []string
	walks int
}

func (c *countingCatalog) GetTemplatesPath([]string) ([]string, map[string]error) {
	c.walks++
	return c.paths, nil
}

type countingParser struct {
	templates map[string]*templates.Template
	parses    map[string]int
}

func (p *countingParser) ParseTemplate(path string, _ catalog.Catalog) (any, error) {
	p.parses[path]++
	return p.templates[path], nil
}

func (p *countingParser) LoadTemplate(string, any, []string, catalog.Catalog) (bool, error) {
	panic("tag lookups must not reparse through LoadTemplate")
}

func (p *countingParser) LoadWorkflow(string, catalog.Catalog) (bool, error) {
	return false, nil
}

func TestGetTemplatePathsByTagsReadsTemplatesDirectoryOnce(t *testing.T) {
	template := func(id, tags string) *templates.Template {
		return &templates.Template{ID: id, Info: model.Info{
			Name:           id,
			Authors:        stringslice.StringSlice{Value: "author"},
			Tags:           stringslice.StringSlice{Value: tags},
			SeverityHolder: severity.Holder{Severity: severity.Info},
		}}
	}
	parser := &countingParser{
		templates: map[string]*templates.Template{
			"wordpress.yaml": template("wordpress", "wordpress"),
			"jira.yaml":      template("jira", "jira"),
		},
		parses: make(map[string]int),
	}
	cat := &countingCatalog{paths: []string{"wordpress.yaml", "jira.yaml"}}
	loader, err := NewLoader(&protocols.ExecutorOptions{Options: types.DefaultOptions(), Catalog: cat, Parser: parser})
	require.NoError(t, err)
	walksBeforeLookups := cat.walks

	require.Equal(t, []string{"wordpress.yaml"}, loader.GetTemplatePathsByTags([]string{"wordpress"}, false))
	require.Equal(t, []string{"jira.yaml"}, loader.GetTemplatePathsByTags([]string{"jira"}, false))

	require.Equal(t, 1, cat.walks-walksBeforeLookups, "templates directory walked per lookup")
	require.Equal(t, map[string]int{"wordpress.yaml": 1, "jira.yaml": 1}, parser.parses, "templates parsed per lookup")
}

func TestGetTemplatePathsByTagsNoValidateAppliesExclusionsButSeverity(t *testing.T) {
	template := func(id string, tags ...string) *templates.Template {
		return &templates.Template{ID: id, Info: model.Info{
			Name:           id,
			Authors:        stringslice.StringSlice{Value: "author"},
			Tags:           stringslice.StringSlice{Value: tags},
			SeverityHolder: severity.Holder{Severity: severity.Info},
		}}
	}
	excludedSeverity := template("excluded-severity", "step")
	excludedSeverity.Info.SeverityHolder.Severity = severity.Low
	excludedProtocol := template("excluded-protocol", "step")
	excludedProtocol.RequestsDNS = []*dns.Request{{}}
	workflow := template("workflow", "step")
	workflow.Workflows = []*workflows.WorkflowTemplate{{Template: "selected.yaml"}}
	parser := &countingParser{
		templates: map[string]*templates.Template{
			"selected.yaml":          template("selected", "step"),
			"included.yaml":          template("included", "step", "included"),
			"excluded-tag.yaml":      template("excluded-tag", "step", "excluded"),
			"excluded-id.yaml":       template("excluded-id", "step"),
			"excluded-severity.yaml": excludedSeverity,
			"excluded-protocol.yaml": excludedProtocol,
			"untagged.yaml":          template("untagged", "other"),
			"workflow.yaml":          workflow,
		},
		parses: make(map[string]int),
	}
	options := types.DefaultOptions()
	options.IncludeIds = []string{"untagged"}
	options.ExcludeTags = []string{"excluded", "included"}
	options.IncludeTags = []string{"included"}
	options.ExcludeIds = []string{"excluded-id"}
	options.ExcludeSeverities = severity.Severities{severity.Low}
	options.ExcludeProtocols = templateTypes.ProtocolTypes{templateTypes.DNSProtocol}
	cat := &countingCatalog{paths: slices.Collect(maps.Keys(parser.templates))}
	loader, err := NewLoader(&protocols.ExecutorOptions{Options: options, Catalog: cat, Parser: parser})
	require.NoError(t, err)

	require.Empty(t, loader.GetTemplatePathsByTags([]string{"step"}, false))
	loaded := loader.GetTemplatePathsByTags([]string{"step"}, true)
	require.ElementsMatch(t, []string{"selected.yaml", "included.yaml", "excluded-severity.yaml"}, loaded)
}

func TestGetTemplatePathsByTagsCountsSyntaxWarningsOfLoadedTemplates(t *testing.T) {
	// a template without severity has a syntax warning
	unrated := &templates.Template{ID: "unrated", Info: model.Info{
		Name:    "unrated",
		Authors: stringslice.StringSlice{Value: "author"},
		Tags:    stringslice.StringSlice{Value: "step"},
	}}
	tests := []struct {
		name     string
		ids      []string
		warnings int64
	}{
		{name: "loaded", warnings: 1},
		{name: "filtered out", ids: []string{"other"}, warnings: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parser := &countingParser{
				templates: map[string]*templates.Template{"unrated.yaml": unrated},
				parses:    make(map[string]int),
			}
			options := types.DefaultOptions()
			options.IncludeIds = tc.ids
			cat := &countingCatalog{paths: []string{"unrated.yaml"}}
			loader, err := NewLoader(&protocols.ExecutorOptions{Options: options, Catalog: cat, Parser: parser})
			require.NoError(t, err)

			before := stats.GetValue(templates.TemplateSyntaxWarningStats)
			loader.GetTemplatePathsByTags([]string{"step"}, false)
			require.Equal(t, tc.warnings, stats.GetValue(templates.TemplateSyntaxWarningStats)-before)
		})
	}
}
