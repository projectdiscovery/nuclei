package workflow

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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

	require.Equal(t, []string{"wordpress.yaml"}, loader.GetTemplatePathsByTags([]string{"wordpress"}))
	require.Equal(t, []string{"jira.yaml"}, loader.GetTemplatePathsByTags([]string{"jira"}))

	require.Equal(t, 1, cat.walks-walksBeforeLookups, "templates directory walked per lookup")
	require.Equal(t, map[string]int{"wordpress.yaml": 1, "jira.yaml": 1}, parser.parses, "templates parsed per lookup")
}
