package filter

import "github.com/projectdiscovery/nuclei/v2/pkg/catalog"

// PathFilter is a path based template filter
type PathFilter struct {
	excludedTemplates          []string
	alwaysIncludedTemplatesMap map[string]struct{}
}

// PathFilterConfig contains configuration options for Path based templates Filter
type PathFilterConfig struct {
	IncludedTemplates []string
	ExcludedTemplates []string
}

// NewPathFilter creates a new path filter from provided config
func NewPathFilter(config *PathFilterConfig, catalogClient *catalog.Catalog) *PathFilter {
	filter := &PathFilter{
		excludedTemplates:          catalogClient.GetTemplatesPath(config.ExcludedTemplates),
		alwaysIncludedTemplatesMap: make(map[string]struct{}),
	}

	alwaysIncludeTemplates := catalogClient.GetTemplatesPath(config.IncludedTemplates)
	for _, tpl := range alwaysIncludeTemplates {
		filter.alwaysIncludedTemplatesMap[tpl] = struct{}{}
	}
	return filter
}

// Match performs match for path filter on templates and returns final list
func (p *PathFilter) Match(templates []string) map[string]struct{} {
	templatesMap := make(map[string]struct{})
	for _, tpl := range templates {
		templatesMap[tpl] = struct{}{}
	}
	for _, template := range p.excludedTemplates {
		if _, ok := p.alwaysIncludedTemplatesMap[template]; ok {
			continue
		} else {
			delete(templatesMap, template)
		}
	}
	return templatesMap
}
