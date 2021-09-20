package references

import (
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

// Matches kb_get("<template-id>:<value> format extracting template-id in group 1.
var referenceRegexp = regexp.MustCompile(`kb_get\(["']([A-Za-z0-9\-_]+):([A-Za-z]+)`)

// ValueDependency
type ValueDependency struct {
	Path          string
	Value         string
	FullReference string
}

// ReferenceAnalysis is the results for a template kb reference analysis process.
type ReferenceAnalysis struct {
	References   map[string]struct{}          // a list of template ids referencing each other.
	Dependencies map[string][]ValueDependency // dependencies is a list of deps where key is template-id
}

// AnalyzeReferences analyzes a list of templates finding references and returns
// a map of template-id:[]template-paths-with-values which is used by the
// execution engine to provide the order of execution as well as the values
// required to the runtime.
func AnalyzeReferences(templates []*templates.Template) *ReferenceAnalysis {
	// Map of template-id>list of templates paths dependent on it.
	references := &ReferenceAnalysis{
		Dependencies: make(map[string][]ValueDependency),
		References:   make(map[string]struct{}),
	}

	for _, template := range templates {
		matches := referenceRegexp.FindAllStringSubmatch(template.Data, -1)
		if len(matches) == 0 {
			continue
		}
		for _, match := range matches {
			if len(match) < 3 {
				continue
			}
			templateID := match[1]
			templateValue := match[2]

			// Add both IDs to the references
			references.References[templateID] = struct{}{}
			references.References[template.ID] = struct{}{}

			if value, ok := references.Dependencies[templateID]; ok {
				references.Dependencies[templateID] = append(value, newValueDependency(templateID, templateValue, template.Path))
			} else {
				references.Dependencies[templateID] = []ValueDependency{newValueDependency(templateID, templateValue, template.Path)}
			}
		}
	}
	return references
}

func newValueDependency(id, value, path string) ValueDependency {
	return ValueDependency{
		Path:          path,
		Value:         value,
		FullReference: strings.Join([]string{id, value}, ":"),
	}
}
