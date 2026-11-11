package replay

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
)

// source is a template whose requests produce events: a loaded template, or
// a step of a loaded workflow, which may not be loaded on its own.
type source struct {
	id       string
	path     string
	info     model.Info
	requests []protocols.Request
	// clustered mirrors templates.Cluster: only a template the scan can
	// cluster shares events with others by its request
	clustered bool
}

type requestLister interface {
	ProtocolRequests() []protocols.Request
}

type templateExecuter interface {
	requestLister
	TemplateOptions() *protocols.ExecutorOptions
}

func sources(templatesList []*templates.Template) []source {
	var list []source
	seen := make(map[string]bool)
	add := func(s source) {
		if !seen[s.id] && len(s.requests) > 0 {
			seen[s.id] = true
			list = append(list, s)
		}
	}
	addTemplate := func(template *templates.Template) {
		if lister, ok := template.Executer.(requestLister); ok {
			clustered := template.Flow == "" && (template.Options == nil || !template.Options.IsMultiProtocol) && !template.Info.HasPlaceholders()
			add(source{id: template.ID, path: template.Path, info: template.Info, requests: lister.ProtocolRequests(), clustered: clustered})
		}
	}
	var walk func(steps []*workflows.WorkflowTemplate)
	walk = func(steps []*workflows.WorkflowTemplate) {
		for _, step := range steps {
			for _, pair := range step.Executers {
				switch executer := pair.Executer.(type) {
				case templateExecuter:
					options := executer.TemplateOptions()
					add(source{id: options.TemplateID, path: options.TemplatePath, info: options.TemplateInfo, requests: executer.ProtocolRequests()})
				case *templates.ClusterExecuter:
					// a cluster holds only the first member's request; each
					// member is parsed again for its own, which the event is
					// matched to by its cluster key
					for _, path := range executer.TemplatePaths() {
						if member, err := templates.Parse(path, nil, pair.Options); err == nil && member != nil {
							addTemplate(member)
						}
					}
				}
			}
			walk(step.Subtemplates)
			for _, matcher := range step.Matchers {
				walk(matcher.Subtemplates)
			}
		}
	}
	for _, template := range templatesList {
		addTemplate(template)
		if template.CompiledWorkflow != nil {
			walk(template.CompiledWorkflow.Workflows)
		}
	}
	return list
}
