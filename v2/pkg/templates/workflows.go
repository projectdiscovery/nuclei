package templates

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows/compile"
)

// compileWorkflow compiles the workflow for execution
func compileWorkflow(preprocessor Preprocessor, options *protocols.ExecuterOptions, workflow *workflows.Workflow, loader compile.WorkflowLoader) {
	for _, workflow := range workflow.Workflows {
		if err := parseWorkflow(preprocessor, workflow, options, loader); err != nil {
			gologger.Warning().Msgf("Could not parse workflow: %v\n", err)
			continue
		}
	}
}

// parseWorkflow parses and compiles all templates in a workflow recursively
func parseWorkflow(preprocessor Preprocessor, workflow *workflows.WorkflowTemplate, options *protocols.ExecuterOptions, loader compile.WorkflowLoader) error {
	shouldNotValidate := false

	if len(workflow.Subtemplates) > 0 || len(workflow.Matchers) > 0 {
		shouldNotValidate = true
	}
	if err := parseWorkflowTemplate(workflow, preprocessor, options, loader, shouldNotValidate); err != nil {
		return err
	}
	for _, subtemplates := range workflow.Subtemplates {
		if err := parseWorkflow(preprocessor, subtemplates, options, loader); err != nil {
			gologger.Warning().Msgf("Could not parse workflow: %v\n", err)
			continue
		}
	}
	for _, matcher := range workflow.Matchers {
		for _, subtemplates := range matcher.Subtemplates {
			if err := parseWorkflow(preprocessor, subtemplates, options, loader); err != nil {
				gologger.Warning().Msgf("Could not parse workflow: %v\n", err)
				continue
			}
		}
	}
	return nil
}

// parseWorkflowTemplate parses a workflow template creating an executer
func parseWorkflowTemplate(workflow *workflows.WorkflowTemplate, preprocessor Preprocessor, options *protocols.ExecuterOptions, loader compile.WorkflowLoader, noValidate bool) error {
	var paths []string

	if len(workflow.Tags) > 0 {
		paths = loader.ListTags([]string{workflow.Tags})
	} else {
		paths = loader.ListTemplates([]string{workflow.Template}, noValidate)
	}
	if len(paths) == 0 {
		return nil
	}
	for _, path := range paths {
		opts := protocols.ExecuterOptions{
			Output:       options.Output,
			Options:      options.Options,
			Progress:     options.Progress,
			Catalog:      options.Catalog,
			Browser:      options.Browser,
			RateLimiter:  options.RateLimiter,
			IssuesClient: options.IssuesClient,
			Interactsh:   options.Interactsh,
			ProjectFile:  options.ProjectFile,
		}
		template, err := Parse(path, preprocessor, opts)
		if err != nil {
			gologger.Warning().Msgf("Could not parse workflow template %s: %v\n", path, err)
			continue
		}
		if template.Executer == nil {
			gologger.Warning().Msgf("Could not parse workflow template %s: no executer found\n", path)
			continue
		}
		workflow.Executers = append(workflow.Executers, &workflows.ProtocolExecuterPair{
			Executer: template.Executer,
			Options:  options,
		})
	}
	return nil
}
