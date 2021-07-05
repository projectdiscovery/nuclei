package templates

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows/compile"
)

// compileWorkflow compiles the workflow for execution
func compileWorkflow(options *protocols.ExecuterOptions, workflow *workflows.Workflow, loader compile.WorkflowLoader) error {
	for _, workflow := range workflow.Workflows {
		if err := parseWorkflow(workflow, options, loader); err != nil {
			return err
		}
	}
	return nil
}

// parseWorkflow parses and compiles all templates in a workflow recursively
func parseWorkflow(workflow *workflows.WorkflowTemplate, options *protocols.ExecuterOptions, loader compile.WorkflowLoader) error {
	shouldNotValidate := false

	if len(workflow.Subtemplates) > 0 || len(workflow.Matchers) > 0 {
		shouldNotValidate = true
	}
	if err := parseWorkflowTemplate(workflow, options, loader, shouldNotValidate); err != nil {
		return err
	}
	for _, subtemplates := range workflow.Subtemplates {
		if err := parseWorkflow(subtemplates, options, loader); err != nil {
			return err
		}
	}
	for _, matcher := range workflow.Matchers {
		for _, subtemplates := range matcher.Subtemplates {
			if err := parseWorkflow(subtemplates, options, loader); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseWorkflowTemplate parses a workflow template creating an executer
func parseWorkflowTemplate(workflow *workflows.WorkflowTemplate, options *protocols.ExecuterOptions, loader compile.WorkflowLoader, noValidate bool) error {
	var paths []string

	if len(workflow.Tags) > 0 {
		paths = loader.ListTags(workflow.Tags)
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
		template, err := Parse(path, opts)
		if err != nil {
			return errors.Wrap(err, "could not parse workflow template")
		}
		if template.Executer == nil {
			return errors.New("no executer found for template")
		}
		workflow.Executers = append(workflow.Executers, &workflows.ProtocolExecuterPair{
			Executer: template.Executer,
			Options:  options,
		})
	}
	return nil
}
