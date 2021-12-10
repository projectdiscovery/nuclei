package templates

import (
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
)

// compileWorkflow compiles the workflow for execution
func compileWorkflow(path string, preprocessor Preprocessor, options *protocols.ExecuterOptions, workflow *workflows.Workflow, loader model.WorkflowLoader) {
	for _, workflow := range workflow.Workflows {
		if err := parseWorkflow(preprocessor, workflow, options, loader); err != nil {
			gologger.Warning().Msgf("Could not parse workflow %s: %v\n", path, err)
			continue
		}
	}
}

// parseWorkflow parses and compiles all templates in a workflow recursively
func parseWorkflow(preprocessor Preprocessor, workflow *workflows.WorkflowTemplate, options *protocols.ExecuterOptions, loader model.WorkflowLoader) error {
	shouldNotValidate := false

	if len(workflow.Template) == 0 && workflow.Tags.IsEmpty() {
		return errors.New("invalid workflow with no templates or tags")
	}
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
func parseWorkflowTemplate(workflow *workflows.WorkflowTemplate, preprocessor Preprocessor, options *protocols.ExecuterOptions, loader model.WorkflowLoader, noValidate bool) error {
	var paths []string

	subTemplateTags := workflow.Tags
	if !subTemplateTags.IsEmpty() {
		paths = loader.GetTemplatePathsByTags(subTemplateTags.ToSlice())
	} else {
		paths = loader.GetTemplatePaths([]string{workflow.Template}, noValidate)
	}
	if len(paths) == 0 {
		return nil
	}

	var workflowTemplates []*Template

	for _, path := range paths {
		template, err := Parse(nil, path, preprocessor, options.Copy())
		if err != nil {
			gologger.Warning().Msgf("Could not parse workflow template %s: %v\n", path, err)
			continue
		}
		if template.Executer == nil {
			gologger.Warning().Msgf("Could not parse workflow template %s: no executer found\n", path)
			continue
		}
		workflowTemplates = append(workflowTemplates, template)
	}

	finalTemplates, _ := ClusterTemplates(workflowTemplates, options.Copy())
	for _, template := range finalTemplates {
		workflow.Executers = append(workflow.Executers, &workflows.ProtocolExecuterPair{
			Executer: template.Executer,
			Options:  options,
		})
	}

	return nil
}
