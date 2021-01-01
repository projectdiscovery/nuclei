package templates

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/file"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
	"gopkg.in/yaml.v2"
)

// Parse parses a yaml request template file
func Parse(filePath string, options *protocols.ExecuterOptions) (*Template, error) {
	template := &Template{}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	err = yaml.NewDecoder(f).Decode(template)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Setting up variables regarding template metadata
	options.TemplateID = template.ID
	options.TemplateInfo = template.Info
	options.TemplatePath = filePath

	// If no requests, and it is also not a workflow, return error.
	if len(template.RequestsDNS)+len(template.RequestsHTTP)+len(template.RequestsFile)+len(template.Workflows) == 0 {
		return nil, fmt.Errorf("no requests defined for %s", template.ID)
	}

	// Compile the workflow request
	if len(template.Workflows) > 0 {
		compiled := &template.Workflow
		if err := template.compileWorkflow(options, compiled); err != nil {
			return nil, errors.Wrap(err, "could not compile workflow")
		}
		template.Workflow.Compile(options)
		template.CompiledWorkflow = compiled
	}

	// Compile the requests found
	for _, request := range template.RequestsDNS {
		template.TotalRequests += request.Requests()
	}
	for _, request := range template.RequestsHTTP {
		template.TotalRequests += request.Requests()
	}
	for _, request := range template.RequestsFile {
		template.TotalRequests += request.Requests()
	}
	if len(template.RequestsDNS) > 0 {
		template.Executer = dns.NewExecuter(template.RequestsDNS, options)
	}
	if len(template.RequestsHTTP) > 0 {
		template.Executer = http.NewExecuter(template.RequestsHTTP, options)
	}
	if len(template.RequestsFile) > 0 {
		template.Executer = file.NewExecuter(template.RequestsFile, options)
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not compile request")
	}
	if template.Executer != nil {
		if err := template.Executer.Compile(); err != nil {
			return nil, errors.Wrap(err, "could not compile template executer")
		}
	}
	return template, nil
}

// compileWorkflow compiles the workflow for execution
func (t *Template) compileWorkflow(options *protocols.ExecuterOptions, workflows *workflows.Workflow) error {
	for _, workflow := range workflows.Workflows {
		if err := t.parseWorkflow(workflow, options); err != nil {
			return err
		}
	}
	return nil
}

// parseWorkflow parses and compiles all templates in a workflow recursively
func (t *Template) parseWorkflow(workflow *workflows.WorkflowTemplate, options *protocols.ExecuterOptions) error {
	if err := t.parseWorkflowTemplate(workflow, options); err != nil {
		return err
	}
	for _, subtemplates := range workflow.Subtemplates {
		if err := t.parseWorkflow(subtemplates, options); err != nil {
			return err
		}
	}
	for _, matcher := range workflow.Matchers {
		for _, subtemplates := range matcher.Subtemplates {
			if err := t.parseWorkflow(subtemplates, options); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseWorkflowTemplate parses a workflow template creating an executer
func (t *Template) parseWorkflowTemplate(workflow *workflows.WorkflowTemplate, options *protocols.ExecuterOptions) error {
	opts := protocols.ExecuterOptions{
		Output:      options.Output,
		Options:     options.Options,
		Progress:    options.Progress,
		Catalogue:   options.Catalogue,
		RateLimiter: options.RateLimiter,
		ProjectFile: options.ProjectFile,
	}
	paths, err := options.Catalogue.GetTemplatePath(workflow.Template)
	if err != nil {
		return errors.Wrap(err, "could not get workflow template")
	}
	if len(paths) != 1 {
		return errors.Wrap(err, "invalid number of templates matched")
	}

	template, err := Parse(paths[0], &opts)
	if err != nil {
		return errors.Wrap(err, "could not parse workflow template")
	}
	workflow.Executer = template.Executer
	return nil
}
