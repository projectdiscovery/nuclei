package templates

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/executer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/offlinehttp"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
	"gopkg.in/yaml.v2"
)

// Parse parses a yaml request template file
//nolint:gocritic // this cannot be passed by pointer
func Parse(filePath string, options protocols.ExecuterOptions) (*Template, error) {
	template := &Template{}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	data = template.expandPreprocessors(data)
	err = yaml.NewDecoder(bytes.NewReader(data)).Decode(template)
	if err != nil {
		return nil, err
	}

	if _, ok := template.Info["name"]; !ok {
		return nil, errors.New("no template name field provided")
	}
	if _, ok := template.Info["author"]; !ok {
		return nil, errors.New("no template author field provided")
	}
	templateTags, ok := template.Info["tags"]
	if !ok {
		templateTags = ""
	}
	matchWithTags := false
	if len(options.Options.Tags) > 0 {
		if err := matchTemplateWithTags(types.ToString(templateTags), types.ToString(template.Info["severity"]), options.Options.Tags); err != nil {
			return nil, fmt.Errorf("tags filter not matched %s", templateTags)
		}
		matchWithTags = true
	}
	if len(options.Options.ExcludeTags) > 0 && !matchWithTags {
		if err := matchTemplateWithTags(types.ToString(templateTags), types.ToString(template.Info["severity"]), options.Options.ExcludeTags); err == nil {
			return nil, fmt.Errorf("exclude-tags filter matched %s", templateTags)
		}
	}

	// Setting up variables regarding template metadata
	options.TemplateID = template.ID
	options.TemplateInfo = template.Info
	options.TemplatePath = filePath

	// If no requests, and it is also not a workflow, return error.
	if len(template.RequestsDNS)+len(template.RequestsHTTP)+len(template.RequestsFile)+len(template.RequestsNetwork)+len(template.RequestsHeadless)+len(template.Workflows) == 0 {
		return nil, fmt.Errorf("no requests defined for %s", template.ID)
	}

	// Compile the workflow request
	if len(template.Workflows) > 0 {
		compiled := &template.Workflow
		if err := template.compileWorkflow(&options, compiled); err != nil {
			return nil, errors.Wrap(err, "could not compile workflow")
		}
		template.CompiledWorkflow = compiled
		template.CompiledWorkflow.Options = &options
	}

	// Compile the requests found
	requests := []protocols.Request{}
	if len(template.RequestsDNS) > 0 && !options.Options.OfflineHTTP {
		for _, req := range template.RequestsDNS {
			requests = append(requests, req)
		}
		template.Executer = executer.NewExecuter(requests, &options)
	}
	if len(template.RequestsHTTP) > 0 {
		if options.Options.OfflineHTTP {
			operatorsList := []*operators.Operators{}

		mainLoop:
			for _, req := range template.RequestsHTTP {
				for _, path := range req.Path {
					if !(strings.EqualFold(path, "{{BaseURL}}") || strings.EqualFold(path, "{{BaseURL}}/")) {
						break mainLoop
					}
				}
				operatorsList = append(operatorsList, &req.Operators)
			}
			if len(operatorsList) > 0 {
				options.Operators = operatorsList
				template.Executer = executer.NewExecuter([]protocols.Request{&offlinehttp.Request{}}, &options)
			}
		} else {
			for _, req := range template.RequestsHTTP {
				requests = append(requests, req)
			}
			template.Executer = executer.NewExecuter(requests, &options)
		}
	}
	if len(template.RequestsFile) > 0 && !options.Options.OfflineHTTP {
		for _, req := range template.RequestsFile {
			requests = append(requests, req)
		}
		template.Executer = executer.NewExecuter(requests, &options)
	}
	if len(template.RequestsNetwork) > 0 && !options.Options.OfflineHTTP {
		for _, req := range template.RequestsNetwork {
			requests = append(requests, req)
		}
		template.Executer = executer.NewExecuter(requests, &options)
	}
	if len(template.RequestsHeadless) > 0 && !options.Options.OfflineHTTP && options.Options.Headless {
		for _, req := range template.RequestsHeadless {
			requests = append(requests, req)
		}
		template.Executer = executer.NewExecuter(requests, &options)
	}
	if template.Executer != nil {
		err := template.Executer.Compile()
		if err != nil {
			return nil, errors.Wrap(err, "could not compile request")
		}
		template.TotalRequests += template.Executer.Requests()
	}
	if template.Executer == nil && template.CompiledWorkflow == nil {
		return nil, errors.New("cannot create template executer")
	}
	template.Path = filePath
	return template, nil
}

// compileWorkflow compiles the workflow for execution
func (t *Template) compileWorkflow(options *protocols.ExecuterOptions, workflow *workflows.Workflow) error {
	for _, workflow := range workflow.Workflows {
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
	paths, err := options.Catalog.GetTemplatePath(workflow.Template)
	if err != nil {
		return errors.Wrap(err, "could not get workflow template")
	}
	for _, path := range paths {
		opts := protocols.ExecuterOptions{
			Output:       options.Output,
			Options:      options.Options,
			Progress:     options.Progress,
			Catalog:      options.Catalog,
			RateLimiter:  options.RateLimiter,
			IssuesClient: options.IssuesClient,
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

// matchTemplateWithTags matches if the template matches a tag
func matchTemplateWithTags(tags, severity string, tagsInput []string) error {
	actualTags := strings.Split(tags, ",")
	if severity != "" {
		actualTags = append(actualTags, severity) // also add severity to tag
	}

	matched := false
mainLoop:
	for _, t := range tagsInput {
		commaTags := strings.Split(t, ",")
		for _, tag := range commaTags {
			tag = strings.TrimSpace(tag)
			key, value := getKeyValue(tag)

			for _, templTag := range actualTags {
				templTag = strings.TrimSpace(templTag)
				tKey, tValue := getKeyValue(templTag)

				if strings.EqualFold(key, tKey) && strings.EqualFold(value, tValue) {
					matched = true
					break mainLoop
				}
			}
		}
	}
	if !matched {
		return errors.New("could not match template tags with input")
	}
	return nil
}

// getKeyValue returns key value pair for a data string
func getKeyValue(data string) (key, value string) {
	if strings.Contains(data, ":") {
		parts := strings.SplitN(data, ":", 2)
		if len(parts) == 2 {
			key, value = parts[0], parts[1]
		}
	}
	if value == "" {
		value = data
	}
	return key, value
}
