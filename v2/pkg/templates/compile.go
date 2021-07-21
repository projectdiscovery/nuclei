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
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows/compile"
	"gopkg.in/yaml.v2"
)

// Parse parses a yaml request template file
//nolint:gocritic // this cannot be passed by pointer
func Parse(filePath string, preprocessor Preprocessor, options protocols.ExecuterOptions) (*Template, error) {
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
	if preprocessor != nil {
		data = preprocessor.Process(data)
	}

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

		loader, err := compile.NewLoader(&options)
		if err != nil {
			return nil, errors.Wrap(err, "could not create workflow loader")
		}
		compileWorkflow(preprocessor, &options, compiled, loader)
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
