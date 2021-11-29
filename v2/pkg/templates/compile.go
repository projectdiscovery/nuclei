package templates

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/executer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/offlinehttp"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/cache"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

var (
	ErrCreateTemplateExecutor = errors.New("cannot create template executer")
)

var parsedTemplatesCache *cache.Templates

func init() {
	parsedTemplatesCache = cache.New()
}

// Parse parses a yaml request template file
//nolint:gocritic // this cannot be passed by pointer
// TODO make sure reading from the disk the template parsing happens once: see parsers.ParseTemplate vs templates.Parse
func Parse(filePath string, preprocessor Preprocessor, options protocols.ExecuterOptions) (*Template, error) {
	if value, err := parsedTemplatesCache.Has(filePath); value != nil {
		return value.(*Template), err
	}

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

	if err := yaml.Unmarshal(data, template); err != nil {
		return nil, err
	}

	if utils.IsBlank(template.Info.Name) {
		return nil, errors.New("no template name field provided")
	}
	if template.Info.Authors.IsEmpty() {
		return nil, errors.New("no template author field provided")
	}

	// Setting up variables regarding template metadata
	options.TemplateID = template.ID
	options.TemplateInfo = template.Info
	options.TemplatePath = filePath

	// If no requests, and it is also not a workflow, return error.
	if template.Requests() == 0 {
		return nil, fmt.Errorf("no requests defined for %s", template.ID)
	}

	// Compile the workflow request
	if len(template.Workflows) > 0 {
		compiled := &template.Workflow

		compileWorkflow(filePath, preprocessor, &options, compiled, options.WorkflowLoader)
		template.CompiledWorkflow = compiled
		template.CompiledWorkflow.Options = &options
	}

	if err := template.compileProtocolRequests(options); err != nil {
		return nil, err
	}

	// if len(template.RequestCode) > 0 && !options.Options.OfflineHTTP {
	// 	for _, req := range template.RequestCode {
	// 		requests = append(requests, req)
	// 	}
	// 	template.Executer = executer.NewExecuter(requests, &options)
	// }
	if template.Executer != nil {
		if err := template.Executer.Compile(); err != nil {
			return nil, errors.Wrap(err, "could not compile request")
		}
		template.TotalRequests = template.Executer.Requests()
	}
	if template.Executer == nil && template.CompiledWorkflow == nil {
		return nil, ErrCreateTemplateExecutor
	}
	template.Path = filePath

	template.parseSelfContainedRequests()

	parsedTemplatesCache.Store(filePath, template, err)
	return template, nil
}

// parseSelfContainedRequests parses the self contained template requests.
func (template *Template) parseSelfContainedRequests() {
	if !template.SelfContained {
		return
	}
	for _, request := range template.RequestsHTTP {
		request.SelfContained = true
	}
	for _, request := range template.RequestsNetwork {
		request.SelfContained = true
	}
}

// Requests returns the total request count for the template
func (template *Template) Requests() int {
	return len(template.RequestsDNS) +
		len(template.RequestsHTTP) +
		len(template.RequestsFile) +
		len(template.RequestsNetwork) +
		len(template.RequestsHeadless) +
		len(template.Workflows) +
		len(template.RequestsSSL) +
		len(template.RequestsWebsocket)
}

// compileProtocolRequests compiles all the protocol requests for the template
func (template *Template) compileProtocolRequests(options protocols.ExecuterOptions) error {
	templateRequests := template.Requests()

	if templateRequests == 0 {
		return fmt.Errorf("no requests defined for %s", template.ID)
	}

	if options.Options.OfflineHTTP {
		template.compileOfflineHTTPRequest(options)
		return nil
	}

	var requests []protocols.Request
	switch {
	case len(template.RequestsDNS) > 0:
		requests = template.convertRequestToProtocolsRequest(template.RequestsDNS)

	case len(template.RequestsFile) > 0:
		requests = template.convertRequestToProtocolsRequest(template.RequestsFile)

	case len(template.RequestsNetwork) > 0:
		requests = template.convertRequestToProtocolsRequest(template.RequestsNetwork)

	case len(template.RequestsHTTP) > 0:
		requests = template.convertRequestToProtocolsRequest(template.RequestsHTTP)

	case len(template.RequestsHeadless) > 0 && options.Options.Headless:
		requests = template.convertRequestToProtocolsRequest(template.RequestsHeadless)

	case len(template.RequestsSSL) > 0:
		requests = template.convertRequestToProtocolsRequest(template.RequestsSSL)

	case len(template.RequestsWebsocket) > 0:
		requests = template.convertRequestToProtocolsRequest(template.RequestsWebsocket)
	}
	template.Executer = executer.NewExecuter(requests, &options)
	return nil
}

// convertRequestToProtocolsRequest is a convenience wrapper to convert
// arbitrary interfaces which are slices of requests from the template to a
// slice of protocols.Request interface items.
func (template *Template) convertRequestToProtocolsRequest(requests interface{}) []protocols.Request {
	switch reflect.TypeOf(requests).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(requests)

		requestSlice := make([]protocols.Request, s.Len())
		for i := 0; i < s.Len(); i++ {
			value := s.Index(i)
			valueInterface := value.Interface()
			requestSlice[i] = valueInterface.(protocols.Request)
		}
		return requestSlice
	}
	return nil
}

// compileOfflineHTTPRequest iterates all requests if offline http mode is
// specified and collects all matchers for all the base request templates
// (those with URL {{BaseURL}} and it's slash variation.)
func (template *Template) compileOfflineHTTPRequest(options protocols.ExecuterOptions) {
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
}
