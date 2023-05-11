package multi

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"golang.org/x/exp/maps"
)

var _ protocols.Request = &Request{}

// refer doc.go for package description , limitations etc

// Request contains a multi protocol request
type Request struct {
	// description: |
	//   ID is the unique id for the template.
	//
	//   #### Good IDs
	//
	//   A good ID uniquely identifies what the requests in the template
	//   are doing. Let's say you have a template that identifies a git-config
	//   file on the webservers, a good name would be `git-config-exposure`. Another
	//   example name is `azure-apps-nxdomain-takeover`.
	// examples:
	//   - name: ID Example
	//     value: "\"CVE-2021-19520\""
	ID string `yaml:"id" json:"id" jsonschema:"title=id of the template,description=The Unique ID for the template,example=cve-2021-19520,pattern=^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$"`
	// description: |
	//   Info contains metadata information about the template.
	// examples:
	//   - value: exampleInfoStructure
	Info model.Info `yaml:"info" json:"info" jsonschema:"title=info for the template,description=Info contains metadata for the template"`

	// Queue is queue of all protocols present in the template
	Queue []protocols.Request `yaml:"-" json:"-"`
	// request executor options
	options *protocols.ExecuterOptions `yaml:"-" json:"-"`
}

// getLastRequest returns the last request in the queue
func (r *Request) getLastRequest() protocols.Request {
	if len(r.Queue) == 0 {
		return nil
	}
	return r.Queue[len(r.Queue)-1]
}

// Requests returns the total number of requests template will send
func (r *Request) Requests() int {
	var count int
	for _, protocol := range r.Queue {
		count += protocol.Requests()
	}
	return count
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(executerOptions *protocols.ExecuterOptions) error {
	r.options = executerOptions
	for _, protocol := range r.Queue {
		if err := protocol.Compile(executerOptions); err != nil {
			return err
		}
	}
	return nil
}

// GetID returns the unique template ID
func (r *Request) GetID() string {
	return r.ID
}

// Match executes matcher on model and returns true or false (used for clustering if request supports clustering)
func (r *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	return protocols.MakeDefaultMatchFunc(data, matcher)
}

// Extract performs extracting operation for an extractor on model and returns true or false (used for clustering if request supports clustering)
func (r *Request) Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{} {
	return protocols.MakeDefaultExtractFunc(data, matcher)
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input *contextargs.Context, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	allProtoEvents := []*output.InternalWrappedEvent{}
	// contains values from previous protocols
	templateContextValues := maps.Clone(dynamicValues)
	// callback to process results from all protocols
	multiProtoCallback := func(event *output.InternalWrappedEvent) {
		allProtoEvents = append(allProtoEvents, event)
		if event.OperatorsResult != nil && len(event.OperatorsResult.DynamicValues) > 0 {
			for k, v := range event.OperatorsResult.DynamicValues {
				// TBD: iterate-all is only supported in `http` protocol
				// we either need to add support for iterate-all in other protocols or implement a different logic (specific to template context)

				// currently if dynamic value array only contains one value we replace it with the value
				if len(v) == 1 {
					templateContextValues[k] = v[0]
				} else {
					templateContextValues[k] = v
				}
			}
		}
	}

	// template context: contains values extracted using `internal` extractor from previous protocols
	// these values are extracted from each protocol in queue and are passed to next protocol in queue
	// instead of adding seperator field to handle such cases these values are appended to `dynamicValues` (which are meant to be used in workflows)
	// this makes it possible to use multi protocol templates in workflows
	// Note: internal extractor values take precedence over dynamicValues from workflows (i.e other templates in workflow)

	// execute all protocols in the queue
	for _, req := range r.Queue {
		err := req.ExecuteWithResults(input, templateContextValues, previous, multiProtoCallback)
		// if error skip execution of next protocols
		if err != nil {
			return err
		}
	}

	// Review: how to handle events of multiple protocols in a single template
	// currently we execute outputEventcallback for each protocol after all protocols are executed successfully
	// Another approach is to just execute callback on last protocol in queue (TBD)
	for _, v := range allProtoEvents {
		callback(v)
	}

	return nil
}

// MakeResultEventItem creates a result event from internal wrapped event. Intended to be used by MakeResultEventItem internally
func (r *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	if r.getLastRequest() == nil {
		return nil
	}
	return r.getLastRequest().MakeResultEventItem(wrapped)
}

// MakeResultEvent creates a flat list of result events from an internal wrapped event, based on successful matchers and extracted data
func (r *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(r.getLastRequest(), wrapped)
}

// GetCompiledOperators returns a list of the compiled operators
func (r *Request) GetCompiledOperators() []*operators.Operators {
	last := r.getLastRequest()
	if last == nil {
		return nil
	}
	return last.GetCompiledOperators()
}

// Type returns the type of the protocol request
func (r *Request) Type() types.ProtocolType {
	return types.MultiProtocol
}
