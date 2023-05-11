package multi

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

var _ protocols.Request = &Request{}

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

	// description: |
	//   Variables contains any variables for the current request.
	Variables variables.Variable `yaml:"variables,omitempty" json:"variables,omitempty" jsonschema:"title=variables for the http request,description=Variables contains any variables for the current request"`

	// dynamicVariables contains all dynamic variables for the template
	// these are populated after execution of every protocol in Queue
	dynamicVariables map[string]interface{} `yaml:"-" json:"-"`

	// Queue is queue of all protocols present in the template
	Queue []protocols.Request `yaml:"-" json:"-"`
	// request executor options
	options *protocols.ExecuterOptions `yaml:"-" json:"-"`
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

func (r *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	return false, nil
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (r *Request) Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{} {
	return nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input *contextargs.Context, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	return nil
}

// MakeResultEventItem creates a result event from internal wrapped event. Intended to be used by MakeResultEventItem internally
func (r *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	return nil
}

// MakeResultEvent creates a flat list of result events from an internal wrapped event, based on successful matchers and extracted data
func (r *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return nil
}

// GetCompiledOperators returns a list of the compiled operators
func (r *Request) GetCompiledOperators() []*operators.Operators {
	return nil
}

// Type returns the type of the protocol request
func (r *Request) Type() types.ProtocolType {
	return types.MultiProtocol
}
