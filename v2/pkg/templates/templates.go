//go:generate dstdocgen -path "" -structure Template -output templates_doc.go -package templates
package templates

import (
	"encoding/json"

	validate "github.com/go-playground/validator/v10"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/file"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/ssl"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/websocket"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/whois"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v2"
)

const (
	// TemplateExtension defines the template default file extension
	TemplateExtension = ".yaml"
)

// Template is a YAML input file which defines all the requests and
// other metadata for a template.
type Template struct {
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
	ID string `yaml:"id" jsonschema:"title=id of the template,description=The Unique ID for the template,example=cve-2021-19520,pattern=^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$"`
	// description: |
	//   Info contains metadata information about the template.
	// examples:
	//   - value: exampleInfoStructure
	Info model.Info `yaml:"info" jsonschema:"title=info for the template,description=Info contains metadata for the template"`
	// description: |
	//   Requests contains the http request to make in the template.
	// examples:
	//   - value: exampleNormalHTTPRequest
	RequestsHTTP []*http.Request `yaml:"requests,omitempty" json:"requests,omitempty" jsonschema:"title=http requests to make,description=HTTP requests to make for the template"`
	// description: |
	//   DNS contains the dns request to make in the template
	// examples:
	//   - value: exampleNormalDNSRequest
	RequestsDNS []*dns.Request `yaml:"dns,omitempty" json:"dns,omitempty" jsonschema:"title=dns requests to make,description=DNS requests to make for the template"`
	// description: |
	//   File contains the file request to make in the template
	// examples:
	//   - value: exampleNormalFileRequest
	RequestsFile []*file.Request `yaml:"file,omitempty" json:"file,omitempty" jsonschema:"title=file requests to make,description=File requests to make for the template"`
	// description: |
	//   Network contains the network request to make in the template
	// examples:
	//   - value: exampleNormalNetworkRequest
	RequestsNetwork []*network.Request `yaml:"network,omitempty" json:"network,omitempty" jsonschema:"title=network requests to make,description=Network requests to make for the template"`
	// description: |
	//   Headless contains the headless request to make in the template.
	RequestsHeadless []*headless.Request `yaml:"headless,omitempty" json:"headless,omitempty" jsonschema:"title=headless requests to make,description=Headless requests to make for the template"`
	// description: |
	//   SSL contains the SSL request to make in the template.
	RequestsSSL []*ssl.Request `yaml:"ssl,omitempty" json:"ssl,omitempty" jsonschema:"title=ssl requests to make,description=SSL requests to make for the template"`
	// description: |
	//   Websocket contains the Websocket request to make in the template.
	RequestsWebsocket []*websocket.Request `yaml:"websocket,omitempty" json:"websocket,omitempty" jsonschema:"title=websocket requests to make,description=Websocket requests to make for the template"`

	// description: |
	//   WHOIS contains the WHOIS request to make in the template.
	RequestsWHOIS []*whois.Request `yaml:"whois,omitempty" json:"whois,omitempty" jsonschema:"title=whois requests to make,description=WHOIS requests to make for the template"`
	// description: |
	//   Workflows is a yaml based workflow declaration code.
	workflows.Workflow `yaml:",inline,omitempty" jsonschema:"title=workflows to run,description=Workflows to run for the template"`
	CompiledWorkflow   *workflows.Workflow `yaml:"-" json:"-" jsonschema:"-"`

	// description: |
	//   Self Contained marks Requests for the template as self-contained
	SelfContained bool `yaml:"self-contained,omitempty" jsonschema:"title=mark requests as self-contained,description=Mark Requests for the template as self-contained"`
	// description: |
	//  Stop execution once first match is found
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty" jsonschema:"title=stop at first match,description=Stop at first match for the template"`

	// description: |
	//   Signature is the request signature method
	// values:
	//   - "AWS"
	Signature http.SignatureTypeHolder `yaml:"signature,omitempty" jsonschema:"title=signature is the http request signature method,description=Signature is the HTTP Request signature Method,enum=AWS"`

	// TotalRequests is the total number of requests for the template.
	TotalRequests int `yaml:"-" json:"-"`
	// Executer is the actual template executor for running template requests
	Executer protocols.Executer `yaml:"-" json:"-"`

	Path string `yaml:"-" json:"-"`
}

// TemplateProtocols is a list of accepted template protocols
var TemplateProtocols = []string{
	"dns",
	"file",
	"http",
	"headless",
	"network",
	"workflow",
	"ssl",
	"websocket",
	"whois",
}

// Type returns the type of the template
func (template *Template) Type() types.ProtocolType {
	switch {
	case len(template.RequestsDNS) > 0:
		return types.DNSProtocol
	case len(template.RequestsFile) > 0:
		return types.FileProtocol
	case len(template.RequestsHTTP) > 0:
		return types.HTTPProtocol
	case len(template.RequestsHeadless) > 0:
		return types.HeadlessProtocol
	case len(template.RequestsNetwork) > 0:
		return types.NetworkProtocol
	case len(template.Workflow.Workflows) > 0:
		return types.WorkflowProtocol
	case len(template.RequestsSSL) > 0:
		return types.SSLProtocol
	case len(template.RequestsWebsocket) > 0:
		return types.WebsocketProtocol
	case len(template.RequestsWHOIS) > 0:
		return types.WHOISProtocol
	default:
		return types.InvalidProtocol
	}
}

// MarshalYAML forces recursive struct validation during marshal operation
func (template *Template) MarshalYAML() ([]byte, error) {
	out, marshalErr := yaml.Marshal(template)
	errValidate := validate.New().Struct(template)
	return out, multierr.Append(marshalErr, errValidate)
}

// MarshalYAML forces recursive struct validation after unmarshal operation
func (template *Template) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type Alias Template
	alias := &Alias{}
	err := unmarshal(alias)
	if err != nil {
		return err
	}
	*template = Template(*alias)
	return validate.New().Struct(template)
}

// MarshalJSON forces recursive struct validation during marshal operation
func (template *Template) MarshalJSON() ([]byte, error) {
	out, marshalErr := json.Marshal(template)
	errValidate := validate.New().Struct(template)
	return out, multierr.Append(marshalErr, errValidate)
}

// UnmarshalJSON forces recursive struct validation after unmarshal operation
func (template *Template) UnmarshalJSON(data []byte) error {
	type Alias Template
	alias := &Alias{}
	err := json.Unmarshal(data, alias)
	if err != nil {
		return err
	}
	*template = Template(*alias)
	return validate.New().Struct(template)
}
