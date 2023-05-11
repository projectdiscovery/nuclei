//go:generate dstdocgen -path "" -structure Template -output templates_doc.go -package templates
package templates

import (
	"encoding/json"

	validate "github.com/go-playground/validator/v10"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/file"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/multi"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/ssl"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/websocket"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/whois"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
	errorutil "github.com/projectdiscovery/utils/errors"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v2"
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
	ID string `yaml:"id" json:"id" jsonschema:"title=id of the template,description=The Unique ID for the template,example=cve-2021-19520,pattern=^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$"`
	// description: |
	//   Info contains metadata information about the template.
	// examples:
	//   - value: exampleInfoStructure
	Info model.Info `yaml:"info" json:"info" jsonschema:"title=info for the template,description=Info contains metadata for the template"`
	// description: |
	//   Requests contains the http request to make in the template.
	//   WARNING: 'requests' will be deprecated and will be removed in a future release. Please use 'http' instead.
	// examples:
	//   - value: exampleNormalHTTPRequest
	RequestsHTTP []*http.Request `yaml:"requests,omitempty" json:"requests,omitempty" jsonschema:"title=http requests to make,description=HTTP requests to make for the template"`
	// description: |
	//   HTTP contains the http request to make in the template.
	// examples:
	//   - value: exampleNormalHTTPRequest
	// RequestsWithHTTP is placeholder(internal) only, and should not be used instead use RequestsHTTP
	// Deprecated: Use RequestsHTTP instead.
	RequestsWithHTTP []*http.Request `yaml:"http,omitempty" json:"http,omitempty" jsonschema:"title=http requests to make,description=HTTP requests to make for the template"`
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
	//   WARNING: 'network' will be deprecated and will be removed in a future release. Please use 'tcp' instead.
	// examples:
	//   - value: exampleNormalNetworkRequest
	RequestsNetwork []*network.Request `yaml:"network,omitempty" json:"network,omitempty" jsonschema:"title=network requests to make,description=Network requests to make for the template"`
	// description: |
	//   TCP contains the network request to make in the template
	// examples:
	//   - value: exampleNormalNetworkRequest
	// RequestsWithTCP is placeholder(internal) only, and should not be used instead use RequestsNetwork
	// Deprecated: Use RequestsNetwork instead.
	RequestsWithTCP []*network.Request `yaml:"tcp,omitempty" json:"tcp,omitempty" jsonschema:"title=network(tcp) requests to make,description=Network requests to make for the template"`
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
	SelfContained bool `yaml:"self-contained,omitempty" json:"self-contained,omitempty" jsonschema:"title=mark requests as self-contained,description=Mark Requests for the template as self-contained"`
	// description: |
	//  Stop execution once first match is found
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty" jsonschema:"title=stop at first match,description=Stop at first match for the template"`

	// description: |
	//   Signature is the request signature method
	// values:
	//   - "AWS"
	Signature http.SignatureTypeHolder `yaml:"signature,omitempty" json:"signature,omitempty" jsonschema:"title=signature is the http request signature method,description=Signature is the HTTP Request signature Method,enum=AWS"`

	// description: |
	//   Variables contains any variables for the current request.
	Variables variables.Variable `yaml:"variables,omitempty" json:"variables,omitempty" jsonschema:"title=variables for the http request,description=Variables contains any variables for the current request"`

	// TotalRequests is the total number of requests for the template.
	TotalRequests int `yaml:"-" json:"-"`
	// Executer is the actual template executor for running template requests
	Executer protocols.Executer `yaml:"-" json:"-"`

	Path string `yaml:"-" json:"-"`

	// Verified defines if the template signature is digitally verified
	Verified bool `yaml:"-" json:"-"`

	// MultiProtoRequest (Internal) contains multi protocol request if multiple protocols are used
	MultiProtoRequest multi.Request `yaml:"-" json:"-"`
}

// Type returns the type of the template
func (template *Template) Type() types.ProtocolType {
	switch {
	case len(template.MultiProtoRequest.Queue) > 0:
		return types.MultiProtocol
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

	if len(template.RequestsHTTP) > 0 || len(template.RequestsNetwork) > 0 {
		deprecatedProtocolNameTemplates.Store(template.ID, struct{}{})
	}

	if len(alias.RequestsHTTP) > 0 && len(alias.RequestsWithHTTP) > 0 {
		return errorutil.New("use http or requests, both are not supported").WithTag("invalid template")
	}
	if len(alias.RequestsNetwork) > 0 && len(alias.RequestsWithTCP) > 0 {
		return errorutil.New("use tcp or network, both are not supported").WithTag("invalid template")
	}
	if len(alias.RequestsWithHTTP) > 0 {
		template.RequestsHTTP = alias.RequestsWithHTTP
	}
	if len(alias.RequestsWithTCP) > 0 {
		template.RequestsNetwork = alias.RequestsWithTCP
	}
	err = validate.New().Struct(template)
	if err != nil {
		return err
	}
	// check if the template contains a multi protocols
	if template.isMultiProtocol() {
		var tempmap yaml.MapSlice
		err = unmarshal(&tempmap)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("failed to unmarshal multi protocol template %s", template.ID)
		}
		arr := []string{}
		for _, v := range tempmap {
			key, ok := v.Key.(string)
			if !ok {
				continue
			}
			arr = append(arr, key)
		}
		// add protocols to the protocol stack (the idea is to preserve the order of the protocols)
		template.addProtocolsToQueue(arr...)
	}
	return nil
}

// Internal function to create a protocol stack from a template if the template is a multi protocol template
func (template *Template) addProtocolsToQueue(keys ...string) {
	for _, key := range keys {
		switch key {
		case types.DNSProtocol.String():
			template.MultiProtoRequest.Queue = append(template.MultiProtoRequest.Queue, template.convertRequestToProtocolsRequest(template.RequestsDNS)...)
		case types.FileProtocol.String():
			template.MultiProtoRequest.Queue = append(template.MultiProtoRequest.Queue, template.convertRequestToProtocolsRequest(template.RequestsFile)...)
		case types.HTTPProtocol.String():
			template.MultiProtoRequest.Queue = append(template.MultiProtoRequest.Queue, template.convertRequestToProtocolsRequest(template.RequestsHTTP)...)
		case types.HeadlessProtocol.String():
			template.MultiProtoRequest.Queue = append(template.MultiProtoRequest.Queue, template.convertRequestToProtocolsRequest(template.RequestsHeadless)...)
		case types.NetworkProtocol.String():
			template.MultiProtoRequest.Queue = append(template.MultiProtoRequest.Queue, template.convertRequestToProtocolsRequest(template.RequestsNetwork)...)
		case types.SSLProtocol.String():
			template.MultiProtoRequest.Queue = append(template.MultiProtoRequest.Queue, template.convertRequestToProtocolsRequest(template.RequestsSSL)...)
		case types.WebsocketProtocol.String():
			template.MultiProtoRequest.Queue = append(template.MultiProtoRequest.Queue, template.convertRequestToProtocolsRequest(template.RequestsWebsocket)...)
		case types.WHOISProtocol.String():
			template.MultiProtoRequest.Queue = append(template.MultiProtoRequest.Queue, template.convertRequestToProtocolsRequest(template.RequestsWHOIS)...)
		}
	}
}

// isMultiProtocol checks if the template is a multi protocol template
func (template *Template) isMultiProtocol() bool {
	counter := len(template.RequestsDNS) + len(template.RequestsFile) +
		len(template.RequestsHTTP) + len(template.RequestsHeadless) +
		len(template.RequestsNetwork) + len(template.RequestsSSL) +
		len(template.RequestsWebsocket) + len(template.RequestsWHOIS)
	return counter > 1
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
	err = validate.New().Struct(template)
	if err != nil {
		return err
	}
	// check if template contains multiple protocols
	if template.isMultiProtocol() {
		var tempMap map[string]interface{}
		err = json.Unmarshal(data, &tempMap)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("failed to unmarshal multi protocol template %s", template.ID)
		}
		arr := []string{}
		for k := range tempMap {
			arr = append(arr, k)
		}
		template.addProtocolsToQueue(arr...)
	}
	return nil
}
