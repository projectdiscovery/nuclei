//go:generate dstdocgen -path "" -structure Template -output templates_doc.go -package templates
package templates

import (
	"io"
	"path/filepath"
	"strconv"
	"strings"

	validate "github.com/go-playground/validator/v10"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/code"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/file"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/javascript"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/ssl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/websocket"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/whois"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
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
	ID string `yaml:"id" json:"id" jsonschema:"title=id of the template,description=The Unique ID for the template,required,example=cve-2021-19520,pattern=^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$"`
	// description: |
	//   Info contains metadata information about the template.
	// examples:
	//   - value: exampleInfoStructure
	Info model.Info `yaml:"info" json:"info" jsonschema:"title=info for the template,description=Info contains metadata for the template,required,type=object"`
	// description: |
	//   Flow contains the execution flow for the template.
	// examples:
	//   - flow: |
	// 		for region in regions {
	//		    http(0)
	//		 }
	//		 for vpc in vpcs {
	//		    http(1)
	//		 }
	//
	Flow string `yaml:"flow,omitempty" json:"flow,omitempty" jsonschema:"title=template execution flow in js,description=Flow contains js code which defines how the template should be executed,type=string,example='flow: http(0) && http(1)'"`
	// description: |
	//   Requests contains the http request to make in the template.
	//   WARNING: 'requests' will be deprecated and will be removed in a future release. Please use 'http' instead.
	// examples:
	//   - value: exampleNormalHTTPRequest
	RequestsHTTP []*http.Request `yaml:"requests,omitempty" json:"requests,omitempty" jsonschema:"title=http requests to make,description=HTTP requests to make for the template,deprecated=true"`
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
	RequestsNetwork []*network.Request `yaml:"network,omitempty" json:"network,omitempty" jsonschema:"title=network requests to make,description=Network requests to make for the template,deprecated=true"`
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
	//   Code contains code snippets.
	RequestsCode []*code.Request `yaml:"code,omitempty" json:"code,omitempty" jsonschema:"title=code snippets to make,description=Code snippets"`
	// description: |
	//   Javascript contains the javascript request to make in the template.
	RequestsJavascript []*javascript.Request `yaml:"javascript,omitempty" json:"javascript,omitempty" jsonschema:"title=javascript requests to make,description=Javascript requests to make for the template"`

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
	//   WARNING: 'signature' will be deprecated and will be removed in a future release. Prefer using 'code' protocol for writing cloud checks
	// values:
	//   - "AWS"
	Signature http.SignatureTypeHolder `yaml:"signature,omitempty" json:"signature,omitempty" jsonschema:"title=signature is the http request signature method,description=Signature is the HTTP Request signature Method,enum=AWS,deprecated=true"`

	// description: |
	//   Variables contains any variables for the current request.
	Variables variables.Variable `yaml:"variables,omitempty" json:"variables,omitempty" jsonschema:"title=variables for the http request,description=Variables contains any variables for the current request,type=object"`

	// description: |
	//   Constants contains any scalar constant for the current template
	Constants map[string]interface{} `yaml:"constants,omitempty" json:"constants,omitempty" jsonschema:"title=constant for the template,description=constants contains any constant for the template,type=object"`

	// TotalRequests is the total number of requests for the template.
	TotalRequests int `yaml:"-" json:"-"`
	// Executer is the actual template executor for running template requests
	Executer protocols.Executer `yaml:"-" json:"-"`

	Path string `yaml:"-" json:"-"`

	// Verified defines if the template signature is digitally verified
	Verified bool `yaml:"-" json:"-"`
	// TemplateVerifier is identifier verifier used to verify the template (default nuclei-templates have projectdiscovery/nuclei-templates)
	TemplateVerifier string `yaml:"-" json:"-"`
	// RequestsQueue contains all template requests in order (both protocol & request order)
	RequestsQueue []protocols.Request `yaml:"-" json:"-"`

	// ImportedFiles contains list of files whose contents are imported after template was compiled
	ImportedFiles []string `yaml:"-" json:"-"`
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
	case len(template.RequestsSSL) > 0:
		return types.SSLProtocol
	case len(template.RequestsWebsocket) > 0:
		return types.WebsocketProtocol
	case len(template.RequestsWHOIS) > 0:
		return types.WHOISProtocol
	case len(template.RequestsCode) > 0:
		return types.CodeProtocol
	case len(template.RequestsJavascript) > 0:
		return types.JavascriptProtocol
	case len(template.Workflow.Workflows) > 0:
		return types.WorkflowProtocol
	default:
		return types.InvalidProtocol
	}
}

// IsFuzzing returns true if the template is a fuzzing template
func (template *Template) IsFuzzing() bool {
	if len(template.RequestsHTTP) == 0 && len(template.RequestsHeadless) == 0 {
		// fuzzing is only supported for http and headless protocols
		return false
	}
	if len(template.RequestsHTTP) > 0 {
		for _, request := range template.RequestsHTTP {
			if len(request.Fuzzing) > 0 {
				return true
			}
		}
	}
	if len(template.RequestsHeadless) > 0 {
		for _, request := range template.RequestsHeadless {
			if len(request.Fuzzing) > 0 {
				return true
			}
		}
	}
	return false
}

// UsesRequestSignature returns true if the template uses a request signature like AWS
func (template *Template) UsesRequestSignature() bool {
	return template.Signature.Value.String() != ""
}

// HasCodeProtocol returns true if the template has a code protocol section
func (template *Template) HasCodeProtocol() bool {
	return len(template.RequestsCode) > 0
}

// validateAllRequestIDs check if that protocol already has given id if not
// then is is manually set to proto_index
func (template *Template) validateAllRequestIDs() {
	// this is required in multiprotocol and flow where we save response variables
	// and all other data in template context if template as two requests in a protocol
	// then it is overwritten to avoid this we use proto_index as request ID
	if len(template.RequestsCode) > 1 {
		for i, req := range template.RequestsCode {
			if req.ID == "" {
				req.ID = req.Type().String() + "_" + strconv.Itoa(i+1)
			}
		}
	}

	if len(template.RequestsDNS) > 1 {
		for i, req := range template.RequestsDNS {
			if req.ID == "" {
				req.ID = req.Type().String() + "_" + strconv.Itoa(i+1)
			}
		}
	}
	if len(template.RequestsFile) > 1 {
		for i, req := range template.RequestsFile {
			if req.ID == "" {
				req.ID = req.Type().String() + "_" + strconv.Itoa(i+1)
			}
		}
	}
	if len(template.RequestsHTTP) > 1 {
		for i, req := range template.RequestsHTTP {
			if req.ID == "" {
				req.ID = req.Type().String() + "_" + strconv.Itoa(i+1)
			}
		}
	}
	if len(template.RequestsHeadless) > 1 {
		for i, req := range template.RequestsHeadless {
			if req.ID == "" {
				req.ID = req.Type().String() + "_" + strconv.Itoa(i+1)
			}
		}

	}
	if len(template.RequestsNetwork) > 1 {
		for i, req := range template.RequestsNetwork {
			if req.ID == "" {
				req.ID = req.Type().String() + "_" + strconv.Itoa(i+1)
			}
		}
	}
	if len(template.RequestsSSL) > 1 {
		for i, req := range template.RequestsSSL {
			if req.ID == "" {
				req.ID = req.Type().String() + "_" + strconv.Itoa(i+1)
			}
		}
	}
	if len(template.RequestsWebsocket) > 1 {
		for i, req := range template.RequestsWebsocket {
			if req.ID == "" {
				req.ID = req.Type().String() + "_" + strconv.Itoa(i+1)
			}
		}
	}
	if len(template.RequestsWHOIS) > 1 {
		for i, req := range template.RequestsWHOIS {
			if req.ID == "" {
				req.ID = req.Type().String() + "_" + strconv.Itoa(i+1)
			}
		}
	}
	if len(template.RequestsJavascript) > 1 {
		for i, req := range template.RequestsJavascript {
			if req.ID == "" {
				req.ID = req.Type().String() + "_" + strconv.Itoa(i+1)
			}
		}
	}
}

// MarshalYAML forces recursive struct validation during marshal operation
func (template *Template) MarshalYAML() ([]byte, error) {
	out, marshalErr := yaml.Marshal(template)
	// Review: we are adding requestIDs for templateContext
	// if we are using this method then we might need to purge manually added IDS that start with `templatetype_`
	// this is only applicable if there are more than 1 request fields in protocol
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

	if !ReTemplateID.MatchString(template.ID) {
		return errorutil.New("template id must match expression %v", ReTemplateID).WithTag("invalid template")
	}
	info := template.Info
	if utils.IsBlank(info.Name) {
		return errorutil.New("no template name field provided").WithTag("invalid template")
	}
	if info.Authors.IsEmpty() {
		return errorutil.New("no template author field provided").WithTag("invalid template")
	}

	if len(template.RequestsHTTP) > 0 || len(template.RequestsNetwork) > 0 {
		_ = deprecatedProtocolNameTemplates.Set(template.ID, true)
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
	// check if the template contains more than 1 protocol request
	// if so  preserve the order of the protocols and requests
	if template.hasMultipleRequests() {
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
		template.addRequestsToQueue(arr...)
	}
	return nil
}

// ImportFileRefs checks if sensitive fields like `flow` , `source` in code protocol are referencing files
// instead of actual javascript / engine code if so it loads the file contents and replaces the reference
func (template *Template) ImportFileRefs(options *protocols.ExecutorOptions) error {
	var errs []error

	loadFile := func(source string) (string, bool) {
		// load file respecting sandbox
		data, err := options.Options.LoadHelperFile(source, options.TemplatePath, options.Catalog)
		if err == nil {
			defer data.Close()
			bin, err := io.ReadAll(data)
			if err == nil {
				return string(bin), true
			} else {
				errs = append(errs, err)
			}
		} else {
			errs = append(errs, err)
		}
		return "", false
	}

	// for code protocol requests
	for _, request := range template.RequestsCode {
		// simple test to check if source is a file or a snippet
		if len(strings.Split(request.Source, "\n")) == 1 && fileutil.FileExists(request.Source) {
			if val, ok := loadFile(request.Source); ok {
				template.ImportedFiles = append(template.ImportedFiles, request.Source)
				request.Source = val
			}
		}
	}

	// for javascript protocol code references
	for _, request := range template.RequestsJavascript {
		// simple test to check if source is a file or a snippet
		if len(strings.Split(request.Code, "\n")) == 1 && fileutil.FileExists(request.Code) {
			if val, ok := loadFile(request.Code); ok {
				template.ImportedFiles = append(template.ImportedFiles, request.Code)
				request.Code = val
			}
		}
	}

	// flow code references
	if template.Flow != "" {
		if len(template.Flow) > 0 && filepath.Ext(template.Flow) == ".js" && fileutil.FileExists(template.Flow) {
			if val, ok := loadFile(template.Flow); ok {
				template.ImportedFiles = append(template.ImportedFiles, template.Flow)
				template.Flow = val
			}
		}
		options.Flow = template.Flow
	}

	// for multiprotocol requests
	// mutually exclusive with flow
	if len(template.RequestsQueue) > 0 && template.Flow == "" {
		// this is most likely a multiprotocol template
		for _, req := range template.RequestsQueue {
			if req.Type() == types.CodeProtocol {
				request := req.(*code.Request)
				// simple test to check if source is a file or a snippet
				if len(strings.Split(request.Source, "\n")) == 1 && fileutil.FileExists(request.Source) {
					if val, ok := loadFile(request.Source); ok {
						template.ImportedFiles = append(template.ImportedFiles, request.Source)
						request.Source = val
					}
				}
			}
		}

		// for javascript protocol code references
		for _, req := range template.RequestsQueue {
			if req.Type() == types.JavascriptProtocol {
				request := req.(*javascript.Request)
				// simple test to check if source is a file or a snippet
				if len(strings.Split(request.Code, "\n")) == 1 && fileutil.FileExists(request.Code) {
					if val, ok := loadFile(request.Code); ok {
						template.ImportedFiles = append(template.ImportedFiles, request.Code)
						request.Code = val
					}
				}
			}
		}
	}

	return multierr.Combine(errs...)
}

// GetFileImports returns a list of files that are imported by the template
func (template *Template) GetFileImports() []string {
	return template.ImportedFiles
}

// addProtocolsToQueue adds protocol requests to the queue and preserves order of the protocols and requests
func (template *Template) addRequestsToQueue(keys ...string) {
	for _, key := range keys {
		switch key {
		case types.DNSProtocol.String():
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsDNS)...)
		case types.FileProtocol.String():
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsFile)...)
		case types.HTTPProtocol.String():
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsHTTP)...)
		case types.HeadlessProtocol.String():
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsHeadless)...)
		case types.NetworkProtocol.String():
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsNetwork)...)
		case types.SSLProtocol.String():
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsSSL)...)
		case types.WebsocketProtocol.String():
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsWebsocket)...)
		case types.WHOISProtocol.String():
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsWHOIS)...)
		case types.CodeProtocol.String():
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsCode)...)
		case types.JavascriptProtocol.String():
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsJavascript)...)
			// for deprecated protocols
		case "requests":
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsHTTP)...)
		case "network":
			template.RequestsQueue = append(template.RequestsQueue, template.convertRequestToProtocolsRequest(template.RequestsNetwork)...)
		}
	}
}

// hasMultipleRequests checks if the template has multiple requests
// if so it preserves the order of the request during compile and execution
func (template *Template) hasMultipleRequests() bool {
	counter := len(template.RequestsDNS) + len(template.RequestsFile) +
		len(template.RequestsHTTP) + len(template.RequestsHeadless) +
		len(template.RequestsNetwork) + len(template.RequestsSSL) +
		len(template.RequestsWebsocket) + len(template.RequestsWHOIS) +
		len(template.RequestsCode) + len(template.RequestsJavascript)
	return counter > 1
}

// MarshalJSON forces recursive struct validation during marshal operation
func (template *Template) MarshalJSON() ([]byte, error) {
	type TemplateAlias Template //avoid recursion
	out, marshalErr := json.Marshal((*TemplateAlias)(template))
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
	// check if the template contains more than 1 protocol request
	// if so  preserve the order of the protocols and requests
	if template.hasMultipleRequests() {
		var tempMap map[string]interface{}
		err = json.Unmarshal(data, &tempMap)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("failed to unmarshal multi protocol template %s", template.ID)
		}
		arr := []string{}
		for k := range tempMap {
			arr = append(arr, k)
		}
		template.addRequestsToQueue(arr...)
	}
	return nil
}

// HasFileProtocol returns true if the template has a file protocol section
func (template *Template) HasFileProtocol() bool {
	return len(template.RequestsFile) > 0
}
