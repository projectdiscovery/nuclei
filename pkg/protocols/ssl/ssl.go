package ssl

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cespare/xxhash"
	"github.com/fatih/structs"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network/networkclientpool"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/openssl"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// Request is a request for the SSL protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty" json:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-" json:"-"`

	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" json:"id,omitempty" jsonschema:"title=id of the request,description=ID of the request"`

	// description: |
	//   Address contains address for the request
	Address string `yaml:"address,omitempty" json:"address,omitempty" jsonschema:"title=address for the ssl request,description=Address contains address for the request"`
	// description: |
	//   Minimum tls version - auto if not specified.
	// values:
	//   - "sslv3"
	//   - "tls10"
	//   - "tls11"
	//   - "tls12"
	//   - "tls13"
	MinVersion string `yaml:"min_version,omitempty" json:"min_version,omitempty" jsonschema:"title=Min. TLS version,description=Minimum tls version - automatic if not specified.,enum=sslv3,enum=tls10,enum=tls11,enum=tls12,enum=tls13"`
	// description: |
	//   Max tls version - auto if not specified.
	// values:
	//   - "sslv3"
	//   - "tls10"
	//   - "tls11"
	//   - "tls12"
	//   - "tls13"
	MaxVersion string `yaml:"max_version,omitempty" json:"max_version,omitempty" jsonschema:"title=Max. TLS version,description=Max tls version - automatic if not specified.,enum=sslv3,enum=tls10,enum=tls11,enum=tls12,enum=tls13"`
	// description: |
	//   Client Cipher Suites  - auto if not specified.
	CipherSuites []string `yaml:"cipher_suites,omitempty" json:"cipher_suites,omitempty"`
	// description: |
	//   Tls Scan Mode - auto if not specified
	// values:
	//   - "ctls"
	//   - "ztls"
	//   - "auto"
	//	 - "openssl" # reverts to "auto" is openssl is not installed
	ScanMode string `yaml:"scan_mode,omitempty" json:"scan_mode,omitempty" jsonschema:"title=Scan Mode,description=Scan Mode - auto if not specified.,enum=ctls,enum=ztls,enum=auto"`
	// description: |
	//   TLS Versions Enum - false if not specified
	//   Enumerates supported TLS versions
	TLSVersionsEnum bool `yaml:"tls_version_enum,omitempty" json:"tls_version_enum,omitempty" jsonschema:"title=Enumerate Versions,description=Enumerate Version - false if not specified"`
	// description: |
	//   TLS Ciphers Enum - false if not specified
	//   Enumerates supported TLS ciphers
	TLSCiphersEnum bool `yaml:"tls_cipher_enum,omitempty" json:"tls_cipher_enum,omitempty" jsonschema:"title=Enumerate Ciphers,description=Enumerate Ciphers - false if not specified"`
	// description: |
	//  TLS Cipher types to enumerate
	// values:
	//   - "insecure" (default)
	//   - "weak"
	//   - "secure"
	//   - "all"
	TLSCipherTypes []string `yaml:"tls_cipher_types,omitempty" json:"tls_cipher_types,omitempty" jsonschema:"title=TLS Cipher Types,description=TLS Cipher Types to enumerate,enum=weak,enum=secure,enum=insecure,enum=all"`

	// cache any variables that may be needed for operation.
	dialer  *fastdialer.Dialer
	tlsx    *tlsx.Service
	options *protocols.ExecutorOptions
}

// TmplClusterKey generates a unique key for the request
// to be used in the clustering process.
func (request *Request) TmplClusterKey() uint64 {
	inp := fmt.Sprintf("%s-%s-%t-%t-%s", request.Address, request.ScanMode, request.TLSCiphersEnum, request.TLSVersionsEnum, strings.Join(request.TLSCipherTypes, ","))
	return xxhash.Sum64String(inp)
}

func (request *Request) IsClusterable() bool {
	return !(len(request.CipherSuites) > 0 || request.MinVersion != "" || request.MaxVersion != "")
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	request.options = options

	client, err := networkclientpool.Get(options.Options, &networkclientpool.Configuration{})
	if err != nil {
		return errorutil.NewWithTag("ssl", "could not get network client").Wrap(err)
	}
	request.dialer = client
	switch {
	//validate scanmode
	case request.ScanMode == "":
		request.ScanMode = "auto"

	case !stringsutil.EqualFoldAny(request.ScanMode, "auto", "openssl", "ztls", "ctls"):
		return errorutil.NewWithTag(request.TemplateID, "template %v does not contain valid scan-mode", request.TemplateID)

	case request.ScanMode == "openssl" && !openssl.IsAvailable():
		// if openssl is not installed instead of failing "auto" scanmode is used
		request.ScanMode = "auto"
	}
	if request.TLSCiphersEnum {
		// cipher enumeration requires tls version enumeration first
		request.TLSVersionsEnum = true
	}
	if request.TLSCiphersEnum && len(request.TLSCipherTypes) == 0 {
		// by default only look for insecure ciphers
		request.TLSCipherTypes = []string{"insecure"}
	}

	tlsxOptions := &clients.Options{
		AllCiphers:        true,
		ScanMode:          request.ScanMode,
		Expired:           true,
		SelfSigned:        true,
		Revoked:           true,
		MisMatched:        true,
		MinVersion:        request.MinVersion,
		MaxVersion:        request.MaxVersion,
		Ciphers:           request.CipherSuites,
		WildcardCertCheck: true,
		Retries:           request.options.Options.Retries,
		Timeout:           request.options.Options.Timeout,
		Fastdialer:        client,
		ClientHello:       true,
		ServerHello:       true,
		DisplayDns:        true,
		TlsVersionsEnum:   request.TLSVersionsEnum,
		TlsCiphersEnum:    request.TLSCiphersEnum,
		TLsCipherLevel:    request.TLSCipherTypes,
	}

	tlsxService, err := tlsx.New(tlsxOptions)
	if err != nil {
		return errorutil.NewWithTag(request.TemplateID, "could not create tlsx service")
	}
	request.tlsx = tlsxService

	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		compiled.ExcludeMatchers = options.ExcludeMatchers
		compiled.TemplateID = options.TemplateID
		if err := compiled.Compile(); err != nil {
			return errorutil.NewWithTag(request.TemplateID, "could not compile operators got %v", err)
		}
		request.CompiledOperators = compiled
	}
	return nil
}

// Options returns executer options for http request
func (r *Request) Options() *protocols.ExecutorOptions {
	return r.options
}

// Requests returns the total number of requests the rule will perform
func (request *Request) Requests() int {
	return 1
}

// GetID returns the ID for the request if any.
func (request *Request) GetID() string {
	return ""
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	hostPort := input.MetaInput.Input
	hostname, port, _ := net.SplitHostPort(hostPort)

	requestOptions := request.options
	payloadValues := generators.BuildPayloadFromOptions(request.options.Options)
	for k, v := range dynamicValues {
		payloadValues[k] = v
	}

	payloadValues["Hostname"] = hostPort
	payloadValues["Host"] = hostname
	payloadValues["Port"] = port

	hostnameVariables := protocolutils.GenerateDNSVariables(hostname)
	// add template context variables to varMap
	values := generators.MergeMaps(payloadValues, hostnameVariables)
	if request.options.HasTemplateCtx(input.MetaInput) {
		values = generators.MergeMaps(values, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}

	variablesMap := request.options.Variables.Evaluate(values)
	payloadValues = generators.MergeMaps(variablesMap, payloadValues, request.options.Constants)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("SSL Protocol request variables: %s\n", vardump.DumpVariables(payloadValues))
	}

	finalAddress, dataErr := expressions.EvaluateByte([]byte(request.Address), payloadValues)
	if dataErr != nil {
		requestOptions.Output.Request(requestOptions.TemplateID, input.MetaInput.Input, request.Type().String(), dataErr)
		requestOptions.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(dataErr, "could not evaluate template expressions")
	}
	addressToDial := string(finalAddress)
	host, port, err := net.SplitHostPort(addressToDial)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not split input host port")
	}

	var hostIp string
	if input.MetaInput.CustomIP != "" {
		hostIp = input.MetaInput.CustomIP
	} else {
		hostIp = host
	}

	response, err := request.tlsx.Connect(host, hostIp, port)
	if err != nil {
		requestOptions.Output.Request(requestOptions.TemplateID, input.MetaInput.Input, request.Type().String(), err)
		requestOptions.Progress.IncrementFailedRequestsBy(1)
		return errorutil.NewWithTag(request.TemplateID, "could not connect to server").Wrap(err)
	}

	requestOptions.Output.Request(requestOptions.TemplateID, hostPort, request.Type().String(), err)
	gologger.Verbose().Msgf("[%s] Sent SSL request to %s", request.options.TemplateID, hostPort)

	if requestOptions.Options.Debug || requestOptions.Options.DebugRequests || requestOptions.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped SSL request for %s", requestOptions.TemplateID, input.MetaInput.Input)
		if requestOptions.Options.Debug || requestOptions.Options.DebugRequests {
			gologger.Debug().Str("address", input.MetaInput.Input).Msg(msg)
		}
		if requestOptions.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(input.MetaInput.Input, request.options.TemplateID, request.Type().String(), msg)
		}
	}

	jsonData, _ := jsoniter.Marshal(response)
	jsonDataString := string(jsonData)

	data := make(map[string]interface{})
	for k, v := range payloadValues {
		data[k] = v
	}
	data["type"] = request.Type().String()
	data["response"] = jsonDataString
	data["host"] = input.MetaInput.Input
	data["matched"] = addressToDial
	if input.MetaInput.CustomIP != "" {
		data["ip"] = hostIp
	} else {
		data["ip"] = request.dialer.GetDialedIP(hostname)
	}
	data["Port"] = port
	data["template-path"] = requestOptions.TemplatePath
	data["template-id"] = requestOptions.TemplateID
	data["template-info"] = requestOptions.TemplateInfo

	// if response is not struct compatible, error out
	if !structs.IsStruct(response) {
		return errorutil.NewWithTag("ssl", "response cannot be parsed into a struct: %v", response)
	}

	// Convert response to key value pairs and first cert chain item as well
	responseParsed := structs.New(response)
	for _, f := range responseParsed.Fields() {
		if !f.IsExported() {
			// if field is not exported f.IsZero() , f.Value() will panic
			continue
		}
		tag := protocolutils.CleanStructFieldJSONTag(f.Tag("json"))
		if tag == "" || f.IsZero() {
			continue
		}
		request.options.AddTemplateVar(input.MetaInput, request.Type(), request.ID, tag, f.Value())
		data[tag] = f.Value()
	}

	// if certificate response is not struct compatible, error out
	if !structs.IsStruct(response.CertificateResponse) {
		return errorutil.NewWithTag("ssl", "certificate response cannot be parsed into a struct: %v", response.CertificateResponse)
	}

	responseParsed = structs.New(response.CertificateResponse)
	for _, f := range responseParsed.Fields() {
		if !f.IsExported() {
			// if field is not exported f.IsZero() , f.Value() will panic
			continue
		}
		tag := protocolutils.CleanStructFieldJSONTag(f.Tag("json"))
		if tag == "" || f.IsZero() {
			continue
		}
		request.options.AddTemplateVar(input.MetaInput, request.Type(), request.ID, tag, f.Value())
		data[tag] = f.Value()
	}

	// add response fields ^ to template context and merge templatectx variables to output event
	if request.options.HasTemplateCtx(input.MetaInput) {
		data = generators.MergeMaps(data, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	event := eventcreator.CreateEvent(request, data, requestOptions.Options.Debug || requestOptions.Options.DebugResponse)
	if requestOptions.Options.Debug || requestOptions.Options.DebugResponse || requestOptions.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped SSL response for %s", requestOptions.TemplateID, input.MetaInput.Input)
		if requestOptions.Options.Debug || requestOptions.Options.DebugResponse {
			gologger.Debug().Msg(msg)
			gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, jsonDataString, requestOptions.Options.NoColor, false))
		}
		if requestOptions.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(input.MetaInput.Input, request.options.TemplateID, request.Type().String(), fmt.Sprintf("%s\n%s", msg, jsonDataString))
		}
	}
	callback(event)
	return nil
}

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"template-id":      "ID of the template executed",
	"template-info":    "Info Block of the template executed",
	"template-path":    "Path of the template executed",
	"host":             "Host is the input to the template",
	"port":             "Port is the port of the host",
	"matched":          "Matched is the input which was matched upon",
	"type":             "Type is the type of request made",
	"timestamp":        "Timestamp is the time when the request was made",
	"response":         "JSON SSL protocol handshake details",
	"cipher":           "Cipher is the encryption algorithm used",
	"domains":          "Domains are the list of domain names in the certificate",
	"fingerprint_hash": "Fingerprint hash is the unique identifier of the certificate",
	"ip":               "IP is the IP address of the server",
	"issuer_cn":        "Issuer CN is the common name of the certificate issuer",
	"issuer_dn":        "Issuer DN is the distinguished name of the certificate issuer",
	"issuer_org":       "Issuer organization is the organization of the certificate issuer",
	"not_after":        "Timestamp after which the remote cert expires",
	"not_before":       "Timestamp before which the certificate is not valid",
	"probe_status":     "Probe status indicates if the probe was successful",
	"serial":           "Serial is the serial number of the certificate",
	"sni":              "SNI is the server name indication used in the handshake",
	"subject_an":       "Subject AN is the list of subject alternative names",
	"subject_cn":       "Subject CN is the common name of the certificate subject",
	"subject_dn":       "Subject DN is the distinguished name of the certificate subject",
	"subject_org":      "Subject organization is the organization of the certificate subject",
	"tls_connection":   "TLS connection is the type of TLS connection used",
	"tls_version":      "TLS version is the version of the TLS protocol used",
}

// Match performs matching operation for a matcher on model and returns:
// true and a list of matched snippets if the matcher type is supports it
// otherwise false and an empty string slice
func (request *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	return protocols.MakeDefaultMatchFunc(data, matcher)
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (request *Request) Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{} {
	return protocols.MakeDefaultExtractFunc(data, matcher)
}

// MakeResultEvent creates a result event from internal wrapped event
func (request *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(request, wrapped)
}

// GetCompiledOperators returns a list of the compiled operators
func (request *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{request.CompiledOperators}
}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.SSLProtocol
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	fields := protocolutils.GetJsonFieldsFromURL(types.ToString(wrapped.InternalEvent["host"]))
	if types.ToString(wrapped.InternalEvent["ip"]) != "" {
		fields.Ip = types.ToString(wrapped.InternalEvent["ip"])
	}
	// in case scheme is not specified , we only connect to port 443 unless custom https port was specified
	// like 8443 etc
	if fields.Port == "80" {
		fields.Port = "443"
	}
	if types.ToString(wrapped.InternalEvent["Port"]) != "" {
		fields.Port = types.ToString(wrapped.InternalEvent["Port"])
	}
	data := &output.ResultEvent{
		TemplateID:       types.ToString(wrapped.InternalEvent["template-id"]),
		TemplatePath:     types.ToString(wrapped.InternalEvent["template-path"]),
		Info:             wrapped.InternalEvent["template-info"].(model.Info),
		TemplateVerifier: request.options.TemplateVerifier,
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Host:             fields.Host,
		Port:             fields.Port,
		Matched:          types.ToString(wrapped.InternalEvent["matched"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		MatcherStatus:    true,
		IP:               fields.Ip,
		TemplateEncoded:  request.options.EncodeTemplate(),
		Error:            types.ToString(wrapped.InternalEvent["error"]),
	}
	return data
}
