package ssl

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/cryptoutil"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network/networkclientpool"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Request is a request for the SSL protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-"`
	// description: |
	//   Address contains address for the request
	Address string `yaml:"address,omitempty" jsonschema:"title=address for the ssl request,description=Address contains address for the request"`

	// cache any variables that may be needed for operation.
	dialer  *fastdialer.Dialer
	options *protocols.ExecuterOptions
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecuterOptions) error {
	request.options = options

	client, err := networkclientpool.Get(options.Options, &networkclientpool.Configuration{})
	if err != nil {
		return errors.Wrap(err, "could not get network client")
	}
	request.dialer = client

	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		request.CompiledOperators = compiled
	}
	return nil
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
func (request *Request) ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	address, err := getAddress(input)
	if err != nil {
		return nil
	}
	hostname, port, _ := net.SplitHostPort(address)

	requestOptions := request.options
	payloadValues := make(map[string]interface{})
	for k, v := range dynamicValues {
		payloadValues[k] = v
	}
	payloadValues["Hostname"] = address
	payloadValues["Host"] = hostname
	payloadValues["Port"] = port

	finalAddress, dataErr := expressions.EvaluateByte([]byte(request.Address), payloadValues)
	if dataErr != nil {
		requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), dataErr)
		requestOptions.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(dataErr, "could not evaluate template expressions")
	}

	addressToDial := string(finalAddress)
	config := &tls.Config{InsecureSkipVerify: true, ServerName: hostname}

	conn, err := request.dialer.DialTLSWithConfig(context.Background(), "tcp", addressToDial, config)
	if err != nil {
		requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), err)
		requestOptions.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not connect to server")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(requestOptions.Options.Timeout) * time.Second))

	connTLS, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	requestOptions.Output.Request(requestOptions.TemplateID, address, request.Type().String(), err)
	gologger.Verbose().Msgf("Sent SSL request to %s", address)

	if requestOptions.Options.Debug || requestOptions.Options.DebugRequests {
		gologger.Debug().Str("address", input).Msgf("[%s] Dumped SSL request for %s", requestOptions.TemplateID, input)
	}

	state := connTLS.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	tlsData := cryptoutil.TLSGrab(&state)
	jsonData, _ := jsoniter.Marshal(tlsData)
	jsonDataString := string(jsonData)

	data := make(map[string]interface{})
	cert := connTLS.ConnectionState().PeerCertificates[0]

	data["type"] = request.Type().String()
	data["response"] = jsonDataString
	data["host"] = input
	data["matched"] = addressToDial
	data["not_after"] = float64(cert.NotAfter.Unix())
	data["ip"] = request.dialer.GetDialedIP(hostname)

	event := eventcreator.CreateEvent(request, data, requestOptions.Options.Debug || requestOptions.Options.DebugResponse)
	if requestOptions.Options.Debug || requestOptions.Options.DebugResponse {
		gologger.Debug().Msgf("[%s] Dumped SSL response for %s", requestOptions.TemplateID, input)
		gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, jsonDataString, requestOptions.Options.NoColor, false))
	}
	callback(event)
	return nil
}

// getAddress returns the address of the host to make request to
func getAddress(toTest string) (string, error) {
	if strings.Contains(toTest, "://") {
		parsed, err := url.Parse(toTest)
		if err != nil {
			return "", err
		}
		_, port, _ := net.SplitHostPort(parsed.Host)

		if strings.ToLower(parsed.Scheme) == "https" && port == "" {
			toTest = net.JoinHostPort(parsed.Host, "443")
		} else {
			toTest = parsed.Host
		}
		return toTest, nil
	}
	return toTest, nil
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
	data := &output.ResultEvent{
		TemplateID:       types.ToString(request.options.TemplateID),
		TemplatePath:     types.ToString(request.options.TemplatePath),
		Info:             request.options.TemplateInfo,
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Matched:          types.ToString(wrapped.InternalEvent["host"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		MatcherStatus:    true,
		IP:               types.ToString(wrapped.InternalEvent["ip"]),
	}
	return data
}
