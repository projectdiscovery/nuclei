package websocket

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network/networkclientpool"
	protocolutils "github.com/projectdiscovery/nuclei/v2/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	urlutil "github.com/projectdiscovery/utils/url"
)

// Request is a request for the Websocket protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty" json:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-" json:"-"`

	// description: |
	//   Address contains address for the request
	Address string `yaml:"address,omitempty" json:"address,omitempty" jsonschema:"title=address for the websocket request,description=Address contains address for the request"`
	// description: |
	//   Inputs contains inputs for the websocket protocol
	Inputs []*Input `yaml:"inputs,omitempty" json:"inputs,omitempty" jsonschema:"title=inputs for the websocket request,description=Inputs contains any input/output for the current request"`
	// description: |
	//   Headers contains headers for the request.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty" jsonschema:"title=headers contains the request headers,description=Headers contains headers for the request"`

	// description: |
	//   Attack is the type of payload combinations to perform.
	//
	//   Sniper is each payload once, pitchfork combines multiple payload sets and clusterbomb generates
	//   permutations and combinations for all payloads.
	AttackType generators.AttackTypeHolder `yaml:"attack,omitempty" json:"attack,omitempty" jsonschema:"title=attack is the payload combination,description=Attack is the type of payload combinations to perform,enum=sniper,enum=pitchfork,enum=clusterbomb"`
	// description: |
	//   Payloads contains any payloads for the current request.
	//
	//   Payloads support both key-values combinations where a list
	//   of payloads is provided, or optionally a single file can also
	//   be provided as payload which will be read on run-time.
	Payloads map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty" jsonschema:"title=payloads for the websocket request,description=Payloads contains any payloads for the current request"`

	generator *generators.PayloadGenerator

	// cache any variables that may be needed for operation.
	dialer  *fastdialer.Dialer
	options *protocols.ExecutorOptions
}

// Input is an input for the websocket protocol
type Input struct {
	// description: |
	//   Data is the data to send as the input.
	//
	//   It supports DSL Helper Functions as well as normal expressions.
	// examples:
	//   - value: "\"TEST\""
	//   - value: "\"hex_decode('50494e47')\""
	Data string `yaml:"data,omitempty" json:"data,omitempty" jsonschema:"title=data to send as input,description=Data is the data to send as the input"`
	// description: |
	//   Name is the optional name of the data read to provide matching on.
	// examples:
	//   - value: "\"prefix\""
	Name string `yaml:"name,omitempty" json:"name,omitempty" jsonschema:"title=optional name for data read,description=Optional name of the data read to provide matching on"`
}

const (
	parseUrlErrorMessage                   = "could not parse input url"
	evaluateTemplateExpressionErrorMessage = "could not evaluate template expressions"
)

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	request.options = options

	client, err := networkclientpool.Get(options.Options, &networkclientpool.Configuration{})
	if err != nil {
		return errors.Wrap(err, "could not get network client")
	}
	request.dialer = client

	if len(request.Payloads) > 0 {
		request.generator, err = generators.New(request.Payloads, request.AttackType.Value, request.options.TemplatePath, request.options.Options.AllowLocalFileAccess, options.Catalog, options.Options.AttackType)
		if err != nil {
			return errors.Wrap(err, "could not parse payloads")
		}
	}

	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		compiled.ExcludeMatchers = options.ExcludeMatchers
		compiled.TemplateID = options.TemplateID
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		request.CompiledOperators = compiled
	}
	return nil
}

// Requests returns the total number of requests the rule will perform
func (request *Request) Requests() int {
	if request.generator != nil {
		return request.generator.NewIterator().Total()
	}
	return 1
}

// GetID returns the ID for the request if any.
func (request *Request) GetID() string {
	return ""
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	hostname, err := getAddress(input.MetaInput.Input)
	if err != nil {
		return err
	}

	if request.generator != nil {
		iterator := request.generator.NewIterator()

		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}
			if err := request.executeRequestWithPayloads(input.MetaInput.Input, hostname, value, previous, callback); err != nil {
				return err
			}
		}
	} else {
		value := make(map[string]interface{})
		if err := request.executeRequestWithPayloads(input.MetaInput.Input, hostname, value, previous, callback); err != nil {
			return err
		}
	}
	return nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) executeRequestWithPayloads(input, hostname string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	header := http.Header{}

	parsed, err := urlutil.Parse(input)
	if err != nil {
		return errors.Wrap(err, parseUrlErrorMessage)
	}
	defaultVars := protocolutils.GenerateVariables(parsed, false, nil)
	optionVars := generators.BuildPayloadFromOptions(request.options.Options)
	variables := request.options.Variables.Evaluate(generators.MergeMaps(defaultVars, optionVars, dynamicValues))
	payloadValues := generators.MergeMaps(variables, defaultVars, optionVars, dynamicValues, request.options.Constants)

	requestOptions := request.options
	for key, value := range request.Headers {
		finalData, dataErr := expressions.EvaluateByte([]byte(value), payloadValues)
		if dataErr != nil {
			requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), dataErr)
			requestOptions.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(dataErr, evaluateTemplateExpressionErrorMessage)
		}
		header.Set(key, string(finalData))
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
		MinVersion:         tls.VersionTLS10,
	}
	if requestOptions.Options.SNI != "" {
		tlsConfig.ServerName = requestOptions.Options.SNI
	}
	websocketDialer := ws.Dialer{
		Header:    ws.HandshakeHeaderHTTP(header),
		Timeout:   time.Duration(requestOptions.Options.Timeout) * time.Second,
		NetDial:   request.dialer.Dial,
		TLSConfig: tlsConfig,
	}

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Protocol request variables: \n%s\n", vardump.DumpVariables(payloadValues))
	}

	finalAddress, dataErr := expressions.EvaluateByte([]byte(request.Address), payloadValues)
	if dataErr != nil {
		requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), dataErr)
		requestOptions.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(dataErr, evaluateTemplateExpressionErrorMessage)
	}

	addressToDial := string(finalAddress)
	parsedAddress, err := url.Parse(addressToDial)
	if err != nil {
		requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), err)
		requestOptions.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, parseUrlErrorMessage)
	}
	parsedAddress.Path = path.Join(parsedAddress.Path, parsed.Path)
	addressToDial = parsedAddress.String()

	conn, readBuffer, _, err := websocketDialer.Dial(context.Background(), addressToDial)
	if err != nil {
		requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), err)
		requestOptions.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not connect to server")
	}
	defer conn.Close()

	responseBuilder := &strings.Builder{}
	if readBuffer != nil {
		_, _ = io.Copy(responseBuilder, readBuffer) // Copy initial response
	}

	events, requestOutput, err := request.readWriteInputWebsocket(conn, payloadValues, input, responseBuilder)
	if err != nil {
		requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), err)
		requestOptions.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not read write response")
	}
	requestOptions.Progress.IncrementRequests()

	if requestOptions.Options.Debug || requestOptions.Options.DebugRequests {
		gologger.Debug().Str("address", input).Msgf("[%s] Dumped Websocket request for %s", requestOptions.TemplateID, input)
		gologger.Print().Msgf("%s", requestOutput)
	}

	requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), err)
	gologger.Verbose().Msgf("Sent Websocket request to %s", input)

	data := make(map[string]interface{})
	for k, v := range previous {
		data[k] = v
	}
	for k, v := range events {
		data[k] = v
	}

	data["type"] = request.Type().String()
	data["success"] = "true"
	data["request"] = requestOutput
	data["response"] = responseBuilder.String()
	data["host"] = input
	data["matched"] = addressToDial
	data["ip"] = request.dialer.GetDialedIP(hostname)

	event := eventcreator.CreateEventWithAdditionalOptions(request, data, requestOptions.Options.Debug || requestOptions.Options.DebugResponse, func(internalWrappedEvent *output.InternalWrappedEvent) {
		internalWrappedEvent.OperatorsResult.PayloadValues = payloadValues
	})
	if requestOptions.Options.Debug || requestOptions.Options.DebugResponse {
		responseOutput := responseBuilder.String()
		gologger.Debug().Msgf("[%s] Dumped Websocket response for %s", requestOptions.TemplateID, input)
		gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, responseOutput, requestOptions.Options.NoColor, false))
	}

	callback(event)
	return nil
}

func (request *Request) readWriteInputWebsocket(conn net.Conn, payloadValues map[string]interface{}, input string, respBuilder *strings.Builder) (events map[string]interface{}, req string, err error) {
	reqBuilder := &strings.Builder{}
	inputEvents := make(map[string]interface{})

	requestOptions := request.options
	for _, req := range request.Inputs {
		reqBuilder.Grow(len(req.Data))

		finalData, dataErr := expressions.EvaluateByte([]byte(req.Data), payloadValues)
		if dataErr != nil {
			requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), dataErr)
			requestOptions.Progress.IncrementFailedRequestsBy(1)
			return nil, "", errors.Wrap(dataErr, evaluateTemplateExpressionErrorMessage)
		}
		reqBuilder.WriteString(string(finalData))

		err = wsutil.WriteClientMessage(conn, ws.OpText, finalData)
		if err != nil {
			requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), err)
			requestOptions.Progress.IncrementFailedRequestsBy(1)
			return nil, "", errors.Wrap(err, "could not write request to server")
		}

		msg, opCode, err := wsutil.ReadServerData(conn)
		if err != nil {
			requestOptions.Output.Request(requestOptions.TemplateID, input, request.Type().String(), err)
			requestOptions.Progress.IncrementFailedRequestsBy(1)
			return nil, "", errors.Wrap(err, "could not write request to server")
		}
		// Only perform matching and writes in case we receive
		// text or binary opcode from the websocket server.
		if opCode != ws.OpText && opCode != ws.OpBinary {
			continue
		}

		respBuilder.Write(msg)
		if req.Name != "" {
			bufferStr := string(msg)
			inputEvents[req.Name] = bufferStr

			// Run any internal extractors for the request here and add found values to map.
			if request.CompiledOperators != nil {
				values := request.CompiledOperators.ExecuteInternalExtractors(map[string]interface{}{req.Name: bufferStr}, protocols.MakeDefaultExtractFunc)
				for k, v := range values {
					inputEvents[k] = v
				}
			}
		}
	}
	return inputEvents, reqBuilder.String(), nil
}

// getAddress returns the address of the host to make request to
func getAddress(toTest string) (string, error) {
	parsed, err := url.Parse(toTest)
	if err != nil {
		return "", errors.Wrap(err, parseUrlErrorMessage)
	}
	scheme := strings.ToLower(parsed.Scheme)

	if scheme != "ws" && scheme != "wss" {
		return "", fmt.Errorf("invalid url scheme provided: %s", scheme)
	}
	if parsed != nil && parsed.Host != "" {
		return parsed.Host, nil
	}
	return "", nil
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

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"type":     "Type is the type of request made",
	"success":  "Success specifies whether websocket connection was successful",
	"request":  "Websocket request made to the server",
	"response": "Websocket response received from the server",
	"host":     "Host is the input to the template",
	"matched":  "Matched is the input which was matched upon",
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(request.options.TemplateID),
		TemplatePath:     types.ToString(request.options.TemplatePath),
		Info:             request.options.TemplateInfo,
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Matched:          types.ToString(wrapped.InternalEvent["matched"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		MatcherStatus:    true,
		IP:               types.ToString(wrapped.InternalEvent["ip"]),
		Request:          types.ToString(wrapped.InternalEvent["request"]),
		Response:         types.ToString(wrapped.InternalEvent["response"]),
	}
	return data
}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.WebsocketProtocol
}
