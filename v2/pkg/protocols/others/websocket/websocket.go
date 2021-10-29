package websocket

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
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
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network/networkclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Request is a request for the Websocket protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-"`

	// description: |
	//   Address contains address for the request
	Address string `yaml:"address,omitempty" jsonschema:"title=address for the websocket request,description=Address contains address for the request"`
	// description: |
	//   Inputs contains inputs for the websocket protocol
	Inputs []*Input `yaml:"inputs,omitempty" jsonschema:"title=inputs for the websocket request,description=Inputs contains any input/output for the current request"`
	// description: |
	//   Headers contains headers for the request.
	Headers map[string]string `yaml:"headers,omitempty" jsonschema:"title=headers contains the request headers,description=Headers contains headers for the request"`

	// description: |
	//   Attack is the type of payload combinations to perform.
	//
	//   Sniper is each payload once, pitchfork combines multiple payload sets and clusterbomb generates
	//   permutations and combinations for all payloads.
	// values:
	//   - "sniper"
	//   - "pitchfork"
	//   - "clusterbomb"
	AttackType string `yaml:"attack,omitempty" jsonschema:"title=attack is the payload combination,description=Attack is the type of payload combinations to perform,enum=sniper,enum=pitchfork,enum=clusterbomb"`
	// description: |
	//   Payloads contains any payloads for the current request.
	//
	//   Payloads support both key-values combinations where a list
	//   of payloads is provided, or optionally a single file can also
	//   be provided as payload which will be read on run-time.
	Payloads map[string]interface{} `yaml:"payloads,omitempty" jsonschema:"title=payloads for the webosocket request,description=Payloads contains any payloads for the current request"`

	generator  *generators.Generator
	attackType generators.Type

	// cache any variables that may be needed for operation.
	dialer  *fastdialer.Dialer
	options *protocols.ExecuterOptions
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
	Data string `yaml:"data,omitempty" jsonschema:"title=data to send as input,description=Data is the data to send as the input"`
	// description: |
	//   Name is the optional name of the data read to provide matching on.
	// examples:
	//   - value: "\"prefix\""
	Name string `yaml:"name,omitempty" jsonschema:"title=optional name for data read,description=Optional name of the data read to provide matching on"`
}

// Compile compiles the request generators preparing any requests possible.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	r.options = options

	client, err := networkclientpool.Get(options.Options, &networkclientpool.Configuration{})
	if err != nil {
		return errors.Wrap(err, "could not get network client")
	}
	r.dialer = client

	if len(r.Payloads) > 0 {
		attackType := r.AttackType
		if attackType == "" {
			attackType = "sniper"
		}
		r.attackType = generators.StringToType[attackType]

		// Resolve payload paths if they are files.
		for name, payload := range r.Payloads {
			payloadStr, ok := payload.(string)
			if ok {
				final, resolveErr := options.Catalog.ResolvePath(payloadStr, options.TemplatePath)
				if resolveErr != nil {
					return errors.Wrap(resolveErr, "could not read payload file")
				}
				r.Payloads[name] = final
			}
		}
		r.generator, err = generators.New(r.Payloads, r.attackType, r.options.TemplatePath)
		if err != nil {
			return errors.Wrap(err, "could not parse payloads")
		}
	}

	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}
	return nil
}

// Requests returns the total number of requests the rule will perform
func (r *Request) Requests() int {
	if r.generator != nil {
		return r.generator.NewIterator().Total()
	}
	return 1
}

// GetID returns the ID for the request if any.
func (r *Request) GetID() string {
	return ""
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	hostname, err := getAddress(input)
	if err != nil {
		return nil
	}

	if r.generator != nil {
		iterator := r.generator.NewIterator()

		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}
			if err := r.executeRequestWithPayloads(input, hostname, value, previous, callback); err != nil {
				return err
			}
		}
	} else {
		value := make(map[string]interface{})
		if err := r.executeRequestWithPayloads(input, hostname, value, previous, callback); err != nil {
			return err
		}
	}
	return nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) executeRequestWithPayloads(input, hostname string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	header := http.Header{}

	payloadValues := make(map[string]interface{})
	for k, v := range dynamicValues {
		payloadValues[k] = v
	}
	parsed, err := url.Parse(input)
	if err != nil {
		return errors.Wrap(err, "could not parse input url")
	}
	payloadValues["Address"] = parsed.Host
	payloadValues["Scheme"] = parsed.Scheme
	payloadValues["Path"] = parsed.Path
	payloadValues["hostname"] = parsed.Hostname()

	for key, value := range r.Headers {
		finalData, dataErr := expressions.EvaluateByte([]byte(value), payloadValues)
		if dataErr != nil {
			r.options.Output.Request(r.options.TemplateID, input, "websocket", dataErr)
			r.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(dataErr, "could not evaluate template expressions")
		}
		header.Set(key, string(finalData))
	}
	websocketDialer := ws.Dialer{
		Header:    ws.HandshakeHeaderHTTP(header),
		Timeout:   time.Duration(r.options.Options.Timeout) * time.Second,
		NetDial:   r.dialer.Dial,
		TLSConfig: &tls.Config{InsecureSkipVerify: true, ServerName: hostname},
	}

	finalAddress, dataErr := expressions.EvaluateByte([]byte(r.Address), payloadValues)
	if dataErr != nil {
		r.options.Output.Request(r.options.TemplateID, input, "websocket", dataErr)
		r.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(dataErr, "could not evaluate template expressions")
	}

	conn, readBuffer, _, err := websocketDialer.Dial(context.Background(), string(finalAddress))
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "ssl", err)
		r.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not connect to server")
	}
	defer conn.Close()

	responseBuilder := &strings.Builder{}
	if readBuffer != nil {
		_, _ = io.Copy(responseBuilder, readBuffer) // Copy initial response
	}

	reqBuilder := &strings.Builder{}

	inputEvents := make(map[string]interface{})
	for _, req := range r.Inputs {
		reqBuilder.Grow(len(req.Data))

		finalData, dataErr := expressions.EvaluateByte([]byte(req.Data), payloadValues)
		if dataErr != nil {
			r.options.Output.Request(r.options.TemplateID, input, "websocket", dataErr)
			r.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(dataErr, "could not evaluate template expressions")
		}
		reqBuilder.WriteString(string(finalData))

		err = wsutil.WriteClientMessage(conn, ws.OpText, finalData)
		if err != nil {
			r.options.Output.Request(r.options.TemplateID, input, "websocket", err)
			r.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not write request to server")
		}

		msg, _, err := wsutil.ReadServerData(conn)
		if err != nil {
			r.options.Output.Request(r.options.TemplateID, input, "websocket", err)
			r.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not write request to server")
		}

		responseBuilder.Write(msg)
		if req.Name != "" {
			bufferStr := string(msg)
			if req.Name != "" {
				inputEvents[req.Name] = bufferStr
			}

			// Run any internal extractors for the request here and add found values to map.
			if r.CompiledOperators != nil {
				values := r.CompiledOperators.ExecuteInternalExtractors(map[string]interface{}{req.Name: bufferStr}, protocols.MakeDefaultExtractFunc)
				for k, v := range values {
					dynamicValues[k] = v
				}
			}
		}
	}
	r.options.Progress.IncrementRequests()

	if r.options.Options.Debug || r.options.Options.DebugRequests {
		requestOutput := reqBuilder.String()
		gologger.Info().Str("address", input).Msgf("[%s] Dumped Websocket request for %s", r.options.TemplateID, input)
		gologger.Print().Msgf("%s", requestOutput)
	}

	r.options.Output.Request(r.options.TemplateID, input, "websocket", err)
	gologger.Verbose().Msgf("Sent Websocket request to %s", input)

	if r.options.Options.Debug || r.options.Options.DebugResponse {
		responseOutput := responseBuilder.String()
		gologger.Debug().Msgf("[%s] Dumped Websocket response for %s", r.options.TemplateID, input)
		gologger.Print().Msgf("%s", responseOutput)
	}

	data := make(map[string]interface{})
	for k, v := range previous {
		data[k] = v
	}
	for k, v := range dynamicValues {
		data[k] = v
	}
	for k, v := range inputEvents {
		data[k] = v
	}
	data["success"] = "true"
	data["request"] = reqBuilder.String()
	data["response"] = responseBuilder.String()
	data["host"] = input
	data["ip"] = r.dialer.GetDialedIP(hostname)

	event := eventcreator.CreateEventWithAdditionalOptions(r, data, r.options.Options.Debug || r.options.Options.DebugResponse, func(internalWrappedEvent *output.InternalWrappedEvent) {
		internalWrappedEvent.OperatorsResult.PayloadValues = payloadValues
	})

	callback(event)
	return nil
}

// getAddress returns the address of the host to make request to
func getAddress(toTest string) (string, error) {
	if !strings.HasPrefix(toTest, "ws://") && !strings.HasPrefix(toTest, "wss://") {
		return "", errors.New("invalid websocket provided")
	}
	parsed, _ := url.Parse(toTest)
	if parsed != nil && parsed.Host != "" {
		return parsed.Host, nil
	}
	return "", nil
}

// Match performs matching operation for a matcher on model and returns:
// true and a list of matched snippets if the matcher type is supports it
// otherwise false and an empty string slice
func (r *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	return protocols.MakeDefaultMatchFunc(data, matcher)
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (r *Request) Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{} {
	return protocols.MakeDefaultExtractFunc(data, matcher)
}

// MakeResultEvent creates a result event from internal wrapped event
func (r *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(r, wrapped)
}

// GetCompiledOperators returns a list of the compiled operators
func (r *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{r.CompiledOperators}
}

func (r *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(r.options.TemplateID),
		TemplatePath:     types.ToString(r.options.TemplatePath),
		Info:             r.options.TemplateInfo,
		Type:             "websocket",
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Matched:          types.ToString(wrapped.InternalEvent["host"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		IP:               types.ToString(wrapped.InternalEvent["ip"]),
		Request:          types.ToString(wrapped.InternalEvent["request"]),
		Response:         types.ToString(wrapped.InternalEvent["response"]),
	}
	return data
}
