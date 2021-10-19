package network

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network/networkclientpool"
)

// Request contains a Network protocol request to be made from a template
type Request struct {
	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" jsonschema:"title=id of the request,description=ID of the network request"`

	// description: |
	//   Host to send network requests to.
	//
	//   Usually it's set to `{{Hostname}}`. If you want to enable TLS for
	//   TCP Connection, you can use `tls://{{Hostname}}`.
	// examples:
	//   - value: |
	//       []string{"{{Hostname}}"}
	Address   []string `yaml:"host,omitempty" jsonschema:"title=host to send requests to,description=Host to send network requests to"`
	addresses []addressKV

	// description: |
	//   Attack is the type of payload combinations to perform.
	//
	//   Batteringram is same payload into all of the defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
	//   permutations and combinations for all payloads.
	// values:
	//   - "batteringram"
	//   - "pitchfork"
	//   - "clusterbomb"
	AttackType string `yaml:"attack,omitempty" jsonschema:"title=attack is the payload combination,description=Attack is the type of payload combinations to perform,enum=batteringram,enum=pitchfork,enum=clusterbomb"`
	// description: |
	//   Payloads contains any payloads for the current request.
	//
	//   Payloads support both key-values combinations where a list
	//   of payloads is provided, or optionally a single file can also
	//   be provided as payload which will be read on run-time.
	Payloads map[string]interface{} `yaml:"payloads,omitempty" jsonschema:"title=payloads for the network request,description=Payloads contains any payloads for the current request"`

	// description: |
	//   Inputs contains inputs for the network socket
	Inputs []*Input `yaml:"inputs,omitempty" jsonschema:"title=inputs for the network request,description=Inputs contains any input/output for the current request"`
	// description: |
	//   ReadSize is the size of response to read at the end
	//
	//   Default value for read-size is 1024.
	// examples:
	//   - value: "2048"
	ReadSize int `yaml:"read-size,omitempty" jsonschema:"title=size of network response to read,description=Size of response to read at the end. Default is 1024 bytes"`

	// description: |
	//   SelfContained specifies if the request is self contained.
	SelfContained bool `yaml:"-" json:"-"`

	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-"`

	generator  *generators.Generator
	attackType generators.Type
	// cache any variables that may be needed for operation.
	dialer        *fastdialer.Dialer
	options       *protocols.ExecuterOptions
	dynamicValues map[string]interface{}
}

type addressKV struct {
	ip   string
	port string
	tls  bool
}

// Input is the input to send on the network
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
	//   Type is the type of input specified in `data` field.
	//
	//   Default value is text, but hex can be used for hex formatted data.
	// values:
	//   - "hex"
	//   - "text"
	Type string `yaml:"type,omitempty" jsonschema:"title=type is the type of input data,description=Type of input specified in data field,enum=hex,enum=text"`
	// description: |
	//   Read is the number of bytes to read from socket.
	//
	//   This can be used for protocols which expect an immediate response. You can
	//   read and write responses one after another and evetually perform matching
	//   on every data captured with `name` attribute.
	//
	//   The [network docs](https://nuclei.projectdiscovery.io/templating-guide/protocols/network/) highlight more on how to do this.
	// examples:
	//   - value: "1024"
	Read int `yaml:"read,omitempty" jsonschema:"title=bytes to read from socket,description=Number of bytes to read from socket"`
	// description: |
	//   Name is the optional name of the data read to provide matching on.
	// examples:
	//   - value: "\"prefix\""
	Name string `yaml:"name,omitempty" jsonschema:"title=optional name for data read,description=Optional name of the data read to provide matching on"`
}

// GetID returns the unique ID of the request if any.
func (request *Request) GetID() string {
	return request.ID
}

// Compile compiles the protocol request for further execution.
func (request *Request) Compile(options *protocols.ExecuterOptions) error {
	var shouldUseTLS bool
	var err error

	request.options = options
	for _, address := range request.Address {
		// check if the connection should be encrypted
		if strings.HasPrefix(address, "tls://") {
			shouldUseTLS = true
			address = strings.TrimPrefix(address, "tls://")
		}
		if strings.Contains(address, ":") {
			addressHost, addressPort, portErr := net.SplitHostPort(address)
			if portErr != nil {
				return errors.Wrap(portErr, "could not parse address")
			}
			request.addresses = append(request.addresses, addressKV{ip: addressHost, port: addressPort, tls: shouldUseTLS})
		} else {
			request.addresses = append(request.addresses, addressKV{ip: address, tls: shouldUseTLS})
		}
	}
	// Pre-compile any input dsl functions before executing the request.
	for _, input := range request.Inputs {
		if input.Type != "" {
			continue
		}
		if compiled, evalErr := expressions.Evaluate(input.Data, map[string]interface{}{}); evalErr == nil {
			input.Data = compiled
		}
	}

	// Resolve payload paths from vars if they exists
	for name, payload := range request.options.Options.VarsPayload() {
		payloadStr, ok := payload.(string)
		// check if inputs contains the payload
		var hasPayloadName bool
		for _, input := range request.Inputs {
			if input.Type != "" {
				continue
			}
			if expressions.ContainsVariablesWithNames(input.Data, map[string]interface{}{name: payload}) == nil {
				hasPayloadName = true
				break
			}
		}
		if ok && hasPayloadName && fileutil.FileExists(payloadStr) {
			if request.Payloads == nil {
				request.Payloads = make(map[string]interface{})
			}
			request.Payloads[name] = payloadStr
		}
	}

	if len(request.Payloads) > 0 {
		attackType := request.AttackType
		if attackType == "" {
			attackType = "batteringram"
		}
		var ok bool
		request.attackType, ok = generators.StringToType[attackType]
		if !ok {
			return fmt.Errorf("invalid attack type provided: %s", attackType)
		}

		// Resolve payload paths if they are files.
		for name, payload := range request.Payloads {
			payloadStr, ok := payload.(string)
			if ok {
				final, resolveErr := options.Catalog.ResolvePath(payloadStr, options.TemplatePath)
				if resolveErr != nil {
					return errors.Wrap(resolveErr, "could not read payload file")
				}
				request.Payloads[name] = final
			}
		}
		request.generator, err = generators.New(request.Payloads, request.attackType, request.options.TemplatePath)
		if err != nil {
			return errors.Wrap(err, "could not parse payloads")
		}
	}

	// Create a client for the class
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

// Requests returns the total number of requests the YAML rule will perform
func (request *Request) Requests() int {
	return len(request.Address)
}
