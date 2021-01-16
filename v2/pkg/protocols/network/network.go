package network

import (
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network/networkclientpool"
)

// Request contains a Network protocol request to be made from a template
type Request struct {
	ID string `yaml:"id"`

	// Address is the address to send requests to (host:port combos generally)
	Address   []string `yaml:"host"`
	addresses []keyValue

	// Payload is the payload to send for the network request
	Inputs []*Input `yaml:"inputs"`
	// ReadSize is the size of response to read (1024 if not provided by default)
	ReadSize int `yaml:"read-size"`

	// Operators for the current request go here.
	operators.Operators `yaml:",inline"`
	CompiledOperators   *operators.Operators

	// cache any variables that may be needed for operation.
	dialer  *fastdialer.Dialer
	options *protocols.ExecuterOptions
}

// keyValue is a key value pair
type keyValue struct {
	key   string
	value string
}

// Input is the input to send on the network
type Input struct {
	// Data is the data to send as the input
	Data string `yaml:"data"`
	// Type is the type of input - hex, text.
	Type string `yaml:"type"`
}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	var err error
	for _, address := range r.Address {
		if strings.Contains(address, ":") {
			addressHost, addressPort, err := net.SplitHostPort(address)
			if err != nil {
				return errors.Wrap(err, "could not parse address")
			}
			r.addresses = append(r.addresses, keyValue{key: addressHost, value: addressPort})
		} else {
			r.addresses = append(r.addresses, keyValue{key: address})
		}
	}

	// Create a client for the class
	client, err := networkclientpool.Get(options.Options, &networkclientpool.Configuration{})
	if err != nil {
		return errors.Wrap(err, "could not get network client")
	}
	r.dialer = client

	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}
	r.options = options
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int {
	return len(r.Address)
}
