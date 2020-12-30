package network

import (
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network/networkclientpool"
)

// Request contains a Network protocol request to be made from a template
type Request struct {
	// Address is the address to send requests to (host:port combos generally)
	Address     string `yaml:"address"`
	addressHost string
	addressPort string

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

// Input is the input to send on the network
type Input struct {
	// Data is the data to send as the input
	Data string `yaml:"data"`
	// Type is the type of input - hex, text.
	Type string `yaml:"type"`
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	var err error
	if strings.Contains(r.Address, ":") {
		r.addressHost, r.addressPort, err = net.SplitHostPort(r.Address)
		if err != nil {
			return errors.Wrap(err, "could not parse address")
		}
	} else {
		r.addressHost = r.Address
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
	return 1
}

// Make returns the request to be sent for the protocol
func (r *Request) Make(data string) (string, error) {
	replacer := replacer.New(map[string]interface{}{"Address": data})
	address := replacer.Replace(r.addressHost)
	if !strings.Contains(address, ":") {
		address = net.JoinHostPort(address, r.addressPort)
	}
	return address, nil
}
