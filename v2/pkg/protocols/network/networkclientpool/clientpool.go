package networkclientpool

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

var (
	normalClient *fastdialer.Dialer
)

// Init initializes the clientpool implementation
func Init(options *types.Options) error {
	// Don't create clients if already created in past.
	if normalClient != nil {
		return nil
	}
	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		return errors.Wrap(err, "could not create dialer")
	}
	normalClient = dialer
	return nil
}

// Configuration contains the custom configuration options for a client
type Configuration struct{}

// Hash returns the hash of the configuration to allow client pooling
func (c *Configuration) Hash() string {
	return ""
}

// Get creates or gets a client for the protocol based on custom configuration
func Get(options *types.Options, configuration *Configuration) (*fastdialer.Dialer, error) {
	return normalClient, nil
}
