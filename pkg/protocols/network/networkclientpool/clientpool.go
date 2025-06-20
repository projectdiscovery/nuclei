package networkclientpool

import (
	"fmt"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Init initializes the clientpool implementation
func Init(options *types.Options) error {
	return nil
}

// Configuration contains the custom configuration options for a client
type Configuration struct {
	CustomDialer *fastdialer.Dialer
}

// Hash returns the hash of the configuration to allow client pooling
func (c *Configuration) Hash() string {
	return ""
}

// Get creates or gets a client for the protocol based on custom configuration
func Get(options *types.Options, configuration *Configuration /*TODO review unused parameters*/) (*fastdialer.Dialer, error) {
	if configuration != nil && configuration.CustomDialer != nil {
		return configuration.CustomDialer, nil
	}
	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", options.ExecutionId)
	}
	return dialers.Fastdialer, nil
}
