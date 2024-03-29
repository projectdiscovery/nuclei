package networkclientpool

import (
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

type NetworkClientPool struct {
	normalClient *fastdialer.Dialer
}

func New(options *types.Options) (*NetworkClientPool, error) {
	return &NetworkClientPool{normalClient: protocolstate.Dialer}, nil
}

// Configuration contains the custom configuration options for a client
type Configuration struct{}

// Hash returns the hash of the configuration to allow client pooling
func (c *Configuration) Hash() uint64 {
	return 0
}

// Get creates or gets a client for the protocol based on custom configuration
func (ncp *NetworkClientPool) Get(options *types.Options, configuration *Configuration) (*fastdialer.Dialer, error) {
	return ncp.normalClient, nil
}
