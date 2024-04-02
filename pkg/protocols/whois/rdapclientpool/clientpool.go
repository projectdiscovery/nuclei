package rdapclientpool

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/rdap"
)

type RdapClientPool struct {
	normalClient *rdap.Client
}

func New(options *types.Options) (*RdapClientPool, error) {
	normalClient := &rdap.Client{}
	if options.Verbose || options.Debug || options.DebugRequests || options.DebugResponse {
		normalClient.Verbose = func(text string) {
			gologger.Debug().Msgf("rdap: %s", text)
		}
	}
	return &RdapClientPool{normalClient: normalClient}, nil
}

// Configuration contains the custom configuration options for a client - placeholder
type Configuration struct{}

// Hash returns the hash of the configuration to allow client pooling - placeholder
func (c *Configuration) Hash() uint64 {
	return 0
}

// Get creates or gets a client for the protocol based on custom configuration
func (rcp *RdapClientPool) Get(options *types.Options, configuration *Configuration) (*rdap.Client, error) {
	return rcp.normalClient, nil
}
