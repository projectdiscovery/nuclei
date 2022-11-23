package rdapclientpool

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/rdap"
)

var normalClient *rdap.Client

// Init initializes the client pool implementation
func Init(options *types.Options) error {
	// Don't create clients if already created in the past.
	if normalClient != nil {
		return nil
	}

	normalClient = &rdap.Client{}
	if options.Verbose || options.Debug || options.DebugRequests || options.DebugResponse {
		normalClient.Verbose = func(text string) {
			gologger.Debug().Msgf("rdap: %s", text)
		}
	}
	return nil
}

// Configuration contains the custom configuration options for a client - placeholder
type Configuration struct{}

// Hash returns the hash of the configuration to allow client pooling - placeholder
func (c *Configuration) Hash() string {
	return ""
}

// Get creates or gets a client for the protocol based on custom configuration
func Get(options *types.Options, configuration *Configuration) (*rdap.Client, error) {
	return normalClient, nil
}
