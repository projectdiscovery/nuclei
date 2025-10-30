package rdapclientpool

import (
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/rdap"
)

var normalClient *rdap.Client
var m sync.Mutex

// Init initializes the client pool implementation
func Init(options *types.Options) error {
	m.Lock()
	defer m.Unlock()

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

func getNormalClient() *rdap.Client {
	m.Lock()
	defer m.Unlock()
	return normalClient
}

// Configuration contains the custom configuration options for a client - placeholder
type Configuration struct{}

// Hash returns the hash of the configuration to allow client pooling - placeholder
func (c *Configuration) Hash() string {
	return ""
}

// Get creates or gets a client for the protocol based on custom configuration
func Get(options *types.Options, configuration *Configuration) (*rdap.Client, error) {
	return getNormalClient(), nil
}
