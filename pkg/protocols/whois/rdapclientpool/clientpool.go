package rdapclientpool

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/openrdap/rdap/bootstrap"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/rdap"
)

// clients holds one client per execution, because each one dials with the
// network policy of its execution.
var clients = map[string]*rdap.Client{}
var m sync.Mutex

// Init initializes the client pool implementation
func Init(options *types.Options) error {
	_, err := Get(options, nil)
	return err
}

// newClient returns an rdap client whose requests, bootstrap lookups and
// redirects all dial through the fastdialer of the execution, so every
// address it connects to is checked against the network policy.
func newClient(options *types.Options) *rdap.Client {
	executionID := options.ExecutionId
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialers := protocolstate.GetDialersWithId(executionID)
				if dialers == nil || dialers.Fastdialer == nil {
					return nil, fmt.Errorf("dialers not initialized for %s", executionID)
				}
				return dialers.Fastdialer.Dial(ctx, network, address)
			},
		},
		Timeout: options.GetTimeouts().HttpTimeout,
	}
	client := &rdap.Client{
		HTTP:      httpClient,
		Bootstrap: &bootstrap.Client{HTTP: httpClient},
	}
	if options.Verbose || options.Debug || options.DebugRequests || options.DebugResponse {
		client.Verbose = func(text string) {
			gologger.Debug().Msgf("rdap: %s", text)
		}
	}
	return client
}

// Configuration contains the custom configuration options for a client - placeholder
type Configuration struct{}

// Hash returns the hash of the configuration to allow client pooling - placeholder
func (c *Configuration) Hash() string {
	return ""
}

// Get creates or gets the client of the execution
func Get(options *types.Options, configuration *Configuration) (*rdap.Client, error) {
	m.Lock()
	defer m.Unlock()
	if client, ok := clients[options.ExecutionId]; ok {
		return client, nil
	}
	client := newClient(options)
	clients[options.ExecutionId] = client
	return client, nil
}

// Close drops the client of an execution.
func Close(executionID string) {
	m.Lock()
	client := clients[executionID]
	delete(clients, executionID)
	m.Unlock()
	if client != nil {
		client.HTTP.CloseIdleConnections()
	}
}
