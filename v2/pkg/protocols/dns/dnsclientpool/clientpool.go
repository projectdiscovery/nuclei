package dnsclientpool

import (
	"strconv"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/retryabledns"
)

var (
	poolMutex    *sync.RWMutex
	normalClient *retryabledns.Client
	clientPool   map[string]*retryabledns.Client
)

// defaultResolvers contains the list of resolvers known to be trusted.
var defaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"8.8.4.4:53", // Google
}

// Init initializes the clientpool implementation
func Init(options *types.Options) error {
	// Don't create clients if already created in past.
	if normalClient != nil {
		return nil
	}
	poolMutex = &sync.RWMutex{}
	clientPool = make(map[string]*retryabledns.Client)

	normalClient = retryabledns.New(defaultResolvers, 1)
	return nil
}

// Configuration contains the custom configuration options for a client
type Configuration struct {
	// Retries contains the retries for the dns client
	Retries int
}

// Hash returns the hash of the configuration to allow client pooling
func (c *Configuration) Hash() string {
	builder := &strings.Builder{}
	builder.Grow(8)
	builder.WriteString("r")
	builder.WriteString(strconv.Itoa(c.Retries))
	hash := builder.String()
	return hash
}

// Get creates or gets a client for the protocol based on custom configuration
func Get(options *types.Options, configuration *Configuration) (*retryabledns.Client, error) {
	if !(configuration.Retries > 1) {
		return normalClient, nil
	}
	hash := configuration.Hash()
	poolMutex.RLock()
	if client, ok := clientPool[hash]; ok {
		poolMutex.RUnlock()
		return client, nil
	}
	poolMutex.RUnlock()

	client := retryabledns.New(defaultResolvers, configuration.Retries)

	poolMutex.Lock()
	clientPool[hash] = client
	poolMutex.Unlock()
	return client, nil
}
