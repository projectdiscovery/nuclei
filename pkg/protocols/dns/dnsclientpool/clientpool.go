package dnsclientpool

import (
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryabledns"
)

var (
	poolMutex  *sync.RWMutex
	clientPool map[string]*retryabledns.Client

	normalClient *retryabledns.Client
	m            sync.Mutex
)

// defaultResolvers contains the list of resolvers known to be trusted.
var defaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"8.8.4.4:53", // Google
}

// Init initializes the client pool implementation
func Init(options *types.Options) error {
	m.Lock()
	defer m.Unlock()

	// Don't create clients if already created in the past.
	if normalClient != nil {
		return nil
	}
	poolMutex = &sync.RWMutex{}
	clientPool = make(map[string]*retryabledns.Client)

	resolvers := defaultResolvers
	if len(options.InternalResolversList) > 0 {
		resolvers = options.InternalResolversList
	}
	var err error
	normalClient, err = retryabledns.New(resolvers, 1)
	if err != nil {
		return errors.Wrap(err, "could not create dns client")
	}
	return nil
}

func getNormalClient() *retryabledns.Client {
	m.Lock()
	defer m.Unlock()
	return normalClient
}

// Configuration contains the custom configuration options for a client
type Configuration struct {
	// Retries contains the retries for the dns client
	Retries int
	// Resolvers contains the specific per request resolvers
	Resolvers []string
	// Proxy contains the proxy to use for the dns client
	Proxy string
}

// Hash returns the hash of the configuration to allow client pooling
func (c *Configuration) Hash() string {
	builder := &strings.Builder{}
	builder.WriteString("r")
	builder.WriteString(strconv.Itoa(c.Retries))
	builder.WriteString("l")
	builder.WriteString(strings.Join(c.Resolvers, ""))
	builder.WriteString("p")
	builder.WriteString(c.Proxy)
	hash := builder.String()
	return hash
}

// Get creates or gets a client for the protocol based on custom configuration
func Get(options *types.Options, configuration *Configuration) (*retryabledns.Client, error) {
	if (configuration.Retries <= 1) && len(configuration.Resolvers) == 0 {
		return getNormalClient(), nil
	}
	hash := configuration.Hash()
	poolMutex.RLock()
	if client, ok := clientPool[hash]; ok {
		poolMutex.RUnlock()
		return client, nil
	}
	poolMutex.RUnlock()

	resolvers := defaultResolvers
	if len(options.InternalResolversList) > 0 {
		resolvers = options.InternalResolversList
	} else if len(configuration.Resolvers) > 0 {
		resolvers = configuration.Resolvers
	}
	client, err := retryabledns.NewWithOptions(retryabledns.Options{
		BaseResolvers: resolvers,
		MaxRetries:    configuration.Retries,
		Proxy:         options.AliveSocksProxy,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create dns client")
	}

	poolMutex.Lock()
	clientPool[hash] = client
	poolMutex.Unlock()
	return client, nil
}
