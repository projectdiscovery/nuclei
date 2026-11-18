package dnsclientpool

import (
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryabledns"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var (
	clientPool *mapsutil.SyncLockMap[string, *Client]

	normalClient *Client
	m            sync.Mutex
)

// defaultResolvers contains the list of resolvers known to be trusted.
var defaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"8.8.4.4:53", // Google
}

// Init initializes the client pool implementation.
// Each resolver list gets its own client, so a later scan is not stuck with the first scan's resolvers.
func Init(options *types.Options) error {
	client, err := cachedClient(resolversFor(options))
	if err != nil {
		return errors.Wrap(err, "could not create dns client")
	}
	m.Lock()
	normalClient = client
	m.Unlock()
	return nil
}

func resolversFor(options *types.Options) []string {
	if options != nil && len(options.InternalResolversList) > 0 {
		return options.InternalResolversList
	}
	return defaultResolvers
}

func cachedClient(resolvers []string) (*Client, error) {
	m.Lock()
	defer m.Unlock()
	if clientPool == nil {
		clientPool = mapsutil.NewSyncLockMap[string, *Client]()
	}
	key := strings.Join(resolvers, ",")
	if client, ok := clientPool.Get(key); ok {
		return client, nil
	}
	dnsClient, err := retryabledns.New(resolvers, 1)
	if err != nil {
		return nil, err
	}
	client := &Client{Client: dnsClient}
	_ = clientPool.Set(key, client)
	return client, nil
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
func Get(options *types.Options, configuration *Configuration) (*Client, error) {
	if (configuration.Retries <= 1) && len(configuration.Resolvers) == 0 {
		return cachedClient(resolversFor(options))
	}
	if len(options.InternalResolversList) == 0 && hasPolicyResolver(configuration.Resolvers) {
		return getPolicyClient(options, configuration)
	}
	hash := configuration.Hash()
	if client, ok := clientPool.Get(hash); ok {
		return client, nil
	}

	resolvers := defaultResolvers
	if len(options.InternalResolversList) > 0 {
		resolvers = options.InternalResolversList
	} else if len(configuration.Resolvers) > 0 {
		resolvers = configuration.Resolvers
	}
	dnsClient, err := retryabledns.NewWithOptions(retryabledns.Options{
		BaseResolvers: resolvers,
		MaxRetries:    configuration.Retries,
		Proxy:         options.AliveSocksProxy,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create dns client")
	}
	client := &Client{Client: dnsClient}
	_ = clientPool.Set(hash, client)

	return client, nil
}
