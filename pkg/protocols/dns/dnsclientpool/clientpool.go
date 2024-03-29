package dnsclientpool

import (
	"fmt"
	"strings"
	"sync"

	"github.com/cespare/xxhash"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/utils/conversion"
)

type DnsClientPool struct {
	poolMutex    *sync.RWMutex
	normalClient *retryabledns.Client
	clientPool   map[uint64]*retryabledns.Client
}

// defaultResolvers contains the list of resolvers known to be trusted.
var defaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"8.8.4.4:53", // Google
}

// Init initializes the client pool implementation
func New(options *types.Options) (*DnsClientPool, error) {
	dcPool := &DnsClientPool{
		poolMutex:  &sync.RWMutex{},
		clientPool: make(map[uint64]*retryabledns.Client),
	}

	resolvers := defaultResolvers
	if options.ResolversFile != "" {
		resolvers = options.InternalResolversList
	}
	var err error
	dcPool.normalClient, err = retryabledns.New(resolvers, 1)
	if err != nil {
		return nil, errors.Wrap(err, "could not create dns client")
	}
	return dcPool, nil
}

// Configuration contains the custom configuration options for a client
type Configuration struct {
	// Retries contains the retries for the dns client
	Retries int
	// Resolvers contains the specific per request resolvers
	Resolvers []string
}

// Hash returns the hash of the configuration to allow client pooling
func (c *Configuration) Hash() uint64 {
	return xxhash.Sum64(conversion.Bytes(fmt.Sprint(c.Retries, strings.Join(c.Resolvers, ""))))
}

// Get creates or gets a client for the protocol based on custom configuration
func (dcp *DnsClientPool) Get(options *types.Options, configuration *Configuration) (*retryabledns.Client, error) {
	if !(configuration.Retries > 1) && len(configuration.Resolvers) == 0 {
		return dcp.normalClient, nil
	}
	hash := configuration.Hash()
	dcp.poolMutex.RLock()
	if client, ok := dcp.clientPool[hash]; ok {
		dcp.poolMutex.RUnlock()
		return client, nil
	}
	dcp.poolMutex.RUnlock()

	resolvers := defaultResolvers
	if options.ResolversFile != "" {
		resolvers = options.InternalResolversList
	} else if len(configuration.Resolvers) > 0 {
		resolvers = configuration.Resolvers
	}
	client, err := retryabledns.New(resolvers, configuration.Retries)
	if err != nil {
		return nil, errors.Wrap(err, "could not create dns client")
	}

	dcp.poolMutex.Lock()
	dcp.clientPool[hash] = client
	dcp.poolMutex.Unlock()
	return client, nil
}
