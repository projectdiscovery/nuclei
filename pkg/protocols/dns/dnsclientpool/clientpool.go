package dnsclientpool

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryabledns"
)

// defaultResolvers contains the list of resolvers known to be trusted.
var defaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare
	"1.0.0.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"8.8.4.4:53", // Google
}

func GetResolversOrDefault(options *types.Options) []string {
	resolvers := defaultResolvers
	if len(options.InternalResolversList) > 0 {
		resolvers = options.InternalResolversList
	}
	return resolvers
}

// Configuration contains the custom configuration options for a client
type Configuration struct {
	// Retries contains the retries for the dns client
	Retries int
	// Resolvers contains the specific per request resolvers
	Resolvers []string
}

// Get creates a new dns client with scoped usage
// all other usages should rely on ExecuterOptions.Dialers.dnsClient
func Get(options *types.Options, configuration *Configuration) (*retryabledns.Client, error) {
	resolvers := defaultResolvers
	if len(options.InternalResolversList) > 0 {
		resolvers = options.InternalResolversList
	} else if len(configuration.Resolvers) > 0 {
		resolvers = configuration.Resolvers
	}
	client, err := retryabledns.New(resolvers, configuration.Retries)
	if err != nil {
		return nil, errors.Wrap(err, "could not create dns client")
	}
	return client, nil
}
