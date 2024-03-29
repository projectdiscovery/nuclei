package signerpool

import (
	"fmt"
	"sync"

	"github.com/cespare/xxhash/v2"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/signer"
	"github.com/projectdiscovery/utils/conversion"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

type SignerPool struct {
	poolMutex  *sync.RWMutex
	clientPool map[uint64]signer.Signer
}

func New(options *types.Options) (*SignerPool, error) {
	sp := &SignerPool{
		poolMutex:  &sync.RWMutex{},
		clientPool: make(map[uint64]signer.Signer),
	}
	return sp, nil
}

// Configuration contains the custom configuration options for a client
type Configuration struct {
	SignerArgs signer.SignerArgs
}

// Hash returns the hash of the configuration to allow client pooling
func (c *Configuration) Hash() uint64 {
	return xxhash.Sum64(conversion.Bytes(fmt.Sprint(c.SignerArgs)))
}

// Get creates or gets a client for the protocol based on custom configuration
func (sp *SignerPool) Get(options *types.Options, configuration *Configuration) (signer.Signer, error) {
	hash := configuration.Hash()
	sp.poolMutex.RLock()
	if client, ok := sp.clientPool[hash]; ok {
		sp.poolMutex.RUnlock()
		return client, nil
	}
	sp.poolMutex.RUnlock()

	client, err := signer.NewSigner(configuration.SignerArgs)
	if err != nil {
		return nil, err
	}

	sp.poolMutex.Lock()
	sp.clientPool[hash] = client
	sp.poolMutex.Unlock()
	return client, nil
}
