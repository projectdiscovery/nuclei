package dns

import (
	"fmt"

	"github.com/cespare/xxhash"
)

// CanCluster returns true if the request can be clustered.
//
// This used by the clustering engine to decide whether two requests
// are similar enough to be considered one and can be checked by
// just adding the matcher/extractors for the request and the correct IDs.
func (request *Request) CanCluster(other *Request) bool {
	if request.Recursion != nil {
		if other.Recursion == nil {
			return false
		}
		if *request.Recursion != *other.Recursion {
			return false
		}
	}
	return true
}

func (request *Request) ClusterHash() uint64 {
	inp := fmt.Sprintf("%s-%d-%d-%d", request.Name, request.class, request.Retries, request.question)
	return xxhash.Sum64String(inp)
}

func (request *Request) IsClusterable() bool {
	return !(len(request.Resolvers) > 0 || request.Trace || request.ID != "")
}
