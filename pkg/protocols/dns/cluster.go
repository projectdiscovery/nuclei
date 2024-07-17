package dns

import (
	"fmt"

	"github.com/cespare/xxhash"
)


// TmplClusterKey generates a unique key for the request
// to be used in the clustering process.
func (request *Request) TmplClusterKey() uint64 {
	recursion := ""
	if request.Recursion != nil {
		recursion = fmt.Sprintf("%t", *request.Recursion)
	}
	inp := fmt.Sprintf("%s-%d-%d-%d-%s", request.Name, request.class, request.Retries, request.question, recursion)
	return xxhash.Sum64String(inp)
}

// IsClusterable returns true if the request is eligible to be clustered.
func (request *Request) IsClusterable() bool {
	return !(len(request.Resolvers) > 0 || request.Trace || request.ID != "")
}
