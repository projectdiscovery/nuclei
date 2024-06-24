package http

import (
	"fmt"
	"strings"

	"github.com/cespare/xxhash"
	"golang.org/x/exp/maps"
)

// CanCluster returns true if the request can be clustered.
//
// This used by the clustering engine to decide whether two requests
// are similar enough to be considered one and can be checked by
// just adding the matcher/extractors for the request and the correct IDs.
func (request *Request) CanCluster(other *Request) bool {
	return maps.Equal(request.Headers, other.Headers)
}

func (request *Request) ClusterHash() uint64 {
	inp := fmt.Sprintf("%s-%d-%t-%t-%s", request.Method.String(), request.MaxRedirects, request.DisableCookie, request.Redirects, strings.Join(request.Path, "-"))
	return xxhash.Sum64String(inp)
}

func (request *Request) IsClusterable() bool {
	return !(len(request.Payloads) > 0 || len(request.Fuzzing) > 0 || len(request.Raw) > 0 || len(request.Body) > 0 || request.Unsafe || request.NeedsRequestCondition() || request.Name != "")
}
