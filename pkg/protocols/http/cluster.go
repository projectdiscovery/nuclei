package http

import (
	"fmt"
	"strings"

	"github.com/cespare/xxhash"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
)

// TmplClusterKey generates a unique key for the request
// to be used in the clustering process.
func (request *Request) TmplClusterKey() uint64 {
	inp := fmt.Sprintf("%s-%d-%t-%t-%s-%d", request.Method.String(), request.MaxRedirects, request.DisableCookie, request.Redirects, strings.Join(request.Path, "-"), utils.MapHash(request.Headers))
	return xxhash.Sum64String(inp)
}

// IsClusterable returns true if the request is eligible to be clustered.
func (request *Request) IsClusterable() bool {
	return !(len(request.Payloads) > 0 || len(request.Fuzzing) > 0 || len(request.Raw) > 0 || len(request.Body) > 0 || request.Unsafe || request.NeedsRequestCondition() || request.Name != "")
}
