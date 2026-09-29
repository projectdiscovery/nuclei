//go:build gofuzz
// +build gofuzz

package matchers

import "github.com/projectdiscovery/nuclei/v3/pkg/operators/cache"

func init() {
	cache.SetCapacities(128, 128)
}

// Fuzz exercises matcher compilation with a compact line-based grammar.
func Fuzz(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if len(data) > fuzzMaxInputSize {
		return -1
	}

	matcher, ok := matcherFromFuzzData(data)
	if !ok {
		return 0
	}
	if err := matcher.CompileMatchers(); err != nil {
		return 0
	}
	return 1
}
