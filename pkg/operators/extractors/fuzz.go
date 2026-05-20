//go:build gofuzz
// +build gofuzz

package extractors

import "github.com/projectdiscovery/nuclei/v3/pkg/operators/cache"

func init() {
	cache.SetCapacities(128, 128)
}

// Fuzz exercises extractor compilation and extraction with a compact line-based grammar.
func Fuzz(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if len(data) > fuzzMaxInputSize {
		return -1
	}

	extractor, ok := extractorFromFuzzData(data)
	if !ok {
		return 0
	}
	if err := extractor.CompileExtractors(); err != nil {
		return 0
	}
	exerciseFuzzExtractor(extractor)
	return 1
}
