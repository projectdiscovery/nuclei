//go:build gofuzz
// +build gofuzz

package types

// Fuzz exercises raw HTTP request parsing used by input format ingestion.
func Fuzz(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if len(data) > fuzzMaxInputSize {
		return -1
	}
	if !fuzzRawRequestParsing(data) {
		return 0
	}
	return 1
}
