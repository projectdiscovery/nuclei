//go:build gofuzz
// +build gofuzz

package templates

// Fuzz exercises YAML and JSON template parsing plus compile-time validation
// without executing any protocol requests.
func Fuzz(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if len(data) > fuzzMaxInputSize {
		return -1
	}
	if !fuzzTemplateParsing(data) {
		return 0
	}
	return 1
}
