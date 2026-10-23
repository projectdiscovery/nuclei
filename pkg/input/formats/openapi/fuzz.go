//go:build gofuzz
// +build gofuzz

package openapi

// Fuzz exercises OpenAPI 3.0 schema parsing and request generation. The input
// bytes are treated as a raw schema document (YAML or JSON) and fed through the
// format's Parse, which loads the schema and generates requests from it.
func Fuzz(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if len(data) > fuzzMaxInputSize {
		return -1
	}
	if !fuzzOpenAPIParsing(data) {
		return 0
	}
	return 1
}
