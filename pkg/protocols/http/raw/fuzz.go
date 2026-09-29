//go:build gofuzz
// +build gofuzz

package raw

// Fuzz exercises raw HTTP request parsing in safe, unsafe, self-contained, and
// path-automerge modes.
func Fuzz(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if len(data) > fuzzMaxInputSize {
		return -1
	}
	if !fuzzRawHTTPParsing(data) {
		return 0
	}
	return 1
}
