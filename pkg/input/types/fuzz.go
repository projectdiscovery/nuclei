//go:build gofuzz
// +build gofuzz

package types

func Fuzz(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if len(data) > fuzzMaxInputSize {
		return -1
	}

	raw := string(data)

	rr, err := ParseRawRequest(raw)
	if err != nil {
		return 0
	}

	if rr == nil {
		return 0
	}

	if rr.Request != nil {
		if rr.Request.Method != "" && rr.Request.Method != "GET" &&
		   rr.Request.Method != "POST" && rr.Request.Method != "PUT" &&
		   rr.Request.Method != "DELETE" && rr.Request.Method != "PATCH" &&
		   rr.Request.Method != "HEAD" && rr.Request.Method != "OPTIONS" {
			return 0
		}
	}

	return 1
}

const fuzzMaxInputSize = 64 * 1024