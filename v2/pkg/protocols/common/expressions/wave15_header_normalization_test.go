package expressions

import (
	"strings"
	"testing"
)

// TestWave15HeaderKeyCanonicalCasing asserts HTTP header normalization
func TestWave15HeaderKeyCanonicalCasing(t *testing.T) {
	canonicalizeHeader := func(key string) string {
		parts := strings.Split(key, "-")
		for i, p := range parts {
			if len(p) > 0 {
				parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
			}
		}
		return strings.Join(parts, "-")
	}

	testCases := []struct {
		input    string
		expected string
	}{
		{"content-type", "Content-Type"},
		{"X-NUCLEI-TRACE", "X-Nuclei-Trace"},
		{"authorization", "Authorization"},
		{"sec-ch-ua-platform", "Sec-Ch-Ua-Platform"},
	}

	for _, tc := range testCases {
		actual := canonicalizeHeader(tc.input)
		if actual != tc.expected {
			t.Errorf("canonicalizeHeader(%s): expected %s, got %s", tc.input, tc.expected, actual)
		}
	}
}

// TestWave15StatusCodeEqualityOperator asserts numeric status match
func TestWave15StatusCodeEqualityOperator(t *testing.T) {
	isStatusMatched := func(respCode, ruleCode int) bool {
		return respCode == ruleCode
	}

	if !isStatusMatched(403, 403) {
		t.Errorf("expected status code 403 equality match")
	}
	if isStatusMatched(200, 404) {
		t.Errorf("expected mismatched status codes to return false")
	}
}
