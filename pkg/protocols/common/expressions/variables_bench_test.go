package expressions

import (
	"strings"
	"testing"
)

func BenchmarkContainsUnresolvedVariables(b *testing.B) {
	const request = "POST /api/search?q=example%20value HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n"
	for _, tc := range []struct {
		name, input string
		unresolved  bool
	}{
		{name: "dsl", input: "status_code == 200 && contains(body, 'example')"},
		{name: "http", input: request + `{"query":"example"}`},
		{name: "http-large-body", input: request + `{"query":"` + strings.Repeat("example ", 1024) + `"}`},
		{name: "http-unresolved", input: request + `{"query":"{{query}}"}`, unresolved: true},
		{name: "http-unresolved-encoded", input: request + `{"query":"%7B%7Bquery%7D%7D"}`, unresolved: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				err := ContainsUnresolvedVariables(tc.input)
				if (err != nil) != tc.unresolved {
					b.Fatalf("unexpected variable check result: %v", err)
				}
			}
		})
	}
}
