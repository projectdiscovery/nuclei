package offlinehttp

import (
	"fmt"
	"io"
	"testing"
)

func TestReadResponsePreservesHTTPVersionText(t *testing.T) {
	body := "Supports HTTP/2 and HTTP/3."
	tests := []struct {
		name   string
		raw    string
		proto  string
		status string
		header string
	}{
		{
			name:   "body without content length",
			raw:    "HTTP/1.1 200 OK\r\n\r\n" + body,
			proto:  "HTTP/1.1",
			status: "200 OK",
		},
		{
			name:   "body with content length",
			raw:    fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body),
			proto:  "HTTP/1.1",
			status: "200 OK",
		},
		{
			name:   "chunked body",
			raw:    fmt.Sprintf("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body),
			proto:  "HTTP/1.1",
			status: "200 OK",
		},
		{
			name:   "header value",
			raw:    "HTTP/1.1 200 OK\r\nServer: HTTP/2 gateway\r\n\r\n" + body,
			proto:  "HTTP/1.1",
			status: "200 OK",
			header: "HTTP/2 gateway",
		},
		{
			name:   "reason phrase",
			raw:    "HTTP/1.1 200 HTTP/2 supported\r\n\r\n" + body,
			proto:  "HTTP/1.1",
			status: "200 HTTP/2 supported",
		},
		{
			name:   "HTTP 2 missing minor version",
			raw:    "HTTP/2 200 OK\r\n\r\n" + body,
			proto:  "HTTP/2.0",
			status: "200 OK",
		},
		{
			name:   "HTTP 3 missing minor version",
			raw:    "HTTP/3 200 OK\r\n\r\n" + body,
			proto:  "HTTP/3.0",
			status: "200 OK",
		},
		{
			name:   "request followed by response",
			raw:    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHTTP/1.1 200 OK\r\n\r\n" + body,
			proto:  "HTTP/1.1",
			status: "200 OK",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := readResponseFromString(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}
			if string(got) != body {
				t.Errorf("body = %q, want %q", got, body)
			}
			if resp.Proto != tt.proto {
				t.Errorf("protocol = %q, want %q", resp.Proto, tt.proto)
			}
			if resp.Status != tt.status {
				t.Errorf("status = %q, want %q", resp.Status, tt.status)
			}
			if got := resp.Header.Get("Server"); got != tt.header {
				t.Errorf("Server header = %q, want %q", got, tt.header)
			}
		})
	}
}
