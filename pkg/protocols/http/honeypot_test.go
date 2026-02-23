package http

import (
	"net/http"
	"testing"
)

func TestIsHoneypot(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		body     []byte
		want     bool
	}{
		{
			name:   "normal server nginx",
			server: "nginx",
			body:   nil,
			want:   false,
		},
		{
			name:   "cowrie honeypot",
			server: "cowrie",
			body:   nil,
			want:   true,
		},
		{
			name:   "honeyd server",
			server: "honeyd v1.5",
			body:   nil,
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{"Server": []string{tt.server}},
			}
			got := IsHoneypot(resp, tt.body)
			if got != tt.want {
				t.Errorf("IsHoneypot(Server: %q) = %v, want %v", tt.server, got, tt.want)
			}
		})
	}
}
