package http

import (
	"net/http"
	"strings"
)

// Known honeypot Server header substrings (lowercase). If the Server header
// contains any of these, IsHoneypot returns true.
var honeypotServerSignatures = []string{
	"honeyd",
	"cowrie",
	"dionaea",
	"canarynetwork",
	"nepenthes",
	"kippo",
	"canarytokens",
}

// IsHoneypot returns true if the HTTP response appears to come from a known
// honeypot based on the Server header. Body is reserved for future heuristics.
func IsHoneypot(resp *http.Response, body []byte) bool {
	if resp == nil {
		return false
	}
	server := strings.ToLower(strings.TrimSpace(resp.Header.Get("Server")))
	if server == "" {
		return false
	}
	for _, sig := range honeypotServerSignatures {
		if strings.Contains(server, sig) {
			return true
		}
	}
	return false
}
