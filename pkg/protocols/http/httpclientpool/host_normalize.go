package httpclientpool

import (
	"fmt"
	"net"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
)

// normalizeHostPort extracts and normalizes "hostname:port" from a URL or
// host[:port] string. Default ports (80/443) are derived from the scheme when
// missing. It is shared by the per-host rate limit pool and the HTTP-to-HTTPS
// port tracker so that both group entries by the same key.
func normalizeHostPort(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := urlutil.Parse(rawURL)
	if err != nil {
		// If parsing fails, try to extract host:port manually
		return extractHostPort(rawURL)
	}

	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "http"
	}

	// Extract just the hostname (without port) and port separately
	hostname := parsed.Hostname()
	if hostname == "" {
		// Fallback: try to extract from Host field
		host := parsed.Host
		if host != "" {
			// Split host:port if port is present
			if h, _, err := net.SplitHostPort(host); err == nil {
				hostname = h
			} else {
				hostname = host
			}
		}
	}

	if hostname == "" {
		return extractHostPort(rawURL)
	}

	port := parsed.Port()
	if port == "" {
		// Use default ports based on scheme
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Return just hostname:port (no scheme prefix)
	return fmt.Sprintf("%s:%s", hostname, port)
}

// extractHostPort attempts to extract host:port from a string when URL parsing fails
func extractHostPort(s string) string {
	original := s
	scheme := "http"

	// Remove scheme prefix if present
	if strings.HasPrefix(s, "http://") {
		s = strings.TrimPrefix(s, "http://")
		scheme = "http"
	} else if strings.HasPrefix(s, "https://") {
		s = strings.TrimPrefix(s, "https://")
		scheme = "https"
	}

	// Extract up to first /, ?, #, space, or newline (path/query/fragment separator)
	if idx := strings.IndexAny(s, "/?# \n\r\t"); idx != -1 {
		s = s[:idx]
	}

	if s == "" {
		return original // Return original if we can't extract anything
	}

	// Validate and split host:port
	host, port, err := net.SplitHostPort(s)
	if err == nil {
		// Valid host:port format
		if port == "" {
			// Port is empty, use default
			if scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		// Return just host:port (no scheme prefix)
		return fmt.Sprintf("%s:%s", host, port)
	}

	// No port in string, add default port
	if scheme == "https" {
		return fmt.Sprintf("%s:443", s)
	}
	return fmt.Sprintf("%s:80", s)
}
