package hostratelimit

import (
	"fmt"
	"net"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
)

// NormalizeHostPort extracts and normalizes "hostname:port" from a URL or
// host[:port] string. Default ports (80/443) are derived from the scheme when
// missing. It is shared by the per-host rate limit pool and the HTTP-to-HTTPS
// port tracker so that both group entries by the same key.
func NormalizeHostPort(rawURL string) string {
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
		port = defaultPort(scheme)
	}

	// Return just hostname:port (no scheme prefix)
	return fmt.Sprintf("%s:%s", hostname, port)
}

// extractHostPort attempts to extract host:port from a string when URL parsing fails
func extractHostPort(s string) string {
	original := s
	scheme := "http"

	// Remove scheme prefix if present
	switch {
	case strings.HasPrefix(s, "wss://"):
		s = strings.TrimPrefix(s, "wss://")
		scheme = "wss"
	case strings.HasPrefix(s, "ws://"):
		s = strings.TrimPrefix(s, "ws://")
		scheme = "ws"
	case strings.HasPrefix(s, "https://"):
		s = strings.TrimPrefix(s, "https://")
		scheme = "https"
	case strings.HasPrefix(s, "http://"):
		s = strings.TrimPrefix(s, "http://")
		scheme = "http"
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
			port = defaultPort(scheme)
		}
		// Return just host:port (no scheme prefix)
		return fmt.Sprintf("%s:%s", host, port)
	}

	return fmt.Sprintf("%s:%s", s, defaultPort(scheme))
}

func defaultPort(scheme string) string {
	if scheme == "https" || scheme == "wss" {
		return "443"
	}
	return "80"
}
