package http

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/stringsutil"
	"github.com/projectdiscovery/urlutil"
)

var (
	// @Host:target overrides the input target with the annotated one (similar to self-contained requests)
	reHostAnnotation = regexp.MustCompile(`(?m)^@Host:\s*(.+)\s*$`)
	// @tls-sni:target overrides the input target with the annotated one
	// special values:
	// request.host: takes the value from the host header
	// target: overiddes with the specific value
	reSniAnnotation = regexp.MustCompile(`(?m)^@tls-sni:\s*(.+)\s*$`)
	// @timeout:duration overrides the input timout with a custom duration
	reTimeoutAnnotation = regexp.MustCompile(`(?m)^@timeout:\s*(.+)\s*$`)
)

// parseAnnotations and override requests settings
func (r *Request) parseAnnotations(rawRequest string, request *http.Request) (*http.Request, bool) {
	// parse request for known ovverride annotations
	var modified bool
	// @Host:target
	if hosts := reHostAnnotation.FindStringSubmatch(rawRequest); len(hosts) > 0 {
		value := strings.TrimSpace(hosts[1])
		// handle scheme
		switch {
		case stringsutil.HasPrefixI(value, "http://"):
			request.URL.Scheme = urlutil.HTTP
		case stringsutil.HasPrefixI(value, "https://"):
			request.URL.Scheme = urlutil.HTTPS
		}

		value = stringsutil.TrimPrefixAny(value, "http://", "https://")

		if isHostPort(value) {
			request.URL.Host = value
		} else {
			hostPort := value
			port := request.URL.Port()
			if port != "" {
				hostPort = net.JoinHostPort(hostPort, port)
			}
			request.URL.Host = hostPort
		}
		modified = true
	}

	// @tls-sni:target
	if hosts := reSniAnnotation.FindStringSubmatch(rawRequest); len(hosts) > 0 {
		value := strings.TrimSpace(hosts[1])
		value = stringsutil.TrimPrefixAny(value, "http://", "https://")
		if idxForwardSlash := strings.Index(value, "/"); idxForwardSlash >= 0 {
			value = value[:idxForwardSlash]
		}

		if stringsutil.EqualFoldAny(value, "request.host") {
			value = request.Host
		}
		ctx := context.WithValue(request.Context(), fastdialer.SniName, value)
		request = request.Clone(ctx)
		modified = true
	}

	// @timeout:duration
	if r.connConfiguration.NoTimeout {
		modified = true

		if duration := reTimeoutAnnotation.FindStringSubmatch(rawRequest); len(duration) > 0 {
			value := strings.TrimSpace(duration[1])
			if parsed, err := time.ParseDuration(value); err == nil {
				//nolint:govet // cancelled automatically by withTimeout
				ctx, _ := context.WithTimeout(request.Context(), parsed)
				request = request.Clone(ctx)
			}
		} else {
			//nolint:govet // cancelled automatically by withTimeout
			ctx, _ := context.WithTimeout(request.Context(), time.Duration(r.options.Options.Timeout)*time.Second)
			request = request.Clone(ctx)
		}
	}

	return request, modified
}

func isHostPort(value string) bool {
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	if !iputil.IsPort(port) {
		return false
	}
	return true
}
