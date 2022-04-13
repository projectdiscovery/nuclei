package http

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/stringsutil"
	"github.com/projectdiscovery/urlutil"
)

// @Host:target overrides the input target with the annotated one (similar to self-contained requests)
var reHostAnnotation = regexp.MustCompile(`(?m)^@Host:\s*(.+)\s*$`)

// parseAnnotations and override requests settings
func parseAnnotations(rawRequest string, request *http.Request) {
	// parse request for known ovverride annotations
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
		}
	}
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
