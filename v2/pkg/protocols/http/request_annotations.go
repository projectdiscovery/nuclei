package http

import (
	"net/http"
	"regexp"
	"strings"
)

// @Host:target overrides the input target with the annotated one (similar to self-contained requests)
var reHostAnnotation = regexp.MustCompile(`(?m)^@Host:(.+)$`)

// parseAnnotations and override requests settings
func parseAnnotations(rawRequest string, request *http.Request) {
	// parse request for known ovverride annotations
	if hosts := reHostAnnotation.FindStringSubmatch(rawRequest); len(hosts) > 0 {
		host := strings.TrimSpace(hosts[1])
		request.URL.Host = host
	}
}
