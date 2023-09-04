package httputil

import (
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types/scanstrategy"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	// TODO: adapt regex for cases where port is updated
	urlWithPortRegex = regexp.MustCompile(`^{{(BaseURL|RootURL)}}:(\d+)`)
	// regex to detect trailing slash in path (not applicable to raw requests)
	trailingSlashregex = regexp.MustCompile(`^\Q{{\E[a-zA-Z]+\Q}}/\E`)
	// ErrNoMoreRequests is internal error to
)

// HasTrailingSlash returns true if path(that has default variables) has trailing slash
func HasTrailingSlash(data string) bool {
	return trailingSlashregex.MatchString(data)
}

// UpdateURLPortFromPayload overrides input port if specified in payload(ex: {{BaseURL}}:8080)
func UpdateURLPortFromPayload(parsed *urlutil.URL, data string) (*urlutil.URL, string) {
	matches := urlWithPortRegex.FindAllStringSubmatch(data, -1)
	if len(matches) > 0 {
		port := matches[0][2]
		parsed.UpdatePort(port)
		// remove it from dsl
		data = strings.Replace(data, ":"+port, "", 1)
	}
	return parsed, data
}

// setHeader sets some headers only if the header wasn't supplied by the user
func SetHeader(req *retryablehttp.Request, name, value string) {
	if _, ok := req.Header[name]; !ok {
		req.Header.Set(name, value)
	}
	if name == "Host" {
		req.Host = value
	}
}

// ShouldDisableKeepAlive depending on scan strategy
func ShouldDisableKeepAlive(options *types.Options) bool {
	// with host-spray strategy keep-alive must be enabled
	return options.ScanStrategy != scanstrategy.HostSpray.String()
}
