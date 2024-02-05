package protocolstate

import (
	"net"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/networkpolicy"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
	"go.uber.org/multierr"
)

// initalize state of headless protocol

var (
	ErrURLDenied         = errorutil.NewWithFmt("headless: url %v dropped by rule: %v")
	ErrHostDenied        = errorutil.NewWithFmt("host %v dropped by network policy")
	NetworkPolicy        *networkpolicy.NetworkPolicy
	allowLocalFileAccess bool
)

// ValidateNFailRequest validates and fails request
// if the request does not respect the rules, it will be canceled with reason
func ValidateNFailRequest(page *rod.Page, e *proto.FetchRequestPaused) error {
	reqURL := e.Request.URL
	normalized := strings.ToLower(reqURL)      // normalize url to lowercase
	normalized = strings.TrimSpace(normalized) // trim leading & trailing whitespaces
	if !allowLocalFileAccess && stringsutil.HasPrefixI(normalized, "file:") {
		return multierr.Combine(FailWithReason(page, e), ErrURLDenied.Msgf(reqURL, "use of file:// protocol disabled use '-lfa' to enable"))
	}
	// validate potential invalid schemes
	// javascript protocol is allowed for xss fuzzing
	if stringsutil.HasPrefixAnyI(normalized, "ftp:", "externalfile:", "chrome:", "chrome-extension:") {
		return multierr.Combine(FailWithReason(page, e), ErrURLDenied.Msgf(reqURL, "protocol blocked by network policy"))
	}
	if !isValidHost(reqURL) {
		return multierr.Combine(FailWithReason(page, e), ErrURLDenied.Msgf(reqURL, "address blocked by network policy"))
	}
	return nil
}

// FailWithReason fails request with AccessDenied reason
func FailWithReason(page *rod.Page, e *proto.FetchRequestPaused) error {
	m := proto.FetchFailRequest{
		RequestID:   e.RequestID,
		ErrorReason: proto.NetworkErrorReasonAccessDenied,
	}
	return m.Call(page)
}

// InitHeadless initializes headless protocol state
func InitHeadless(localFileAccess bool, np *networkpolicy.NetworkPolicy) {
	allowLocalFileAccess = localFileAccess
	if np != nil {
		NetworkPolicy = np
	}
}

// isValidHost checks if the host is valid (only limited to http/https protocols)
func isValidHost(targetUrl string) bool {
	if !stringsutil.HasPrefixAny(targetUrl, "http:", "https:") {
		return true
	}
	if NetworkPolicy == nil {
		return true
	}
	urlx, err := urlutil.Parse(targetUrl)
	if err != nil {
		// not a valid url
		return false
	}
	targetUrl = urlx.Hostname()
	_, ok := NetworkPolicy.ValidateHost(targetUrl)
	return ok
}

// IsHostAllowed checks if the host is allowed by network policy
func IsHostAllowed(targetUrl string) bool {
	if NetworkPolicy == nil {
		return true
	}
	sepCount := strings.Count(targetUrl, ":")
	if sepCount > 1 {
		// most likely a ipv6 address (parse url and validate host)
		return NetworkPolicy.Validate(targetUrl)
	}
	if sepCount == 1 {
		host, _, _ := net.SplitHostPort(targetUrl)
		if _, ok := NetworkPolicy.ValidateHost(host); !ok {
			return false
		}
		return true
		// portInt, _ := strconv.Atoi(port)
		// fixme:  broken port validation logic in networkpolicy
		// if !NetworkPolicy.ValidatePort(portInt) {
		// 	return false
		// }
	}
	// just a hostname or ip without port
	_, ok := NetworkPolicy.ValidateHost(targetUrl)
	return ok
}
