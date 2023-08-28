package protocolstate

import (
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
	networkPolicy        *networkpolicy.NetworkPolicy
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
func InitHeadless(RestrictLocalNetworkAccess bool, localFileAccess bool) {
	allowLocalFileAccess = localFileAccess
	if !RestrictLocalNetworkAccess {
		return
	}
	networkPolicy, _ = networkpolicy.New(networkpolicy.Options{
		DenyList: append(networkpolicy.DefaultIPv4DenylistRanges, networkpolicy.DefaultIPv6DenylistRanges...),
	})
}

// isValidHost checks if the host is valid (only limited to http/https protocols)
func isValidHost(targetUrl string) bool {
	if !stringsutil.HasPrefixAny(targetUrl, "http:", "https:") {
		return true
	}
	if networkPolicy == nil {
		return true
	}
	urlx, err := urlutil.Parse(targetUrl)
	if err != nil {
		// not a valid url
		return false
	}
	targetUrl = urlx.Hostname()
	_, ok := networkPolicy.ValidateHost(targetUrl)
	return ok
}
