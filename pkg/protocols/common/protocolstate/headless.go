package protocolstate

import (
	"context"
	"net"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
	"go.uber.org/multierr"
)

// initalize state of headless protocol

var (
	ErrURLDenied  = errorutil.NewWithFmt("headless: url %v dropped by rule: %v")
	ErrHostDenied = errorutil.NewWithFmt("host %v dropped by network policy")

	allowLocalFileAccess bool
)

func GetNetworkPolicy(ctx context.Context) *networkpolicy.NetworkPolicy {
	execCtx := GetExecutionContext(ctx)
	if execCtx == nil {
		return nil
	}
	dialers, ok := dialers.Get(execCtx.ExecutionID)
	if !ok || dialers == nil {
		return nil
	}
	return dialers.NetworkPolicy
}

// ValidateNFailRequest validates and fails request
// if the request does not respect the rules, it will be canceled with reason
func ValidateNFailRequest(options *types.Options, page *rod.Page, e *proto.FetchRequestPaused) error {
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
	if !isValidHost(options, reqURL) {
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
func InitHeadless(localFileAccess bool) {
	allowLocalFileAccess = localFileAccess
}

// isValidHost checks if the host is valid (only limited to http/https protocols)
func isValidHost(options *types.Options, targetUrl string) bool {
	if !stringsutil.HasPrefixAny(targetUrl, "http:", "https:") {
		return true
	}

	dialers, ok := dialers.Get(options.ExecutionId)
	if !ok {
		return true
	}

	np := dialers.NetworkPolicy
	if !ok || np == nil {
		return true
	}

	urlx, err := urlutil.Parse(targetUrl)
	if err != nil {
		// not a valid url
		return false
	}
	targetUrl = urlx.Hostname()
	_, ok = np.ValidateHost(targetUrl)
	return ok
}

// IsHostAllowed checks if the host is allowed by network policy
func IsHostAllowed(executionId string, targetUrl string) bool {
	dialers, ok := dialers.Get(executionId)
	if !ok {
		return true
	}

	np := dialers.NetworkPolicy
	if !ok || np == nil {
		return true
	}

	sepCount := strings.Count(targetUrl, ":")
	if sepCount > 1 {
		// most likely a ipv6 address (parse url and validate host)
		return np.Validate(targetUrl)
	}
	if sepCount == 1 {
		host, _, _ := net.SplitHostPort(targetUrl)
		if _, ok := np.ValidateHost(host); !ok {
			return false
		}
		return true
	}
	// just a hostname or ip without port
	_, ok = np.ValidateHost(targetUrl)
	return ok
}
