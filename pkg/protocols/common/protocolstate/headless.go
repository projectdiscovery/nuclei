package protocolstate

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/errkit"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
	"go.uber.org/multierr"
)

// initialize state of headless protocol

var (
	ErrURLDenied  = errkit.New("headless: url dropped by rule")
	ErrHostDenied = errorTemplate{format: "host %v dropped by network policy"}
)

// errorTemplate provides a way to create formatted errors like the old errorutil.NewWithFmt
type errorTemplate struct {
	format string
}

func (e errorTemplate) Msgf(args ...interface{}) error {
	return errkit.Newf(e.format, args...)
}

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
	if !IsLfaAllowed(options) && stringsutil.HasPrefixI(normalized, "file:") {
		return multierr.Combine(FailWithReason(page, e), errkit.Newf("headless: url %v dropped by rule: %v", reqURL, "use of file:// protocol disabled use '-lfa' to enable"))
	}
	// validate potential invalid schemes
	// javascript protocol is allowed for xss fuzzing
	if stringsutil.HasPrefixAnyI(normalized, "ftp:", "externalfile:", "chrome:", "chrome-extension:") {
		return multierr.Combine(FailWithReason(page, e), errkit.Newf("headless: url %v dropped by rule: %v", reqURL, "protocol blocked by network policy"))
	}
	if !isValidHost(options, reqURL) {
		return multierr.Combine(FailWithReason(page, e), errkit.Newf("headless: url %v dropped by rule: %v", reqURL, "address blocked by network policy"))
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
func InitHeadless(options *types.Options) {
	dialers, ok := dialers.Get(options.ExecutionId)
	if ok && dialers != nil {
		dialers.Lock()
		dialers.LocalFileAccessAllowed = options.AllowLocalFileAccess
		dialers.RestrictLocalNetworkAccess = options.RestrictLocalNetworkAccess
		dialers.Unlock()
	}
}

func IsRestrictLocalNetworkAccess(options *types.Options) bool {
	dialers, ok := dialers.Get(options.ExecutionId)
	if ok && dialers != nil {
		dialers.Lock()
		defer dialers.Unlock()

		return dialers.RestrictLocalNetworkAccess
	}
	return false
}

// isValidHost checks if the host is valid (for http/https and ws/wss protocols)
func isValidHost(options *types.Options, targetUrl string) bool {
	normalized := strings.ToLower(strings.TrimSpace(targetUrl))
	if !stringsutil.HasPrefixAny(normalized, "http:", "https:", "ws:", "wss:") {
		return true
	}

	dialers, ok := dialers.Get(options.ExecutionId)
	if !ok {
		return true
	}

	np := dialers.NetworkPolicy
	if np == nil {
		// no policy present: deny rather than allow.
		return false
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
	if np == nil {
		// no policy present: deny rather than allow.
		return false
	}

	if urlx, err := urlutil.Parse(targetUrl); err == nil && urlx.Hostname() != "" {
		_, ok = np.ValidateHost(urlx.Hostname())
		return ok
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

// SetupHeadlessNetworkPolicy configures CDP Network blocking and WebSocket interception
// to enforce network policies on headless pages.
func SetupHeadlessNetworkPolicy(options *types.Options, page *rod.Page) error {
	if options == nil || page == nil {
		return nil
	}

	var blockedPatterns []string
	for _, target := range options.ExcludeTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if !strings.Contains(target, "/") {
			blockedPatterns = append(blockedPatterns,
				"*://"+target+"/*",
				"*://"+target+":*/*",
				"ws://"+target+"/*",
				"ws://"+target+":*/*",
				"wss://"+target+"/*",
				"wss://"+target+":*/*",
			)
		}
	}

	if options.RestrictLocalNetworkAccess {
		localPatterns := []string{
			"*://localhost/*", "*://localhost:*/*",
			"*://127.*/*", "*://127.*:*/*",
			"*://0.0.0.0/*", "*://0.0.0.0:*/*",
			"*://[::1]/*", "*://[::1]:*/*",
			"*://10.*/*", "*://10.*:*/*",
			"*://192.168.*/*", "*://192.168.*:*/*",
			"*://169.254.*/*", "*://169.254.*:*/*",
			"ws://localhost/*", "ws://localhost:*/*",
			"ws://127.*/*", "ws://127.*:*/*",
			"ws://0.0.0.0/*", "ws://0.0.0.0:*/*",
			"ws://[::1]/*", "ws://[::1]:*/*",
			"ws://10.*/*", "ws://10.*:*/*",
			"ws://192.168.*/*", "ws://192.168.*:*/*",
			"ws://169.254.*/*", "ws://169.254.*:*/*",
			"wss://localhost/*", "wss://localhost:*/*",
			"wss://127.*/*", "wss://127.*:*/*",
			"wss://0.0.0.0/*", "wss://0.0.0.0:*/*",
			"wss://[::1]/*", "wss://[::1]:*/*",
			"wss://10.*/*", "wss://10.*:*/*",
			"wss://192.168.*/*", "wss://192.168.*:*/*",
			"wss://169.254.*/*", "wss://169.254.*:*/*",
		}
		for i := 16; i <= 31; i++ {
			prefix := fmt.Sprintf("172.%d.*", i)
			localPatterns = append(localPatterns,
				"*://"+prefix+"/*", "*://"+prefix+":*/*",
				"ws://"+prefix+"/*", "ws://"+prefix+":*/*",
				"wss://"+prefix+"/*", "wss://"+prefix+":*/*",
			)
		}
		blockedPatterns = append(blockedPatterns, localPatterns...)
	}

	_ = proto.NetworkEnable{}.Call(page)
	if len(blockedPatterns) > 0 {
		if err := (proto.NetworkSetBlockedURLs{Urls: blockedPatterns}).Call(page); err != nil {
			return err
		}
	}

	var wsMap sync.Map
	waitWs := page.EachEvent(
		func(e *proto.NetworkWebSocketCreated) {
			wsMap.Store(e.RequestID, e.URL)
			if !IsHostAllowed(options.ExecutionId, e.URL) {
				_ = (proto.NetworkSetBlockedURLs{Urls: append(blockedPatterns, e.URL, "*"+e.URL+"*")}).Call(page)
			}
		},
		func(e *proto.NetworkWebSocketWillSendHandshakeRequest) {
			if val, ok := wsMap.Load(e.RequestID); ok {
				if wsURL, ok := val.(string); ok && !IsHostAllowed(options.ExecutionId, wsURL) {
					_ = (proto.NetworkSetBlockedURLs{Urls: append(blockedPatterns, wsURL, "*"+wsURL+"*")}).Call(page)
				}
			}
		},
	)
	go waitWs()

	return nil
}
