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

// CanonicalizeHost normalizes a hostname or IP string:
// - strips surrounding whitespace and brackets (e.g. "[::1]" -> "::1")
// - maps IPv4-mapped IPv6 literals (e.g. "::ffff:127.0.0.1" or "0:0:0:0:0:ffff:127.0.0.1") to canonical IPv4 ("127.0.0.1")
func CanonicalizeHost(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	if ip := net.ParseIP(h); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
		return ip.String()
	}
	return h
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

	rawTarget := strings.TrimSpace(targetUrl)
	var host string

	if urlx, err := urlutil.Parse(rawTarget); err == nil && urlx.Hostname() != "" {
		host = urlx.Hostname()
	} else if h, _, err := net.SplitHostPort(rawTarget); err == nil {
		host = h
	} else {
		host = rawTarget
		for _, prefix := range []string{"ws://", "wss://", "http://", "https://"} {
			if strings.HasPrefix(strings.ToLower(host), prefix) {
				host = host[len(prefix):]
				if idx := strings.Index(host, "/"); idx != -1 {
					host = host[:idx]
				}
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				break
			}
		}
	}

	canonHost := CanonicalizeHost(host)

	// Check explicit ExcludeTargets against raw, host, and canonical host
	for _, excluded := range dialers.ExcludeTargets {
		ex := CanonicalizeHost(strings.TrimSpace(excluded))
		if ex != "" {
			if strings.EqualFold(canonHost, ex) || strings.EqualFold(host, ex) || strings.EqualFold(rawTarget, ex) {
				return false
			}
		}
	}

	// Validate host against NetworkPolicy using both canonical and original host
	if _, ok := np.ValidateHost(canonHost); !ok {
		return false
	}
	if canonHost != host {
		if _, ok := np.ValidateHost(host); !ok {
			return false
		}
	}
	return true
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
		if strings.Contains(target, "://") {
			parsed, err := urlutil.Parse(target)
			if err != nil || parsed.Hostname() == "" {
				continue
			}
			target = parsed.Hostname()
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

	if err := (proto.NetworkEnable{}).Call(page); err != nil {
		return err
	}
	if len(blockedPatterns) > 0 {
		if err := (proto.NetworkSetBlockedURLs{Urls: blockedPatterns}).Call(page); err != nil {
			return err
		}
	}

	var (
		mu              sync.Mutex
		patternSet      = make(map[string]struct{})
		dynamicPatterns = append([]string(nil), blockedPatterns...)
		wsMap           sync.Map
	)
	for _, p := range blockedPatterns {
		patternSet[p] = struct{}{}
	}

	addBlockedURL := func(urlStr string) {
		mu.Lock()
		defer mu.Unlock()

		newPatterns := []string{urlStr}
		if parsed, err := urlutil.Parse(urlStr); err == nil && parsed.Hostname() != "" {
			host := parsed.Hostname()
			if strings.Count(host, ":") > 1 && !strings.HasPrefix(host, "[") {
				host = "[" + host + "]"
			}
			newPatterns = append(newPatterns,
				"*://"+host+"/*",
				"*://"+host+":*/*",
				"ws://"+host+"/*",
				"ws://"+host+":*/*",
				"wss://"+host+"/*",
				"wss://"+host+":*/*",
			)
		}

		var pending []string
		for _, p := range newPatterns {
			if _, exists := patternSet[p]; !exists {
				pending = append(pending, p)
			}
		}

		if len(pending) > 0 {
			candidateList := append(dynamicPatterns, pending...)
			if err := (proto.NetworkSetBlockedURLs{Urls: candidateList}).Call(page); err == nil {
				for _, p := range pending {
					patternSet[p] = struct{}{}
				}
				dynamicPatterns = candidateList
			}
		}
	}

	waitWs := page.EachEvent(
		func(e *proto.NetworkWebSocketCreated) {
			wsMap.Store(e.RequestID, e.URL)
			if !IsHostAllowed(options.ExecutionId, e.URL) {
				addBlockedURL(e.URL)
			}
		},
		func(e *proto.NetworkWebSocketWillSendHandshakeRequest) {
			if val, ok := wsMap.Load(e.RequestID); ok {
				wsMap.Delete(e.RequestID)
				if wsURL, ok := val.(string); ok && !IsHostAllowed(options.ExecutionId, wsURL) {
					addBlockedURL(wsURL)
				}
			}
		},
		func(e *proto.NetworkWebSocketClosed) {
			wsMap.Delete(e.RequestID)
		},
	)
	go waitWs()

	return nil
}
