package protocolstate

import (
	"sync"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
)

type Dialers struct {
	Fastdialer *fastdialer.Dialer
	// HTTPProxyTunnelFastdialer reaches targets through the http -proxy with
	// CONNECT. It is nil unless an http proxy is in use.
	HTTPProxyTunnelFastdialer  *fastdialer.Dialer
	RawHTTPClient              *rawhttp.Client
	DefaultHTTPClient          *retryablehttp.Client
	HTTPClientPool             *HTTPPool
	PerHostRateLimitPool       any // *hostratelimit.PerHostRateLimitPool
	HTTPToHTTPSPortTracker     any // *httpclientpool.HTTPToHTTPSPortTracker
	SharedResponses            any // *httpclientpool.sharedResponses
	HTTPDesyncHosts            *ExpiringSet
	NetworkPolicy              *networkpolicy.NetworkPolicy
	LocalFileAccessAllowed     bool
	RestrictLocalNetworkAccess bool
	ExcludeTargets             []string

	sync.Mutex
}
