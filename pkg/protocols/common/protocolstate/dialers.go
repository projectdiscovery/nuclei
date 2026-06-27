package protocolstate

import (
	"sync"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
)

type Dialers struct {
	Fastdialer                 *fastdialer.Dialer
	RawHTTPClient              *rawhttp.Client
	DefaultHTTPClient          *retryablehttp.Client
	HTTPClientPool             *HTTPPool
	PerHostRateLimitPool       any // *httpclientpool.PerHostRateLimitPool
	HTTPToHTTPSPortTracker     any // *httpclientpool.HTTPToHTTPSPortTracker
	NetworkPolicy              *networkpolicy.NetworkPolicy
	LocalFileAccessAllowed     bool
	RestrictLocalNetworkAccess bool
	ExcludeTargets             []string

	sync.Mutex
}
