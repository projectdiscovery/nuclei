package protocolstate

import (
	"sync"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/retryablehttp-go"
)

type Dialers struct {
	Fastdialer                 *fastdialer.Dialer
	RawHTTPClient              *RawHTTPClient
	DefaultHTTPClient          *retryablehttp.Client
	HTTPClientPool             *HTTPPool
	NetworkPolicy              *networkpolicy.NetworkPolicy
	LocalFileAccessAllowed     bool
	RestrictLocalNetworkAccess bool

	sync.Mutex
}
