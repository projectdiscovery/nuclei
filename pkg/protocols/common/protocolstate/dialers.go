package protocolstate

import (
	"sync"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

type Dialers struct {
	Fastdialer             *fastdialer.Dialer
	RawHTTPClient          *rawhttp.Client
	DefaultHTTPClient      *retryablehttp.Client
	HTTPClientPool         *mapsutil.SyncLockMap[string, *retryablehttp.Client]
	NetworkPolicy          *networkpolicy.NetworkPolicy
	LocalFileAccessAllowed bool
	sync.Mutex
}
