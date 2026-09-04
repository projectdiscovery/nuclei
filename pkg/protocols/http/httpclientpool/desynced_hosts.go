package httpclientpool

import (
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Some servers answer a request and then send another, unsolicited response on
// the same keep-alive connection. net/http already discards that connection when
// the leftover lands while the connection is idle, but it only logs the event.
// Under back-to-back load a leftover can still be attributed to the next request,
// corrupting a small number of responses before the stream resynchronizes.
//
// Once a leftover is observed on an idle connection, reuse for that host is
// disabled for a while so the same listener cannot keep costing wrong results.
const desyncedHostTTL = 15 * time.Minute

var desyncedResponses atomic.Int64

// DesyncedResponses reports how many idle connections were closed after receiving
// unsolicited bytes since the process started.
func DesyncedResponses() int64 {
	return desyncedResponses.Load()
}

func countDesyncedResponse() {
	desyncedResponses.Add(1)
}

func desyncHostsFor(options *types.Options) *protocolstate.ExpiringSet {
	if options == nil {
		return nil
	}
	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil
	}
	return dialers.HTTPDesyncHosts
}

// MarkHostDesynced disables connection reuse for a target until the mark expires.
func MarkHostDesynced(options *types.Options, target string) {
	hosts := desyncHostsFor(options)
	if hosts == nil {
		return
	}
	key := desyncedHostKey(target)
	if key == "" {
		return
	}
	hosts.Store(key, desyncedHostTTL)
}

// IsHostDesynced reports whether connection reuse for a target is disabled.
func IsHostDesynced(options *types.Options, target string) bool {
	hosts := desyncHostsFor(options)
	key := desyncedHostKey(target)
	return hosts != nil && key != "" && hosts.Contains(key)
}

// DesyncedHosts returns the hosts connection reuse is currently disabled for.
func DesyncedHosts(options *types.Options) []string {
	hosts := desyncHostsFor(options)
	if hosts == nil {
		return nil
	}
	return hosts.Keys()
}

func desyncedHostKey(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		return strings.ToLower(parsed.Host)
	}

	return strings.ToLower(strings.TrimSuffix(target, "/"))
}
