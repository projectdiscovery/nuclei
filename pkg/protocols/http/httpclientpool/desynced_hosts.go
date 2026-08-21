package httpclientpool

import (
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Some servers answer a request and then send a second, unsolicited response on the
// same keep-alive connection. net/http returns that connection to the idle pool
// before its read loop notices, so a later request can read the leftover response as
// its own. Nothing reports it: the response is well-formed, so the retry policy --
// which only fires on transport errors -- accepts it, the template matches against
// the wrong response, and every response after that on the connection is off by one.
//
// A connection cannot be proven clean at the moment it is handed out; by then the
// extra response may be on the wire, or already buffered inside net/http where no
// caller can see it. Reuse itself is the problem, so a caller that detects the
// condition marks the host here and this pool stops reusing connections to it.
//
// The mark expires so a host that stops misbehaving gets its connection reuse back.
// An expiry mid-scan is cheap: detection is per-request, so the next wrong response
// is caught and retried rather than lost, and re-marks the host.
const desyncedHostTTL = 15 * time.Minute

// host:port -> time.Time the mark was set.
var desyncedHosts sync.Map

// MarkHostDesynced disables connection reuse for a target until the mark expires.
// The target may be a bare host, host:port, or a full URL; callers do not have to
// match the exact string the pool was keyed with.
func MarkHostDesynced(target string) {
	key := desyncedHostKey(target)
	if key == "" {
		return
	}

	desyncedHosts.Store(key, time.Now())
}

// IsHostDesynced reports whether connection reuse for a target is disabled.
func IsHostDesynced(target string) bool {
	key := desyncedHostKey(target)
	if key == "" {
		return false
	}

	value, ok := desyncedHosts.Load(key)
	if !ok {
		return false
	}

	markedAt, ok := value.(time.Time)
	if !ok || time.Since(markedAt) > desyncedHostTTL {
		desyncedHosts.Delete(key)

		return false
	}

	return true
}

// DesyncedHosts returns the hosts connection reuse is currently disabled for, as
// host:port and sorted, for callers reporting which targets misbehaved.
func DesyncedHosts() []string {
	var hosts []string

	desyncedHosts.Range(func(key, value any) bool {
		host, ok := key.(string)
		if !ok {
			return true
		}

		markedAt, ok := value.(time.Time)
		if ok && time.Since(markedAt) <= desyncedHostTTL {
			hosts = append(hosts, host)
		}

		return true
	})

	slices.Sort(hosts)

	return hosts
}

// desyncedHostKey reduces a target to host:port so that a mark set from a URL still
// matches a lookup made with a bare host, and vice versa. Reuse happens per
// listener, so the port is part of the key.
func desyncedHostKey(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		return parsed.Host
	}

	return strings.TrimSuffix(target, "/")
}
