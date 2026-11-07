package protocolstate

import (
	"context"
	"net"
	"strings"
)

type dialObserverKey struct{}

// WithDialObserver returns ctx carrying fn, which then receives the address and
// outcome of every connection attempt the shared dialer makes under ctx. Dials
// made under other contexts, by nuclei itself or by other protocols, are not
// reported to it.
func WithDialObserver(ctx context.Context, fn func(address string, err error)) context.Context {
	return context.WithValue(ctx, dialObserverKey{}, fn)
}

func reportDialResult(ctx context.Context, hostname, port string, err error) {
	if fn, ok := ctx.Value(dialObserverKey{}).(func(string, error)); ok {
		fn(net.JoinHostPort(strings.Trim(hostname, "[]"), port), err)
	}
}
