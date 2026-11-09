// Package external is a tsgen fixture that references types from other
// packages, both structs and non-structs.
package external

import (
	"context"
	"net"
	"net/url"
)

// Dial returns an external interface type.
func Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

// Parse returns an external struct type.
func Parse(raw string) (*url.URL, error) {
	return url.Parse(raw)
}

// Session holds an external interface type in an exported field.
type Session struct {
	Conn net.Conn
}

type dialer struct{}

// DialContext is exported, but its receiver is not.
func (dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}
