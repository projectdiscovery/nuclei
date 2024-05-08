// ports implements a open-port cache to avoid sending redundant requests to same port
package ports

import (
	"context"
	"errors"

	"github.com/Mzack9999/gcache"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	singleflight "github.com/projectdiscovery/utils/memoize/simpleflight"
)

var (
	portsCacher   *PortsCache
	ErrPortClosed = errors.New("port closed or filtered")
)

type PortStatus uint8

const (
	Unknown PortStatus = iota
	Open
	Closed
)

// PortsCache is a cache for open ports
type PortsCache struct {
	cache  gcache.Cache[string, PortStatus]
	group  singleflight.Group[string]
	dialer *fastdialer.Dialer
}

// NewPortsCache creates a new cache for open ports
func NewPortsCache(dialer *fastdialer.Dialer, size int) *PortsCache {
	p := &PortsCache{group: singleflight.Group[string]{}, dialer: dialer}
	cache := gcache.New[string, PortStatus](size).
		LRU().
		EvictedFunc(func(key string, value PortStatus) {
			p.group.Forget(key)
		}).
		Build()
	p.cache = cache
	return p
}

// Do performs a check for open ports and caches the result
func (p *PortsCache) Do(ctx context.Context, address string) error {
	// check if it exists in cache
	if value, err := p.cache.GetIFPresent(address); !errors.Is(err, gcache.KeyNotFoundError) {
		switch value {
		case Closed:
			return ErrPortClosed
		default:
			return nil
		}
	}

	// if not in cache then check if it is open
	code, _, _ := p.group.Do(address, func() (interface{}, error) {
		conn, err := p.dialer.Dial(ctx, "tcp", address)
		if err != nil {
			_ = p.cache.Set(address, Closed)
			return Closed, nil
		}
		_ = conn.Close()
		_ = p.cache.Set(address, Open)
		return Open, nil
	})

	if status, ok := code.(PortStatus); ok {
		if status == Closed {
			return ErrPortClosed
		}
	}
	return nil
}

// Do performs a check for open ports
func (p *PortsCache) DoInput(ctx context.Context, input *contextargs.Context) error {
	address := input.MetaInput.Address()
	if address == "" {
		// assume port is open is given info is not present/enough
		return nil
	}
	return p.Do(ctx, address)
}

// Close closes the ports cache and releases any allocated resources
func (p *PortsCache) Close() {
	p.cache = nil
	p.group = singleflight.Group[string]{}
}

// Init initializes the ports package
func Init(dialer *fastdialer.Dialer, size int) {
	portsCacher = NewPortsCache(dialer, size)
}

// Close closes the ports package
func Close() {
	if portsCacher != nil {
		portsCacher.Close()
	}
}

// InputPortStatus checks for cached status of input port
func InputPortStatus(input *contextargs.Context) error {
	if portsCacher == nil {
		return nil
	}
	return portsCacher.DoInput(input.Context(), input)
}

// CheckPortStatus checks for cached status of remote port
func CheckPortStatus(ctx context.Context, address string) error {
	if portsCacher == nil {
		return nil
	}
	return portsCacher.Do(ctx, address)
}
