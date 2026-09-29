package oracle

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// oracleCustomDialer implements the dialer interface expected by go-ora
type oracleCustomDialer struct {
	executionId string
	ctx         context.Context
}

func (o *oracleCustomDialer) dialWithCtx(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		ctx = o.ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialers := protocolstate.GetDialersWithId(o.executionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", o.executionId)
	}
	if !protocolstate.IsHostAllowed(o.executionId, address) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(address)
	}
	return dialers.Fastdialer.Dial(ctx, network, address)
}

func (o *oracleCustomDialer) Dial(network, address string) (net.Conn, error) {
	return o.dialWithCtx(o.ctx, network, address)
}

func (o *oracleCustomDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	baseCtx := o.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, timeout)
	defer cancel()

	return o.dialWithCtx(ctx, network, address)
}

func (o *oracleCustomDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return o.dialWithCtx(ctx, network, address)
}
