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
}

func (o *oracleCustomDialer) Dial(network, address string) (net.Conn, error) {
	dialers := protocolstate.GetDialersWithId(o.executionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", o.executionId)
	}
	return dialers.Fastdialer.Dial(context.TODO(), network, address)
}

func (o *oracleCustomDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	dialers := protocolstate.GetDialersWithId(o.executionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", o.executionId)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return dialers.Fastdialer.Dial(ctx, network, address)
}

func (o *oracleCustomDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialers := protocolstate.GetDialersWithId(o.executionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", o.executionId)
	}
	return dialers.Fastdialer.Dial(ctx, network, address)
}
