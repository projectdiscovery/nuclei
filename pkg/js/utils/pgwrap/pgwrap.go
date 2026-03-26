package pgwrap

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/lib/pq"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

const (
	PGWrapDriver = "pgwrap"
)

type pgDial struct {
	executionId string
	ctx         context.Context
}

func (p *pgDial) Dial(network, address string) (net.Conn, error) {
	dialers := protocolstate.GetDialersWithId(p.executionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", p.executionId)
	}
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return dialers.Fastdialer.Dial(ctx, network, address)
}

func (p *pgDial) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	dialers := protocolstate.GetDialersWithId(p.executionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", p.executionId)
	}
	baseCtx := p.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeoutCause(baseCtx, timeout, fastdialer.ErrDialTimeout)
	defer cancel()
	return dialers.Fastdialer.Dial(ctx, network, address)
}

func (p *pgDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		ctx = p.ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialers := protocolstate.GetDialersWithId(p.executionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", p.executionId)
	}
	return dialers.Fastdialer.Dial(ctx, network, address)
}

func OpenDB(ctx context.Context, executionId string, dsn string) (*sql.DB, error) {
	connector, err := pq.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	connector.Dialer(&pgDial{executionId: executionId, ctx: ctx})
	return sql.OpenDB(connector), nil
}

// Unfortunately lib/pq does not provide easy to customize or
// replace dialer so we need to hijack it by wrapping it in our own
// driver and register it as postgres driver

// PgDriver is the Postgres database driver.
type PgDriver struct{}

// Open opens a new connection to the database. name is a connection string.
// Most users should only use it through database/sql package from the standard
// library.
func (d PgDriver) Open(name string) (driver.Conn, error) {
	// Parse the connection string to get executionId
	u, err := url.Parse(name)
	if err != nil {
		return nil, fmt.Errorf("invalid connection string: %v", err)
	}
	values := u.Query()
	executionId := values.Get("executionId")
	// Remove executionId from the connection string
	values.Del("executionId")
	u.RawQuery = values.Encode()

	return pq.DialOpen(&pgDial{executionId: executionId}, u.String())
}

func init() {
	sql.Register(PGWrapDriver, &PgDriver{})
}
