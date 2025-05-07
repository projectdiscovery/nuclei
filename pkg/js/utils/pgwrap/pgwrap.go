package pgwrap

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

const (
	PGWrapDriver = "pgwrap"
)

// nolint
type pgDial struct {
	fd *fastdialer.Dialer
}

// nolint
func (p *pgDial) Dial(network, address string) (net.Conn, error) {
	return p.fd.Dial(context.TODO(), network, address)
}

// nolint
func (p *pgDial) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeoutCause(context.Background(), timeout, fastdialer.ErrDialTimeout)
	defer cancel()
	return p.fd.Dial(ctx, network, address)
}

// nolint
func (p *pgDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return p.fd.Dial(ctx, network, address)
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
	panic("todo")
	// nolint
	return nil, nil
	//return pq.DialOpen(&pgDial{fd: dialer.Fastdialer}, name)
}

func init() {
	sql.Register(PGWrapDriver, &PgDriver{})
}
