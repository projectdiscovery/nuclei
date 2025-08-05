package rsync

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/rsync"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// IsRsyncResponse is the response from the IsRsync function.
	// this is returned by IsRsync function.
	// @example
	// ```javascript
	// const rsync = require('nuclei/rsync');
	// const isRsync = rsync.IsRsync('acme.com', 873);
	// log(toJSON(isRsync));
	// ```
	IsRsyncResponse struct {
		IsRsync bool
		Banner  string
	}
)

// IsRsync checks if a host is running a Rsync server.
// @example
// ```javascript
// const rsync = require('nuclei/rsync');
// const isRsync = rsync.IsRsync('acme.com', 873);
// log(toJSON(isRsync));
// ```
func IsRsync(ctx context.Context, host string, port int) (IsRsyncResponse, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedisRsync(executionId, host, port)
}

// @memo
func isRsync(executionId string, host string, port int) (IsRsyncResponse, error) {
	resp := IsRsyncResponse{}

	timeout := 5 * time.Second
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return IsRsyncResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}
	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer func() {
		_ = conn.Close()
	}()

	rsyncPlugin := rsync.RSYNCPlugin{}
	service, err := rsyncPlugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, err
	}
	if service == nil {
		return resp, nil
	}
	resp.Banner = service.Version
	resp.IsRsync = true
	return resp, nil
}
