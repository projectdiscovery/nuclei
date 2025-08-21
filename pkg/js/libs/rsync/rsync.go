package rsync

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	rsynclib "github.com/Mzack9999/go-rsync/rsync"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/rsync"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// RsyncClient is a client for RSYNC servers.
	// Internally client uses https://github.com/gokrazy/rsync driver.
	// @example
	// ```javascript
	// const rsync = require('nuclei/rsync');
	// const client = new rsync.RsyncClient();
	// ```
	RsyncClient struct{}

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

	// ListSharesResponse is the response from the ListShares function.
	// this is returned by ListShares function.
	// @example
	// ```javascript
	// const rsync = require('nuclei/rsync');
	// const client = new rsync.RsyncClient();
	// const listShares = client.ListShares('acme.com', 873);
	// log(toJSON(listShares));
	RsyncListResponse struct {
		Modules []string
		Files   []string
		Output  string
	}
)

func connectWithFastDialer(executionId string, host string, port int) (net.Conn, error) {
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", executionId)
	}
	return dialer.Fastdialer.Dial(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

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
	conn, err := connectWithFastDialer(executionId, host, port)
	if err != nil {
		return resp, err
	}
	defer func() {
		_ = conn.Close()
	}()

	rsyncPlugin := rsync.RSYNCPlugin{}
	service, err := rsyncPlugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, nil
	}
	if service == nil {
		return resp, nil
	}
	resp.Banner = service.Version
	resp.IsRsync = true
	return resp, nil
}

// ListModules lists the modules of a Rsync server.
// @example
// ```javascript
// const rsync = require('nuclei/rsync');
// const client = new rsync.RsyncClient();
// const listModules = client.ListModules('acme.com', 873, 'username', 'password');
// log(toJSON(listModules));
// ```
func (c *RsyncClient) ListModules(ctx context.Context, host string, port int, username string, password string) (RsyncListResponse, error) {
	executionId := ctx.Value("executionId").(string)
	return listModules(executionId, host, port, username, password)
}

// ListShares lists the shares of a Rsync server.
// @example
// ```javascript
// const rsync = require('nuclei/rsync');
// const client = new rsync.RsyncClient();
// const listShares = client.ListFilesInModule('acme.com', 873, 'username', 'password', '/');
// log(toJSON(listShares));
// ```
func (c *RsyncClient) ListFilesInModule(ctx context.Context, host string, port int, username string, password string, module string) (RsyncListResponse, error) {
	executionId := ctx.Value("executionId").(string)
	return listFilesInModule(executionId, host, port, username, password, module)
}

func listModules(executionId string, host string, port int, username string, password string) (RsyncListResponse, error) {
	fastDialer := protocolstate.GetDialersWithId(executionId)
	if fastDialer == nil {
		return RsyncListResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))

	// Create a bytes buffer for logging
	var logBuffer bytes.Buffer

	// Create a custom slog handler that writes to the buffer
	logHandler := slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	// Create a logger that writes to our buffer
	logger := slog.New(logHandler)

	sr, err := rsynclib.ListModules(address,
		rsynclib.WithClientAuth(username, password),
		rsynclib.WithLogger(logger),
		rsynclib.WithFastDialer(fastDialer.Fastdialer),
	)
	if err != nil {
		return RsyncListResponse{}, fmt.Errorf("connect failed: %v", err)
	}

	result := RsyncListResponse{
		Modules: make([]string, len(sr)),
		Output:  logBuffer.String(),
	}

	for i, item := range sr {
		result.Modules[i] = string(item.Name)
	}

	return result, nil
}

func listFilesInModule(executionId string, host string, port int, username string, password string, module string) (RsyncListResponse, error) {
	fastDialer := protocolstate.GetDialersWithId(executionId)
	if fastDialer == nil {
		return RsyncListResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))

	// Create a bytes buffer for logging
	var logBuffer bytes.Buffer

	// Create a custom slog handler that writes to the buffer
	logHandler := slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	// Create a logger that writes to our buffer
	logger := slog.New(logHandler)

	sr, err := rsynclib.SocketClient(nil, address, module, ".",
		rsynclib.WithClientAuth(username, password),
		rsynclib.WithLogger(logger),
		rsynclib.WithFastDialer(fastDialer.Fastdialer),
	)
	if err != nil {
		return RsyncListResponse{}, fmt.Errorf("connect failed: %v", err)
	}

	// Try to list files to test authentication
	list, err := sr.List()
	if err != nil {
		return RsyncListResponse{}, fmt.Errorf("authentication failed: %v", err)
	}

	result := RsyncListResponse{
		Files:  make([]string, len(list)),
		Output: logBuffer.String(),
	}

	for i, item := range list {
		result.Files[i] = string(item.Path)
	}

	return result, nil
}
