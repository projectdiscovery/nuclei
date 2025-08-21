package rsync

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	rsyncclient "github.com/gokrazy/rsync/rsyncclient"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/rsync"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
)

type (
	// RsyncClient is a client for RSYNC servers.
	// Internally client uses https://github.com/gokrazy/rsync driver.
	// @example
	// ```javascript
	// const rsync = require('nuclei/rsync');
	// const client = new rsync.RsyncClient();
	// ```
	RsyncClient struct {
		connection   net.Conn
		host         string
		port         int
		timeout      time.Duration
		username     string
		password     string
		client       *rsyncclient.Client
		passwordFile string
	}

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

func connect(executionId string, host string, port int) (net.Conn, error) {
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
	conn, err := connect(executionId, host, port)
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

// Connect establishes a connection to the rsync server.
// @example
// ```javascript
// const rsync = require('nuclei/rsync');
// const client = new rsync.RsyncClient();
// const connected = client.Connect('acme.com', 873, 'username', 'password');
// ```
func (c *RsyncClient) Connect(ctx context.Context, host string, port int, username, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	conn, err := connect(executionId, host, port)
	if err != nil {
		return false, err
	}

	// Create minimal rsync client with auth
	args := []string{"--list-only"}
	if username != "" {
		args = append(args, "--user", username)
	}
	if password != "" {
		// Create a temporary password file
		tempFileName, err := fileutil.GetTempFileName()
		if err != nil {
			_ = conn.Close()
			return false, fmt.Errorf("failed to get temporary filename: %v", err)
		}

		// Write password to the file
		err = os.WriteFile(tempFileName, []byte(password), 0600)
		if err != nil {
			_ = os.Remove(tempFileName)
			_ = conn.Close()
			return false, fmt.Errorf("failed to write password to file: %v", err)
		}

		// Use the actual filename instead of stdin
		args = append(args, "--password-file", tempFileName)
		c.passwordFile = tempFileName
	}

	client, err := rsyncclient.New(args)
	if err != nil {
		_ = conn.Close()
		return false, fmt.Errorf("failed to create rsync client: %v", err)
	}

	// Test authentication with minimal command
	_, err = client.Run(ctx, conn, []string{"/"})
	if err != nil {
		_ = conn.Close()
		if c.passwordFile != "" {
			_ = os.Remove(c.passwordFile)
		}
		return false, fmt.Errorf("authentication failed: %v", err)
	}

	c.connection = conn
	c.host = host
	c.port = port
	c.timeout = 30 * time.Second
	c.username = username
	c.password = password
	c.client = client

	return true, nil
}

// Close closes the rsync connection and cleans up temporary files.
// @example
// ```javascript
// const rsync = require('nuclei/rsync');
// const client = new rsync.RsyncClient();
// client.Connect('acme.com', 873, 'username', 'password');
// // ... use client ...
// client.Close();
// ```
func (c *RsyncClient) Close() error {
	var errs []error

	// Close the connection
	if c.connection != nil {
		if err := c.connection.Close(); err != nil {
			errs = append(errs, err)
		}
		c.connection = nil
	}

	// Clean up temporary password file
	if c.passwordFile != "" {
		if err := os.Remove(c.passwordFile); err != nil {
			errs = append(errs, err)
		}
		c.passwordFile = ""
	}

	// Reset other fields
	c.host = ""
	c.port = 0
	c.timeout = 0
	c.username = ""
	c.password = ""
	c.client = nil

	// Return joined errors if any occurred
	if len(errs) > 0 {
		return errkit.Join(errs...)
	}
	return nil
}
