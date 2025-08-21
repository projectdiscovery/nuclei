package vnc

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	vnclib "github.com/alexsnet/go-vnc"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	vncplugin "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/vnc"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

type (
	// IsVNCResponse is the response from the IsVNC function.
	// @example
	// ```javascript
	// const vnc = require('nuclei/vnc');
	// const isVNC = vnc.IsVNC('acme.com', 5900);
	// log(toJSON(isVNC));
	// ```
	IsVNCResponse struct {
		IsVNC  bool
		Banner string
	}

	// VNCClient is a client for VNC servers.
	// @example
	// ```javascript
	// const vnc = require('nuclei/vnc');
	// const client = new vnc.VNCClient();
	// const connected = client.Connect('acme.com', 5900, 'password');
	// log(toJSON(connected));
	// ```
	VNCClient struct{}
)

// Connect connects to VNC server using given password.
// If connection and authentication is successful, it returns true.
// If connection or authentication is unsuccessful, it returns false and error.
// The connection is closed after the function returns.
// @example
// ```javascript
// const vnc = require('nuclei/vnc');
// const client = new vnc.VNCClient();
// const connected = client.Connect('acme.com', 5900, 'password');
// ```
func (c *VNCClient) Connect(ctx context.Context, host string, port int, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return connect(executionId, host, port, password)
}

// connect attempts to authenticate with a VNC server using the given password
func connect(executionId string, host string, port int, password string) (bool, error) {
	if host == "" || port <= 0 {
		return false, fmt.Errorf("invalid host or port")
	}
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied(host)
	}

	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return false, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, err
	}
	defer func() {
		_ = conn.Close()
	}()

	// Set connection timeout
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Create VNC client config with password
	vncConfig := vnclib.NewClientConfig(password)

	// Attempt to connect and authenticate
	_, err = vnclib.Connect(context.TODO(), conn, vncConfig)
	if err != nil {
		// Check for specific authentication errors
		if isAuthError(err) {
			return false, nil // Authentication failed, but connection succeeded
		}
		return false, err // Connection or other error
	}

	return true, nil
}

// isAuthError checks if the error is an authentication failure
func isAuthError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common VNC authentication error messages
	errStr := err.Error()
	return stringsutil.ContainsAny(errStr, "authentication", "auth", "password", "invalid", "failed")
}

// IsVNC checks if a host is running a VNC server.
// It returns a boolean indicating if the host is running a VNC server
// and the banner of the VNC server.
// @example
// ```javascript
// const vnc = require('nuclei/vnc');
// const isVNC = vnc.IsVNC('acme.com', 5900);
// log(toJSON(isVNC));
// ```
func IsVNC(ctx context.Context, host string, port int) (IsVNCResponse, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedisVNC(executionId, host, port)
}

// @memo
func isVNC(executionId string, host string, port int) (IsVNCResponse, error) {
	resp := IsVNCResponse{}

	timeout := 5 * time.Second
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return IsVNCResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}
	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer func() {
		_ = conn.Close()
	}()

	vncPlugin := vncplugin.VNCPlugin{}
	service, err := vncPlugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, err
	}
	if service == nil {
		return resp, nil
	}
	resp.Banner = service.Version
	resp.IsVNC = true
	return resp, nil
}
