package telnet

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/telnet"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	telnetmini "github.com/projectdiscovery/nuclei/v3/pkg/utils/telnet"
)

// Telnet protocol constants
const (
	IAC               = 255 // Interpret As Command
	WILL              = 251 // Will
	WONT              = 252 // Won't
	DO                = 253 // Do
	DONT              = 254 // Don't
	SB                = 250 // Subnegotiation Begin
	SE                = 240 // Subnegotiation End
	ECHO              = 1   // Echo
	SUPPRESS_GO_AHEAD = 3   // Suppress Go Ahead
	TERMINAL_TYPE     = 24  // Terminal Type
	NAWS              = 31  // Negotiate About Window Size
	ENCRYPT           = 38  // Encryption option (0x26)
)

type (
	// IsTelnetResponse is the response from the IsTelnet function.
	// this is returned by IsTelnet function.
	// @example
	// ```javascript
	// const telnet = require('nuclei/telnet');
	// const isTelnet = telnet.IsTelnet('acme.com', 23);
	// log(toJSON(isTelnet));
	// ```
	IsTelnetResponse struct {
		IsTelnet bool
		Banner   string
	}

	// TelnetInfoResponse is the response from the Info function.
	// @example
	// ```javascript
	// const telnet = require('nuclei/telnet');
	// const client = new telnet.TelnetClient();
	// const info = client.Info('acme.com', 23);
	// log(toJSON(info));
	// ```
	TelnetInfoResponse struct {
		SupportsEncryption bool
		Banner             string
		Options            map[int][]int
	}

	// TelnetClient is a client for Telnet servers.
	// @example
	// ```javascript
	// const telnet = require('nuclei/telnet');
	// const client = new telnet.TelnetClient();
	// ```
	TelnetClient struct{}
)

// IsTelnet checks if a host is running a Telnet server.
// @example
// ```javascript
// const telnet = require('nuclei/telnet');
// const isTelnet = telnet.IsTelnet('acme.com', 23);
// log(toJSON(isTelnet));
// ```
func IsTelnet(ctx context.Context, host string, port int) (IsTelnetResponse, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedisTelnet(executionId, host, port)
}

// @memo
func isTelnet(executionId string, host string, port int) (IsTelnetResponse, error) {
	resp := IsTelnetResponse{}

	timeout := 5 * time.Second
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return IsTelnetResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer func() {
		_ = conn.Close()
	}()

	telnetPlugin := telnet.TELNETPlugin{}
	service, err := telnetPlugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, err
	}
	if service == nil {
		return resp, nil
	}
	resp.Banner = service.Metadata().(plugins.ServiceTelnet).ServerData
	resp.IsTelnet = true
	return resp, nil
}

// Connect tries to connect to provided host and port with telnet.
// Optionally provides username and password for authentication.
// Returns state of connection. If the connection is successful,
// the function will return true, otherwise false.
// @example
// ```javascript
// const telnet = require('nuclei/telnet');
// const client = new telnet.TelnetClient();
// const connected = client.Connect('acme.com', 23, 'username', 'password');
// ```
func (c *TelnetClient) Connect(ctx context.Context, host string, port int, username string, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)

	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return false, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	if !protocolstate.IsHostAllowed(executionId, host) {
		return false, protocolstate.ErrHostDenied(host)
	}

	// Create TCP connection
	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, err
	}

	// Create telnet client using the telnetmini library
	client := telnetmini.New(conn)
	defer func() {
		_ = client.Close()
	}()

	// Handle authentication if credentials provided
	if username != "" && password != "" {
		// Set a timeout context for authentication
		authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if err := client.Auth(authCtx, username, password); err != nil {
			return false, err
		}
	}

	return true, nil
}

// Info gathers information about the telnet server including encryption support.
// Uses the telnetmini library's DetectEncryption helper function.
// WARNING: The connection used for detection becomes unusable after this call.
// @example
// ```javascript
// const telnet = require('nuclei/telnet');
// const client = new telnet.TelnetClient();
// const info = client.Info('acme.com', 23);
// log(toJSON(info));
// ```
func (c *TelnetClient) Info(ctx context.Context, host string, port int) (TelnetInfoResponse, error) {
	executionId := ctx.Value("executionId").(string)

	if !protocolstate.IsHostAllowed(executionId, host) {
		return TelnetInfoResponse{}, protocolstate.ErrHostDenied(host)
	}

	// Create TCP connection for encryption detection
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return TelnetInfoResponse{}, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	conn, err := dialer.Fastdialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return TelnetInfoResponse{}, err
	}
	defer conn.Close()

	// Use the telnetmini library's DetectEncryption helper function
	// Note: The connection becomes unusable after this call
	encryptionInfo, err := telnetmini.DetectEncryption(conn, 7*time.Second)
	if err != nil {
		return TelnetInfoResponse{}, err
	}

	return TelnetInfoResponse{
		SupportsEncryption: encryptionInfo.SupportsEncryption,
		Banner:             encryptionInfo.Banner,
		Options:            encryptionInfo.Options,
	}, nil
}
