package websocket

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/projectdiscovery/goja"

	jsnet "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/net"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

const (
	defaultTimeout = 5 * time.Second
	// maxMessageSize caps a received message, matching the net module's read limit.
	maxMessageSize = 8 * 1024 * 1024
)

type (
	// Options configures a WebSocket Client. All fields are optional.
	// @example
	// ```javascript
	// const websocket = require('nuclei/websocket');
	// const opts = new websocket.Options();
	// opts.Headers = {'Origin': 'https://acme.com'};
	// opts.Protocols = ['chat'];
	// const client = new websocket.Client('wss://acme.com/socket', opts);
	// ```
	Options struct {
		// Headers are extra HTTP headers sent with the opening handshake.
		Headers map[string]string
		// Protocols are the subprotocols offered in the handshake, in preference order.
		Protocols []string
		// TimeoutSeconds bounds the handshake and each send or receive.
		// 0 uses the scan's TCP read timeout.
		TimeoutSeconds int
		// ServerName overrides the TLS server name for wss:// URLs.
		ServerName string
	}
)

type (
	// Client is a WebSocket client for nuclei JS templates.
	// @example
	// ```javascript
	// const websocket = require('nuclei/websocket');
	// const client = new websocket.Client('ws://acme.com/socket');
	// client.Send('hello');
	// const reply = client.Receive();
	// client.Close();
	// ```
	Client struct {
		// URL is the ws:// or wss:// endpoint.
		URL string
		// Protocol is the subprotocol the server accepted, set after connecting.
		Protocol string
		// ResponseHeaders are the handshake response headers, set after connecting.
		ResponseHeaders map[string]string

		nj          *utils.NucleiJS
		executionID string
		opts        Options
		timeout     time.Duration
		conn        net.Conn
		reader      io.Reader
	}
)

// NewClient creates a new WebSocket client for the given ws:// or wss:// URL.
//
// Constructor: constructor(public url: string, public options?: Options)
func NewClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	c := &Client{nj: utils.NewNucleiJS(runtime)}
	c.nj.ObjectSig = "Client(url, {Options})"

	rawURL, _ := c.nj.GetArg(call.Arguments, 0).(string)
	c.nj.Require(rawURL != "", "websocket url cannot be empty")
	if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		if err := runtime.ExportTo(call.Arguments[1], &c.opts); err != nil {
			c.nj.HandleError(err, "invalid websocket options")
		}
	}

	parsed, err := url.Parse(rawURL)
	c.nj.HandleError(err, "invalid websocket url")
	c.nj.Require(parsed.Scheme == "ws" || parsed.Scheme == "wss", "websocket url must use ws:// or wss://")
	c.nj.Require(parsed.Hostname() != "", "websocket url host cannot be empty")

	c.URL = rawURL
	c.executionID = c.nj.ExecutionId()
	c.timeout = timeoutFor(c.nj.Context(), c.opts.TimeoutSeconds)

	// defense in depth: the dialer re-checks the network policy on every dial
	c.nj.Require(protocolstate.IsHostAllowed(c.executionID, parsed.Hostname()), protocolstate.ErrHostDenied.Msgf(parsed.Hostname()).Error())

	return utils.LinkConstructor(call, runtime, c)
}

// Connect performs the opening handshake. It is optional; Send and Receive
// connect on demand.
// @example
// ```javascript
// const websocket = require('nuclei/websocket');
// const client = new websocket.Client('ws://acme.com/socket');
// client.Connect();
// log(client.Protocol);
// ```
func (c *Client) Connect() {
	c.nj.Require(c.executionID != "", "websocket: missing executionId in runtime")
	if c.conn != nil {
		return
	}

	header := http.Header{}
	for key, value := range c.opts.Headers {
		header.Set(key, value)
	}
	responseHeaders := map[string]string{}
	dialer := ws.Dialer{
		Header:    ws.HandshakeHeaderHTTP(header),
		Protocols: c.opts.Protocols,
		Timeout:   c.timeout,
		TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, ServerName: c.opts.ServerName},
		// route through the net module so network policy and proxies apply
		NetDial: jsnet.Dial,
		OnHeader: func(key, value []byte) error {
			responseHeaders[string(key)] = string(value)
			return nil
		},
	}

	ctx := context.WithValue(c.nj.Context(), "executionId", c.executionID) //nolint:staticcheck
	conn, buffered, handshake, err := dialer.Dial(ctx, c.URL)
	c.nj.HandleError(err, "websocket handshake failed")

	c.conn = conn
	c.reader = conn
	if buffered != nil {
		// frames the server sent right after the handshake are already buffered
		c.reader = io.MultiReader(buffered, conn)
	}
	c.Protocol = handshake.Protocol
	c.ResponseHeaders = responseHeaders
}

// Send sends a text message.
// @example
// ```javascript
// const websocket = require('nuclei/websocket');
// const client = new websocket.Client('ws://acme.com/socket');
// client.Send('hello');
// ```
func (c *Client) Send(data string) {
	c.write(ws.OpText, []byte(data))
}

// SendHex sends a binary message given as hex.
// @example
// ```javascript
// const websocket = require('nuclei/websocket');
// const client = new websocket.Client('ws://acme.com/socket');
// client.SendHex('68656c6c6f');
// ```
func (c *Client) SendHex(data string) {
	payload, err := hex.DecodeString(data)
	c.nj.HandleError(err, "invalid hex data")
	c.write(ws.OpBinary, payload)
}

// Receive returns the next text or binary message as a string. Pings are
// answered automatically.
// @example
// ```javascript
// const websocket = require('nuclei/websocket');
// const client = new websocket.Client('ws://acme.com/socket');
// const message = client.Receive();
// ```
func (c *Client) Receive() string {
	return string(c.read())
}

// ReceiveHex returns the next text or binary message as hex.
// @example
// ```javascript
// const websocket = require('nuclei/websocket');
// const client = new websocket.Client('ws://acme.com/socket');
// const message = client.ReceiveHex();
// ```
func (c *Client) ReceiveHex() string {
	return hex.EncodeToString(c.read())
}

// Close sends a close frame and closes the connection.
// @example
// ```javascript
// const websocket = require('nuclei/websocket');
// const client = new websocket.Client('ws://acme.com/socket');
// client.Close();
// ```
func (c *Client) Close() {
	if c.conn == nil {
		return
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	_ = ws.WriteFrame(c.conn, ws.MaskFrame(ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusNormalClosure, ""))))
	_ = c.conn.Close()
	c.conn = nil
	c.reader = nil
}

func (c *Client) write(op ws.OpCode, payload []byte) {
	c.Connect()
	c.nj.HandleError(c.conn.SetWriteDeadline(time.Now().Add(c.timeout)), "could not set write deadline")
	c.nj.HandleError(wsutil.WriteClientMessage(c.conn, op, payload), "websocket send failed")
}

func (c *Client) read() []byte {
	c.Connect()
	c.nj.HandleError(c.conn.SetReadDeadline(time.Now().Add(c.timeout)), "could not set read deadline")

	control := wsutil.ControlFrameHandler(c.conn, ws.StateClientSide)
	reader := wsutil.Reader{
		Source:       c.reader,
		State:        ws.StateClientSide,
		MaxFrameSize: maxMessageSize,
	}
	for {
		header, err := reader.NextFrame()
		c.nj.HandleError(err, "websocket receive failed")
		if header.OpCode.IsControl() {
			if err := control(header, &reader); err != nil {
				var closed wsutil.ClosedError
				if errors.As(err, &closed) {
					c.nj.Throw("websocket closed by server: %d %s", closed.Code, closed.Reason)
				}
				c.nj.HandleError(err, "websocket receive failed")
			}
			continue
		}

		payload, err := io.ReadAll(io.LimitReader(&reader, maxMessageSize+1))
		c.nj.HandleError(err, "websocket receive failed")
		c.nj.Require(len(payload) <= maxMessageSize, fmt.Sprintf("websocket message exceeds %d bytes", maxMessageSize))
		return payload
	}
}

// timeoutFor returns the configured timeout, falling back to the scan's TCP
// read timeout like the net module.
func timeoutFor(ctx context.Context, seconds int) time.Duration {
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if timeouts, ok := ctx.Value("timeoutVariants").(*types.Timeouts); ok && timeouts != nil && timeouts.TcpReadTimeout > 0 {
		return timeouts.TcpReadTimeout
	}
	return defaultTimeout
}
