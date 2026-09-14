// Package grpc implements a nuclei JavaScript library that speaks gRPC by
// wrapping the grpcurl SDK. It supports server reflection and precompiled
// protoset descriptors, and routes every connection and file access through
// nuclei's network and local-file-access policies.
package grpc

import (
	"context"
	"net"
	"time"

	"github.com/fullstorydev/grpcurl"
	"github.com/projectdiscovery/goja"
	"google.golang.org/grpc"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// Options configures a gRPC Client. All fields are optional; the zero value
	// connects over TLS using the target host as the server name and resolves
	// the schema via server reflection.
	// @example
	// ```javascript
	// const grpc = require('nuclei/grpc');
	// const opts = new grpc.Options();
	// opts.Plaintext = true;
	// opts.TimeoutSeconds = 10;
	// const client = new grpc.Client('grpc.acme.com:443', opts);
	// ```
	Options struct {
		// Plaintext disables TLS and uses cleartext HTTP/2 (h2c).
		Plaintext bool
		// InsecureSkipVerify disables TLS certificate verification.
		InsecureSkipVerify bool
		// ServerName overrides the TLS SNI / certificate server name.
		ServerName string
		// TimeoutSeconds is the per-call timeout. 0 means no explicit timeout.
		TimeoutSeconds int
		// ProtosetFile is the path to a compiled FileDescriptorSet (protoset).
		// When set, server reflection is not used. The file is read through the
		// local-file-access allowlist.
		ProtosetFile string
		// MaxRecvMsgSize overrides the maximum received message size in bytes.
		MaxRecvMsgSize int
	}
)

type (
	// Client is a gRPC client for nuclei JS templates backed by grpcurl.
	// @example
	// ```javascript
	// const grpc = require('nuclei/grpc');
	// const client = new grpc.Client('grpc.acme.com:443');
	// const resp = client.Invoke('grpc.health.v1.Health/Check', '{}');
	// ```
	Client struct {
		// Target is the gRPC endpoint in host:port form.
		Target string

		nj          *utils.NucleiJS
		executionID string
		opts        Options
		conn        *grpcConn
	}
)

// grpcConn bundles the live connection and its descriptor source so they can be
// established once and reused across calls.
type grpcConn struct {
	cc      *grpc.ClientConn
	src     grpcurl.DescriptorSource
	cleanup func()
}

// NewClient creates a new gRPC client for the given target.
//
// Constructor: constructor(public target: string, public options?: Options)
func NewClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	c := &Client{nj: utils.NewNucleiJS(runtime)}
	c.nj.ObjectSig = "Client(target, {Options})"

	target, _ := c.nj.GetArg(call.Arguments, 0).(string)
	c.nj.Require(target != "", "grpc target cannot be empty")
	if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		if err := runtime.ExportTo(call.Arguments[1], &c.opts); err != nil {
			c.nj.HandleError(err, "invalid grpc options")
		}
	}
	c.Target = target
	c.executionID = c.nj.ExecutionId()

	// defense in depth: validate the host against the network policy at
	// construction time. The dialer re-checks and enforces it on every dial.
	host, _, err := net.SplitHostPort(target)
	c.nj.HandleError(err, "invalid grpc target (expected host:port)")
	c.nj.Require(host != "", "grpc target host cannot be empty")
	c.nj.Require(protocolstate.IsHostAllowed(c.executionID, host), protocolstate.ErrHostDenied.Msgf(host).Error())

	return utils.LinkConstructor(call, runtime, c)
}

// ensure lazily establishes the connection and descriptor source.
func (c *Client) ensure() {
	c.nj.Require(c.executionID != "", "grpc: missing executionId in runtime")
	if c.conn != nil {
		return
	}
	cc, err := dialTarget(c.nj.Context(), c.executionID, c.Target, connConfig{
		plaintext:          c.opts.Plaintext,
		insecureSkipVerify: c.opts.InsecureSkipVerify,
		serverName:         c.opts.ServerName,
		maxRecvMsgSize:     c.opts.MaxRecvMsgSize,
	})
	c.nj.HandleError(err, "failed to create grpc client")

	src, cleanup, err := descriptorSource(c.nj.Context(), c.executionID, cc, c.opts.ProtosetFile)
	if err != nil {
		_ = cc.Close()
		c.nj.HandleError(err, "failed to load grpc descriptor source")
	}
	c.conn = &grpcConn{cc: cc, src: src, cleanup: cleanup}
}

func (c *Client) callContext() (context.Context, context.CancelFunc) {
	ctx := c.nj.Context()
	if c.opts.TimeoutSeconds > 0 {
		return context.WithTimeout(ctx, time.Duration(c.opts.TimeoutSeconds)*time.Second)
	}
	return ctx, func() {}
}

// Connect eagerly establishes the connection and descriptor source. It is
// optional; other methods connect on demand.
// @example
// ```javascript
// const grpc = require('nuclei/grpc');
// const client = new grpc.Client('grpc.acme.com:443');
// client.Connect();
// ```
func (c *Client) Connect() bool {
	c.ensure()
	return true
}

// ListServices returns the fully-qualified names of all services exposed by the
// target (via reflection) or defined in the configured protoset.
// @example
// ```javascript
// const grpc = require('nuclei/grpc');
// const client = new grpc.Client('grpc.acme.com:443');
// const services = client.ListServices();
// ```
func (c *Client) ListServices() []string {
	c.ensure()
	services, err := grpcurl.ListServices(c.conn.src)
	c.nj.HandleError(err, "failed to list grpc services")
	return services
}

// ListMethods returns the fully-qualified method names of the given service.
// @example
// ```javascript
// const grpc = require('nuclei/grpc');
// const client = new grpc.Client('grpc.acme.com:443');
// const methods = client.ListMethods('grpc.health.v1.Health');
// ```
func (c *Client) ListMethods(service string) []string {
	c.nj.Require(service != "", "grpc service cannot be empty")
	c.ensure()
	methods, err := grpcurl.ListMethods(c.conn.src, service)
	c.nj.HandleError(err, "failed to list grpc methods")
	return methods
}

// DescribeSymbol returns the textual descriptor of a fully-qualified symbol
// (service, method or message type).
// @example
// ```javascript
// const grpc = require('nuclei/grpc');
// const client = new grpc.Client('grpc.acme.com:443');
// const text = client.DescribeSymbol('grpc.health.v1.Health');
// ```
func (c *Client) DescribeSymbol(symbol string) string {
	c.nj.Require(symbol != "", "grpc symbol cannot be empty")
	c.ensure()
	text, err := describeSymbol(c.conn.src, symbol)
	c.nj.HandleError(err, "failed to describe grpc symbol")
	return text
}

// Invoke calls a unary gRPC method with a JSON request and returns the JSON
// response. The method must be in 'package.Service/Method' or
// 'package.Service.Method' form. An empty message is treated as '{}'.
// @example
// ```javascript
// const grpc = require('nuclei/grpc');
// const client = new grpc.Client('grpc.acme.com:443');
// const resp = client.Invoke('grpc.health.v1.Health/Check', '{"service":""}');
// ```
func (c *Client) Invoke(method string, message string) string {
	return c.invoke(method, message, nil)
}

// InvokeWithHeaders behaves like Invoke but also sends the given request
// metadata. Each header must be in 'key: value' form.
// @example
// ```javascript
// const grpc = require('nuclei/grpc');
// const client = new grpc.Client('grpc.acme.com:443');
// const resp = client.InvokeWithHeaders('acme.v1.Svc/Get', '{}', ['authorization: Bearer x']);
// ```
func (c *Client) InvokeWithHeaders(method string, message string, headers []string) string {
	return c.invoke(method, message, headers)
}

func (c *Client) invoke(method, message string, headers []string) string {
	c.nj.Require(method != "", "grpc method cannot be empty")
	c.ensure()
	ctx, cancel := c.callContext()
	defer cancel()
	resp, err := invokeUnary(ctx, c.conn.src, c.conn.cc, method, message, headers)
	c.nj.HandleError(err, "grpc invoke failed")
	return resp
}

// Close releases the connection and any descriptor source resources.
// @example
// ```javascript
// const grpc = require('nuclei/grpc');
// const client = new grpc.Client('grpc.acme.com:443');
// client.Close();
// ```
func (c *Client) Close() bool {
	if c.conn == nil {
		return true
	}
	if c.conn.cleanup != nil {
		c.conn.cleanup()
	}
	if c.conn.cc != nil {
		_ = c.conn.cc.Close()
	}
	c.conn = nil
	return true
}
