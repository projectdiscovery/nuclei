package redis

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/redis/go-redis/v9"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	pluginsredis "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/redis"
)

// GetServerInfo returns the server info for a redis server
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const info = redis.GetServerInfo('acme.com', 6379);
// ```
func GetServerInfo(ctx context.Context, host string, port int) (string, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedgetServerInfo(ctx, executionId, host, port)
}

// @memo
func getServerInfo(ctx context.Context, executionId string, host string, port int) (string, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := newClient(fmt.Sprintf("%s:%d", host, port), "")
	defer func() {
		_ = client.Close()
	}()

	// Ping the Redis server
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return "", err
	}

	// Get Redis server info
	infoCmd := client.Info(ctx)
	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}

// Connect tries to connect redis server with password
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const connected = redis.Connect('acme.com', 6379, 'password');
// ```
func Connect(ctx context.Context, host string, port int, password string) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedconnect(ctx, executionId, host, port, password)
}

// @memo
func connect(ctx context.Context, executionId string, host string, port int, password string) (bool, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := newClient(fmt.Sprintf("%s:%d", host, port), password)
	defer func() {
		_ = client.Close()
	}()

	_, err := client.Ping(ctx).Result()
	if err != nil {
		return false, err
	}
	// Get Redis server info
	infoCmd := client.Info(ctx)
	if infoCmd.Err() != nil {
		return false, infoCmd.Err()
	}

	return true, nil
}

// GetServerInfoAuth returns the server info for a redis server
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const info = redis.GetServerInfoAuth('acme.com', 6379, 'password');
// ```
func GetServerInfoAuth(ctx context.Context, host string, port int, password string) (string, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedgetServerInfoAuth(ctx, executionId, host, port, password)
}

// @memo
func getServerInfoAuth(ctx context.Context, executionId string, host string, port int, password string) (string, error) {
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return "", protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := newClient(fmt.Sprintf("%s:%d", host, port), password)
	defer func() {
		_ = client.Close()
	}()

	// Ping the Redis server
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return "", err
	}

	// Get Redis server info
	infoCmd := client.Info(ctx)
	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}

// IsAuthenticated checks if the redis server requires authentication
// @example
// ```javascript
// const redis = require('nuclei/redis');
// const isAuthenticated = redis.IsAuthenticated('acme.com', 6379);
// ```
func IsAuthenticated(ctx context.Context, host string, port int) (bool, error) {
	executionId := ctx.Value("executionId").(string)
	return memoizedisAuthenticated(ctx, executionId, host, port)
}

// @memo
func isAuthenticated(ctx context.Context, executionId string, host string, port int) (bool, error) {
	plugin := pluginsredis.REDISPlugin{}
	timeout := 5 * time.Second
	dialer := protocolstate.GetDialersWithId(executionId)
	if dialer == nil {
		return false, fmt.Errorf("dialers not initialized for %s", executionId)
	}

	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, err
	}
	defer func() {
		_ = conn.Close()
	}()

	_, err = plugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return false, err
	}
	return true, nil
}

// RunLuaScript runs a lua script on the redis server
// @example
// ```javascript
// const redis = require('nuclei/redis');
// // Old signature (backwards compatible) - keys and args are optional
// const result = redis.RunLuaScript('acme.com', 6379, 'password', 'return redis.call("ping")');
// // New signature with keys and args
// const result = redis.RunLuaScript('acme.com', 6379, 'password', 'return redis.call("get", KEYS[1])', ['mykey'], []);
// ```
func RunLuaScript(ctx context.Context, host string, port int, password string, script string, keys interface{}, args interface{}) (interface{}, error) {
	executionId := ctx.Value("executionId").(string)
	if !protocolstate.IsHostAllowed(executionId, host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
	// create a new client
	client := newClient(fmt.Sprintf("%s:%d", host, port), password)
	defer func() {
		_ = client.Close()
	}()

	// Ping the Redis server
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return "", err
	}

	// Convert interface{} to []string for keys (handle backwards compatibility)
	keysSlice := []string{}
	if keys != nil {
		switch v := keys.(type) {
		case []string:
			keysSlice = v
		case []interface{}:
			keysSlice = make([]string, 0, len(v))
			for _, item := range v {
				keysSlice = append(keysSlice, fmt.Sprintf("%v", item))
			}
		case string:
			// the goja runtime zero-fills omitted trailing JS arguments with
			// the previous parameter's type, so a 4-arg call (old signature)
			// delivers "" here: treat it as no keys (backwards compat)
			if v != "" {
				return nil, fmt.Errorf("keys must be []string or []interface{}, got string")
			}
		default:
			return nil, fmt.Errorf("keys must be []string or []interface{}, got %T", keys)
		}
	}

	// Convert interface{} args to []interface{} for Eval (handle backwards
	// compatibility). Non-string items (numbers, booleans from JavaScript)
	// are stringified rather than dropped: Redis ARGV values are always
	// bulk strings on the Lua side, so "123"/"true" match JS expectations.
	argsInterface := []interface{}{}
	if args != nil {
		switch v := args.(type) {
		case []string:
			argsInterface = make([]interface{}, len(v))
			for i, arg := range v {
				argsInterface[i] = arg
			}
		case []interface{}:
			argsInterface = make([]interface{}, len(v))
			for i, item := range v {
				argsInterface[i] = fmt.Sprintf("%v", item)
			}
		case string:
			// zero-value padding from omitted JS arguments (see keys above)
			if v != "" {
				return nil, fmt.Errorf("args must be []string or []interface{}, got string")
			}
		default:
			return nil, fmt.Errorf("args must be []string or []interface{}, got %T", args)
		}
	}

	// Execute the Lua script with keys and args
	infoCmd := client.Eval(ctx, script, keysSlice, argsInterface...)

	if infoCmd.Err() != nil {
		return "", infoCmd.Err()
	}

	return infoCmd.Val(), nil
}

// maxReadBytes bounds what one connection may read. go-redis reads a reply line until "\n" with
// no length limit, so a port that streams bytes without one was buffered for as long as it kept
// sending. The replies these calls expect, INFO included, are a few kilobytes.
//
// A RESP length header is rejected before it is returned. go-redis allocates the declared
// bulk size, or one interface per array element, before reading the payload.
const maxReadBytes = 16 << 20

// maxAggregate is how many array, set, map, attribute, or push elements fit in maxReadBytes,
// since each element is an interface value.
const maxAggregate = maxReadBytes / 16

var errReadLimit = fmt.Errorf("redis: reply exceeds %d bytes", maxReadBytes)

// newClient is redis.NewClient on the default dialer, with each connection's reads capped at
// maxReadBytes.
func newClient(addr, password string) *redis.Client {
	opts := &redis.Options{
		Addr:     addr,
		Password: password,
		DB:       0,
	}
	dial := redis.NewDialer(opts)
	opts.Dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &limitedConn{Conn: conn, remaining: maxReadBytes}, nil
	}

	return redis.NewClient(opts)
}

// limitedConn fails a read once remaining is spent, and withholds a RESP length line whose
// declared size is over the cap so go-redis never allocates it.
type limitedConn struct {
	net.Conn
	remaining int64
	pending   []byte
	partial   []byte
	err       error
	scratch   [32 << 10]byte
}

func (c *limitedConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		if err := c.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *limitedConn) fill() error {
	if len(c.pending) > 0 {
		return nil
	}
	if c.err != nil {
		return c.err
	}
	for len(c.pending) == 0 {
		if c.remaining <= 0 {
			c.err = errReadLimit
			return c.err
		}
		want := int64(len(c.scratch))
		if want > c.remaining {
			want = c.remaining
		}
		n, err := c.Conn.Read(c.scratch[:want])
		if n > 0 {
			c.remaining -= int64(n)
			if aerr := c.accept(c.scratch[:n]); aerr != nil {
				c.err = aerr
				if len(c.pending) > 0 {
					return nil
				}
				return aerr
			}
		}
		if err != nil {
			// A read deadline belongs to one call. go-redis peeks for push notifications
			// with a few microseconds of deadline, and on Windows that peek always runs.
			// Keeping the timeout fails the command that follows.
			if timeoutErr(err) {
				if len(c.pending) > 0 {
					return nil
				}
				return err
			}
			c.err = err
			if len(c.pending) > 0 {
				return nil
			}
			return err
		}
		if n == 0 {
			c.err = io.ErrUnexpectedEOF
			return c.err
		}
	}
	return nil
}

func (c *limitedConn) accept(p []byte) error {
	c.partial = append(c.partial, p...)
	for {
		i := bytes.IndexByte(c.partial, '\n')
		if i < 0 {
			if int64(len(c.partial)) > maxReadBytes {
				c.partial = nil
				return errReadLimit
			}
			return nil
		}
		line := c.partial[:i+1]
		if lengthTooLarge(line) {
			c.partial = nil
			return errReadLimit
		}
		copied := make([]byte, len(line))
		copy(copied, line)
		c.pending = append(c.pending, copied...)
		rest := make([]byte, len(c.partial)-(i+1))
		copy(rest, c.partial[i+1:])
		c.partial = rest
	}
}

// lengthTooLarge reports whether line is a RESP length header go-redis would allocate from.
// Bulk strings allocate the declared byte length. Arrays, sets, maps, attributes, and pushes
// allocate one interface per declared element.
func lengthTooLarge(line []byte) bool {
	if len(line) < 3 {
		return false
	}
	var limit int64
	switch line[0] {
	case '$', '=', '!':
		limit = maxReadBytes
	case '*', '~', '>', '%', '|':
		limit = maxAggregate
	default:
		return false
	}
	body := line[1 : len(line)-1]
	if len(body) > 0 && body[len(body)-1] == '\r' {
		body = body[:len(body)-1]
	}
	if len(body) == 0 || body[0] == '-' {
		return false
	}
	n, err := strconv.ParseInt(string(body), 10, 64)
	if err != nil {
		return true
	}
	return n > limit
}

func timeoutErr(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
