package redis

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/projectdiscovery/gologger"
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
		Addr:          addr,
		Password:      password,
		DB:            0,
		DialerRetries: dialAttempts,
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

// maxHeaderLen fits a type byte, any int64, and "\r". Redis never sends a longer length header.
const maxHeaderLen = 32

// limitedConn fails a read once remaining is spent, and ends a read before the "\n" of a RESP
// length header whose declared size is over the cap, so go-redis never gets the line to allocate
// from.
//
// It follows the reply's framing as the bytes pass: a bulk payload is skipped by its declared
// length, so only header lines are checked. A payload line such as "*abc" is data.
type limitedConn struct {
	net.Conn
	remaining int64
	// payload is how many bytes of the current bulk payload, "\r\n" included, are still to come.
	payload int64
	// header is the start of the current header line, without its "\n".
	header   []byte
	overlong bool
	err      error
}

func (c *limitedConn) Read(b []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.remaining <= 0 {
		return 0, errReadLimit
	}
	if int64(len(b)) > c.remaining {
		b = b[:c.remaining]
	}
	n, err := c.Conn.Read(b)
	c.remaining -= int64(n)
	// Errors from the connection, deadlines included, are returned as they come and not kept: a
	// read deadline belongs to one call. go-redis peeks for push notifications with a few
	// microseconds of deadline, and keeping that timeout would fail the command that follows.
	kept, scanErr := c.scan(b[:n])
	if scanErr == nil {
		return n, err
	}
	c.err = scanErr
	if kept == 0 {
		return 0, scanErr
	}
	return kept, nil
}

// scan follows the RESP framing of p and returns how many of its bytes may be returned.
func (c *limitedConn) scan(p []byte) (int, error) {
	for i := 0; i < len(p); {
		if c.payload > 0 {
			skip := min(c.payload, int64(len(p)-i))
			c.payload -= skip
			i += int(skip)
			continue
		}
		end := bytes.IndexByte(p[i:], '\n')
		if end < 0 {
			c.keepHeader(p[i:])
			return len(p), nil
		}
		c.keepHeader(p[i : i+end])
		payload, err := declaredPayload(c.header, c.overlong)
		c.header, c.overlong = c.header[:0], false
		if err != nil {
			return i + end, err
		}
		c.payload = payload
		i += end + 1
	}
	return len(p), nil
}

func (c *limitedConn) keepHeader(p []byte) {
	if room := maxHeaderLen - len(c.header); len(p) > room {
		p = p[:room]
		c.overlong = true
	}
	c.header = append(c.header, p...)
}

// declaredPayload returns how many payload bytes, "\r\n" included, follow a RESP header line
// given without its "\n". It returns errReadLimit when go-redis would allocate more than the cap
// from the line: the declared byte length for bulk strings, one interface per declared element
// for arrays, sets, maps, attributes, and pushes.
func declaredPayload(line []byte, overlong bool) (int64, error) {
	if len(line) == 0 {
		return 0, nil
	}
	var limit int64
	bulk := false
	switch line[0] {
	case '$', '=', '!':
		limit, bulk = maxReadBytes, true
	case '*', '~', '>', '%', '|':
		limit = maxAggregate
	default:
		return 0, nil
	}
	if overlong {
		return 0, errReadLimit
	}
	body := bytes.TrimSuffix(line[1:], []byte("\r"))
	if len(body) == 0 || body[0] == '-' {
		return 0, nil
	}
	n, err := strconv.ParseInt(string(body), 10, 64)
	if err != nil || n > limit {
		return 0, errReadLimit
	}
	if !bulk {
		return 0, nil
	}
	return n + 2, nil
}

// dialAttempts replaces go-redis's default of 5. The extra attempts run in a goroutine that
// ignores the caller's context, so they kept dialing a filtered port for ~25s after the
// template had given up on it.
const dialAttempts = 1

func init() {
	redis.SetLogger(warningLogger{})
}

// warningLogger hands go-redis's logs to gologger as warnings. Its default logger writes them
// straight to stderr, where a failed dial against the scanned host reads as an error.
type warningLogger struct{}

func (warningLogger) Printf(_ context.Context, format string, v ...interface{}) {
	gologger.Warning().Msgf(format, v...)
}
