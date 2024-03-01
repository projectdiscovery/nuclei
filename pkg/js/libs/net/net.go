package net

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	"github.com/projectdiscovery/utils/reader"
)

var (
	defaultTimeout = time.Duration(5) * time.Second
)

// Open opens a new connection to the address with a timeout.
// supported protocols: tcp, udp
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// ```
func Open(protocol, address string) (*NetConn, error) {
	conn, err := protocolstate.Dialer.Dial(context.TODO(), protocol, address)
	if err != nil {
		return nil, err
	}
	return &NetConn{conn: conn, timeout: defaultTimeout}, nil
}

// Open opens a new connection to the address with a timeout.
// supported protocols: tcp, udp
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.OpenTLS('tcp', 'acme.com:443');
// ```
func OpenTLS(protocol, address string) (*NetConn, error) {
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	host, _, _ := net.SplitHostPort(address)
	if host != "" {
		c := config.Clone()
		c.ServerName = host
		config = c
	}
	conn, err := protocolstate.Dialer.DialTLSWithConfig(context.TODO(), protocol, address, config)
	if err != nil {
		return nil, err
	}
	return &NetConn{conn: conn, timeout: defaultTimeout}, nil
}

type (
	// NetConn is a connection to a remote host.
	// this is returned/create by Open and OpenTLS functions.
	// @example
	// ```javascript
	// const net = require('nuclei/net');
	// const conn = net.Open('tcp', 'acme.com:80');
	// ```
	NetConn struct {
		conn    net.Conn
		timeout time.Duration
	}
)

// Close closes the connection.
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// conn.Close();
// ```
func (c *NetConn) Close() error {
	err := c.conn.Close()
	return err
}

// SetTimeout sets read/write timeout for the connection (in seconds).
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// conn.SetTimeout(10);
// ```
func (c *NetConn) SetTimeout(value int) {
	c.timeout = time.Duration(value) * time.Second
}

// setDeadLine sets read/write deadline for the connection (in seconds).
// this is intended to be called before every read/write operation.
func (c *NetConn) setDeadLine() {
	if c.timeout == 0 {
		c.timeout = 5 * time.Second
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))
}

// unsetDeadLine unsets read/write deadline for the connection.
func (c *NetConn) unsetDeadLine() {
	_ = c.conn.SetDeadline(time.Time{})
}

// SendArray sends array data to connection
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// conn.SendArray(['hello', 'world']);
// ```
func (c *NetConn) SendArray(data []interface{}) error {
	c.setDeadLine()
	defer c.unsetDeadLine()
	input := types.ToByteSlice(data)
	length, err := c.conn.Write(input)
	if err != nil {
		return err
	}
	if length < len(input) {
		return fmt.Errorf("failed to write all bytes (%d bytes written, %d bytes expected)", length, len(input))
	}
	return nil
}

// SendHex sends hex data to connection
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// conn.SendHex('68656c6c6f');
// ```
func (c *NetConn) SendHex(data string) error {
	c.setDeadLine()
	defer c.unsetDeadLine()
	bin, err := hex.DecodeString(data)
	if err != nil {
		return err
	}
	length, err := c.conn.Write(bin)
	if err != nil {
		return err
	}
	if length < len(bin) {
		return fmt.Errorf("failed to write all bytes (%d bytes written, %d bytes expected)", length, len(bin))
	}
	return nil
}

// Send sends data to the connection with a timeout.
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// conn.Send('hello');
// ```
func (c *NetConn) Send(data string) error {
	c.setDeadLine()
	defer c.unsetDeadLine()
	bin := []byte(data)
	length, err := c.conn.Write(bin)
	if err != nil {
		return err
	}
	if length < len(bin) {
		return fmt.Errorf("failed to write all bytes (%d bytes written, %d bytes expected)", length, len(data))
	}
	return nil
}

// RecvFull receives data from the connection with a timeout.
// If N is 0, it will read all data sent by the server with 8MB limit.
// it tries to read until N bytes or timeout is reached.
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// const data = conn.RecvFull(1024);
// ```
func (c *NetConn) RecvFull(N int) ([]byte, error) {
	c.setDeadLine()
	defer c.unsetDeadLine()
	if N == 0 {
		// in utils we use -1 to indicate read all rather than 0
		N = -1
	}
	bin, err := reader.ConnReadNWithTimeout(c.conn, int64(N), c.timeout)
	if err != nil {
		return []byte{}, errorutil.NewWithErr(err).Msgf("failed to read %d bytes", N)
	}
	return bin, nil
}

// Recv is similar to RecvFull but does not guarantee full read instead
// it creates a buffer of N bytes and returns whatever is returned by the connection
// for reading headers or initial bytes from the server this is usually used.
// for reading a fixed number of already known bytes (ex: body based on content-length) use RecvFull.
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// const data = conn.Recv(1024);
// log(`Received ${data.length} bytes from the server`)
// ```
func (c *NetConn) Recv(N int) ([]byte, error) {
	c.setDeadLine()
	defer c.unsetDeadLine()
	if N == 0 {
		N = 4096
	}
	b := make([]byte, N)
	n, err := c.conn.Read(b)
	if err != nil {
		return []byte{}, errorutil.NewWithErr(err).Msgf("failed to read %d bytes", N)
	}
	return b[:n], nil
}

// RecvFullString receives data from the connection with a timeout
// output is returned as a string.
// If N is 0, it will read all data sent by the server with 8MB limit.
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// const data = conn.RecvFullString(1024);
// ```
func (c *NetConn) RecvFullString(N int) (string, error) {
	bin, err := c.RecvFull(N)
	if err != nil {
		return "", err
	}
	return string(bin), nil
}

// RecvString is similar to RecvFullString but does not guarantee full read, instead
// it creates a buffer of N bytes and returns whatever is returned by the connection
// for reading headers or initial bytes from the server this is usually used.
// for reading a fixed number of already known bytes (ex: body based on content-length) use RecvFullString.
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// const data = conn.RecvString(1024);
// ```
func (c *NetConn) RecvString(N int) (string, error) {
	bin, err := c.Recv(N)
	if err != nil {
		return "", err
	}
	return string(bin), nil
}

// RecvFullHex receives data from the connection with a timeout
// in hex format.
// If N is 0,it will read all data sent by the server with 8MB limit.
// until N bytes or timeout is reached.
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// const data = conn.RecvFullHex(1024);
// ```
func (c *NetConn) RecvFullHex(N int) (string, error) {
	bin, err := c.RecvFull(N)
	if err != nil {
		return "", err
	}
	return hex.Dump(bin), nil
}

// RecvHex is similar to RecvFullHex but does not guarantee full read instead
// it creates a buffer of N bytes and returns whatever is returned by the connection
// for reading headers or initial bytes from the server this is usually used.
// for reading a fixed number of already known bytes (ex: body based on content-length) use RecvFull.
// @example
// ```javascript
// const net = require('nuclei/net');
// const conn = net.Open('tcp', 'acme.com:80');
// const data = conn.RecvHex(1024);
// ```
func (c *NetConn) RecvHex(N int) (string, error) {
	bin, err := c.Recv(N)
	if err != nil {
		return "", err
	}
	return hex.Dump(bin), nil
}
