package net

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

var dialer = &net.Dialer{
	Timeout: 5 * time.Second,
}

// Open opens a new connection to the address with a timeout.
func Open(protocol, address string) (*Conn, error) {
	conn, err := dialer.Dial(protocol, address)
	if err != nil {
		return nil, err
	}
	return &Conn{conn: conn}, nil
}

// Open opens a new connection to the address with a timeout.
func OpenTLS(protocol, address string) (*Conn, error) {
	config := &tls.Config{InsecureSkipVerify: true}
	host, _, _ := net.SplitHostPort(address)
	if host != "" {
		c := config.Clone()
		c.ServerName = host
		config = c
	}
	conn, err := tls.DialWithDialer(dialer, protocol, address, config)
	if err != nil {
		return nil, err
	}
	return &Conn{conn: conn}, nil
}

// Conn is a connection to a remote host.
type Conn struct {
	conn net.Conn
}

// Close closes the connection.
func (c *Conn) Close() error {
	err := c.conn.Close()
	return err
}

// Send sends data to the connection with a timeout.
func (c *Conn) Send(data []byte, timeout time.Duration) error {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	err := c.conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return err
	}
	length, err := c.conn.Write(data)
	if err != nil {
		return err
	}
	if length < len(data) {
		return fmt.Errorf("failed to write all bytes (%d bytes written, %d bytes expected)", length, len(data))
	}
	return nil
}

// Recv receives data from the connection with a timeout.
func (c *Conn) Recv(timeout time.Duration, N int) ([]byte, error) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	var response []byte
	if N > 0 {
		response = make([]byte, N)
	} else {
		response = make([]byte, 4096)
	}
	err := c.conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return []byte{}, err
	}
	length, err := c.conn.Read(response)
	if err != nil {
		var netErr net.Error
		if (errors.As(err, &netErr) && netErr.Timeout()) ||
			errors.Is(err, syscall.ECONNREFUSED) { // timeout error or connection refused
			return []byte{}, nil
		}
		return response[:length], err
	}
	return response[:length], nil
}

// SendRecv sends data to the connection and receives data from the connection with a timeout.
func (c *Conn) SendRecv(data []byte, timeout time.Duration) ([]byte, error) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	err := c.Send(data, timeout)
	if err != nil {
		return []byte{}, err
	}
	return c.Recv(timeout, 0)
}
