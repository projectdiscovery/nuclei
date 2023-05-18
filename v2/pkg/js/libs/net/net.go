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
func Open(protocol, address string) (net.Conn, error) {
	return dialer.Dial(protocol, address)
}

// Open opens a new connection to the address with a timeout.
func OpenTLS(protocol, address string) (net.Conn, error) {
	config := &tls.Config{InsecureSkipVerify: true}
	host, _, _ := net.SplitHostPort(address)
	if host != "" {
		c := config.Clone()
		c.ServerName = host
		config = c
	}
	return tls.DialWithDialer(dialer, protocol, address, config)
}

// Close closes the connection.
func Close(conn net.Conn) error {
	err := conn.Close()
	return err
}

// Send sends data to the connection with a timeout.
func Send(conn net.Conn, data []byte, timeout time.Duration) error {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	err := conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return err
	}
	length, err := conn.Write(data)
	if err != nil {
		return err
	}
	if length < len(data) {
		return fmt.Errorf(
			"failed to write all bytes (%d bytes written, %d bytes expected)",
			length,
			len(data),
		)
	}
	return nil
}

// Recv receives data from the connection with a timeout.
func Recv(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	response := make([]byte, 4096)
	err := conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return []byte{}, err
	}
	length, err := conn.Read(response)
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
func SendRecv(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	err := Send(conn, data, timeout)
	if err != nil {
		return []byte{}, err
	}
	return Recv(conn, timeout)
}
