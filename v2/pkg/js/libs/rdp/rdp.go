package rdp

import (
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/rdp"
)

// Client is a client for rdp servers
type Client struct{}

type IsRDPResponse struct {
	IsRDP bool
	OS    string
}

// IsRDP checks if the given host and port are running rdp server.
//
// If connection is successful, it returns true.
// If connection is unsuccessful, it returns false and error.
//
// The Name of the OS is also returned if the connection is successful.
func (c *Client) IsRDP(host string, port int) (IsRDPResponse, error) {
	resp := IsRDPResponse{}

	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return resp, err
	}
	defer conn.Close()

	server, isRDP, err := rdp.DetectRDP(conn, timeout)
	if err != nil {
		return resp, err
	}
	if !isRDP {
		return resp, nil
	}
	resp.IsRDP = true
	resp.OS = server
	return resp, nil
}

type CheckRDPAuthResponse struct {
	PluginInfo *plugins.ServiceRDP
	Auth       bool
}

// CheckRDPAuth checks if the given host and port are running rdp server
// with authentication and returns their metadata.
func (c *Client) CheckRDPAuth(host string, port int) (CheckRDPAuthResponse, error) {
	resp := CheckRDPAuthResponse{}

	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return resp, err
	}
	defer conn.Close()

	pluginInfo, auth, err := rdp.DetectRDPAuth(conn, timeout)
	if err != nil {
		return resp, err
	}
	if !auth {
		return resp, nil
	}
	resp.Auth = true
	resp.PluginInfo = pluginInfo
	return resp, nil
}
