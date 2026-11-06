package mqtt

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	libnet "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/net"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

var (
	defaultTimeout = 10 * time.Second
)

type (
	// Message represents an MQTT published message.
	// @example
	// ```javascript
	// const mqtt = require('nuclei/mqtt');
	// const client = new mqtt.Client();
	// client.Connect('broker.hivemq.com', 1883);
	// const msgs = client.Subscribe('test/topic', 2);
	// log(msgs[0].Topic, msgs[0].Payload);
	// ```
	Message struct {
		Topic   string `json:"topic"`
		Payload string `json:"payload"`
		QoS     int    `json:"qos"`
		Retain  bool   `json:"retain"`
	}

	// ConnectOptions contains connection options for an MQTT broker.
	// @example
	// ```javascript
	// const mqtt = require('nuclei/mqtt');
	// const opts = new mqtt.ConnectOptions();
	// opts.Username = 'admin';
	// opts.Password = 'admin';
	// opts.CleanSession = true;
	// ```
	ConnectOptions struct {
		Username     string `json:"username,omitempty"`
		Password     string `json:"password,omitempty"`
		ClientID     string `json:"client_id,omitempty"`
		CleanSession bool   `json:"clean_session,omitempty"`
		KeepAlive    int    `json:"keep_alive,omitempty"`
		TLS          bool   `json:"tls,omitempty"`
		Timeout      int    `json:"timeout,omitempty"`
	}

	// ConnectResult is the response returned by an MQTT connection attempt.
	// @example
	// ```javascript
	// const mqtt = require('nuclei/mqtt');
	// const client = new mqtt.Client();
	// const res = client.Connect('acme.com', 1883);
	// log(res.Success, res.ReturnCode, res.Reason);
	// ```
	ConnectResult struct {
		Success        bool   `json:"success"`
		ReturnCode     int    `json:"return_code"`
		Reason         string `json:"reason"`
		SessionPresent bool   `json:"session_present"`
	}

	// Client is an MQTT client for testing MQTT broker misconfigurations and authentication.
	// @example
	// ```javascript
	// const mqtt = require('nuclei/mqtt');
	// const client = new mqtt.Client();
	// const res = client.Connect('acme.com', 1883);
	// if (res.Success) {
	//     const msgs = client.Subscribe('#', 2);
	//     client.Publish('nuclei/probe', 'test');
	// }
	// client.Close();
	// ```
	Client struct {
		conn     net.Conn
		packetID uint16
		mu       sync.Mutex
		timeout  time.Duration
	}
)

// dial opens a network connection to host:port respecting protocolstate policy and context.
func dial(ctx context.Context, host string, port int, useTLS bool, timeout time.Duration) (net.Conn, error) {
	if host == "" || port <= 0 {
		return nil, fmt.Errorf("invalid host or port")
	}

	executionId, _ := ctx.Value("executionId").(string)
	if executionId != "" && !protocolstate.IsHostAllowed(executionId, host) {
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var conn net.Conn
	var err error

	if executionId != "" {
		conn, err = libnet.Dial(ctx, "tcp", addr)
	} else {
		var d net.Dialer
		d.Timeout = timeout
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}

	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn = tlsConn
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

// IsMQTT checks whether the target host:port is running an MQTT broker.
// @example
// ```javascript
// const mqtt = require('nuclei/mqtt');
// const isMqtt = mqtt.IsMQTT('acme.com', 1883);
// log(isMqtt);
// ```
func IsMQTT(ctx context.Context, host string, port int) (bool, error) {
	conn, err := dial(ctx, host, port, false, defaultTimeout)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	pkt := buildConnectPacket("nuclei-probe", "", "", true, 60)
	if _, err := conn.Write(pkt); err != nil {
		return false, err
	}

	header, payload, err := readPacket(conn)
	if err != nil {
		return false, nil
	}

	// Any valid CONNACK indicates an active MQTT broker
	if (header >> 4) == PacketConnack {
		_, _, err := parseConnack(payload)
		return err == nil, nil
	}
	return false, nil
}

// IsAnonymousAllowed checks whether an MQTT broker permits unauthenticated / anonymous login.
// @example
// ```javascript
// const mqtt = require('nuclei/mqtt');
// const allowed = mqtt.IsAnonymousAllowed('acme.com', 1883);
// log(allowed);
// ```
func IsAnonymousAllowed(ctx context.Context, host string, port int) (bool, error) {
	conn, err := dial(ctx, host, port, false, defaultTimeout)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	pkt := buildConnectPacket("", "", "", true, 60)
	if _, err := conn.Write(pkt); err != nil {
		return false, err
	}

	header, payload, err := readPacket(conn)
	if err != nil {
		return false, err
	}

	if (header >> 4) != PacketConnack {
		return false, fmt.Errorf("expected CONNACK, got packet type %d", header>>4)
	}

	_, returnCode, err := parseConnack(payload)
	if err != nil {
		return false, err
	}

	return returnCode == ConnAccepted, nil
}

// Connect connects to an MQTT broker using optional credentials and settings.
// @example
// ```javascript
// const mqtt = require('nuclei/mqtt');
// const client = new mqtt.Client();
// const res = client.Connect('acme.com', 1883);
// log(res.Success);
// ```
func (c *Client) Connect(ctx context.Context, host string, port int, options *ConnectOptions) (*ConnectResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}

	timeout := defaultTimeout
	cleanSession := true
	keepAlive := uint16(60)
	clientID := "nuclei"
	var username, password string
	useTLS := false

	if options != nil {
		if options.Timeout > 0 {
			timeout = time.Duration(options.Timeout) * time.Second
		}
		if options.KeepAlive > 0 {
			keepAlive = uint16(options.KeepAlive)
		}
		if options.ClientID != "" {
			clientID = options.ClientID
		}
		cleanSession = options.CleanSession
		username = options.Username
		password = options.Password
		useTLS = options.TLS
	}

	c.timeout = timeout
	conn, err := dial(ctx, host, port, useTLS, timeout)
	if err != nil {
		return &ConnectResult{
			Success:    false,
			ReturnCode: -1,
			Reason:     err.Error(),
		}, err
	}

	pkt := buildConnectPacket(clientID, username, password, cleanSession, keepAlive)
	if _, err := conn.Write(pkt); err != nil {
		_ = conn.Close()
		return &ConnectResult{
			Success:    false,
			ReturnCode: -1,
			Reason:     fmt.Sprintf("failed to send CONNECT: %v", err),
		}, err
	}

	header, payload, err := readPacket(conn)
	if err != nil {
		_ = conn.Close()
		return &ConnectResult{
			Success:    false,
			ReturnCode: -1,
			Reason:     fmt.Sprintf("failed to read CONNACK: %v", err),
		}, err
	}

	if (header >> 4) != PacketConnack {
		_ = conn.Close()
		return &ConnectResult{
			Success:    false,
			ReturnCode: -1,
			Reason:     fmt.Sprintf("unexpected packet %d (expected CONNACK)", header>>4),
		}, fmt.Errorf("unexpected packet %d", header>>4)
	}

	sessPresent, returnCode, err := parseConnack(payload)
	if err != nil {
		_ = conn.Close()
		return &ConnectResult{
			Success:    false,
			ReturnCode: int(returnCode),
			Reason:     err.Error(),
		}, err
	}

	res := &ConnectResult{
		Success:        returnCode == ConnAccepted,
		ReturnCode:     int(returnCode),
		Reason:         ConnackReason(returnCode),
		SessionPresent: sessPresent,
	}

	if res.Success {
		c.conn = conn
	} else {
		_ = conn.Close()
	}

	return res, nil
}

// ConnectAuth connects to an MQTT broker with a username and password.
// @example
// ```javascript
// const mqtt = require('nuclei/mqtt');
// const client = new mqtt.Client();
// const res = client.ConnectAuth('acme.com', 1883, 'admin', 'admin');
// log(res.Success);
// ```
func (c *Client) ConnectAuth(ctx context.Context, host string, port int, username, password string) (*ConnectResult, error) {
	return c.Connect(ctx, host, port, &ConnectOptions{
		Username:     username,
		Password:     password,
		CleanSession: true,
	})
}

// Subscribe subscribes to a topic filter and collects received messages up to timeoutSec.
// @example
// ```javascript
// const mqtt = require('nuclei/mqtt');
// const client = new mqtt.Client();
// client.Connect('acme.com', 1883);
// const msgs = client.Subscribe('#', 3);
// for (const m of msgs) {
//     log(m.Topic, m.Payload);
// }
// ```
func (c *Client) Subscribe(ctx context.Context, topic string, timeoutSec int) ([]*Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("not connected to MQTT broker")
	}

	c.packetID++
	if c.packetID == 0 {
		c.packetID = 1
	}
	pktID := c.packetID

	subPkt := buildSubscribePacket(pktID, topic, 0)
	if _, err := c.conn.Write(subPkt); err != nil {
		return nil, fmt.Errorf("failed to send SUBSCRIBE: %w", err)
	}

	waitDuration := 2 * time.Second
	if timeoutSec > 0 {
		waitDuration = time.Duration(timeoutSec) * time.Second
	}

	deadline := time.Now().Add(waitDuration)
	_ = c.conn.SetDeadline(deadline)
	defer func() {
		if c.conn != nil {
			_ = c.conn.SetDeadline(time.Time{})
		}
	}()

	var messages []*Message
	subackReceived := false

	for {
		header, payload, err := readPacket(c.conn)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Window finished
				break
			}
			if err == io.EOF && subackReceived {
				break
			}
			if !subackReceived {
				return nil, fmt.Errorf("failed waiting for SUBACK: %w", err)
			}
			break
		}

		packetType := header >> 4
		switch packetType {
		case PacketSuback:
			_, grantedQoS, err := parseSuback(payload)
			if err != nil {
				return nil, err
			}
			for _, qos := range grantedQoS {
				if qos == 0x80 {
					return nil, fmt.Errorf("subscription rejected by broker for topic %q", topic)
				}
			}
			subackReceived = true

		case PacketPublish:
			msg, err := parsePublish(header, payload)
			if err == nil {
				messages = append(messages, msg)
			}
		}

		if time.Now().After(deadline) {
			break
		}
	}

	return messages, nil
}

// Publish publishes a message payload to a topic.
// @example
// ```javascript
// const mqtt = require('nuclei/mqtt');
// const client = new mqtt.Client();
// client.Connect('acme.com', 1883);
// const ok = client.Publish('nuclei/test', 'probe payload');
// log(ok);
// ```
func (c *Client) Publish(ctx context.Context, topic string, payload string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return false, fmt.Errorf("not connected to MQTT broker")
	}

	_ = c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	pkt := buildPublishPacket(topic, []byte(payload), 0, false, 0)
	if _, err := c.conn.Write(pkt); err != nil {
		return false, fmt.Errorf("failed to send PUBLISH: %w", err)
	}

	return true, nil
}

// Ping sends an MQTT PINGREQ and awaits PINGRESP.
// @example
// ```javascript
// const mqtt = require('nuclei/mqtt');
// const client = new mqtt.Client();
// client.Connect('acme.com', 1883);
// const alive = client.Ping();
// log(alive);
// ```
func (c *Client) Ping(ctx context.Context) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return false, fmt.Errorf("not connected to MQTT broker")
	}

	_ = c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.conn.Write(buildPingreqPacket()); err != nil {
		return false, fmt.Errorf("failed to send PINGREQ: %w", err)
	}

	header, _, err := readPacket(c.conn)
	if err != nil {
		return false, fmt.Errorf("failed to read PINGRESP: %w", err)
	}

	if (header >> 4) != PacketPingresp {
		return false, fmt.Errorf("unexpected ping response packet: %d", header>>4)
	}

	return true, nil
}

// Close cleanly disconnects and closes the connection.
// @example
// ```javascript
// const mqtt = require('nuclei/mqtt');
// const client = new mqtt.Client();
// client.Connect('acme.com', 1883);
// client.Close();
// ```
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		_, _ = c.conn.Write(buildDisconnectPacket())
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}
