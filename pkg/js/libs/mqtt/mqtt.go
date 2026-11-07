package mqtt

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	libnet "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/net"
)

var (
	defaultTimeout = 10 * time.Second
)

const (
	maxSubscribedMessages = 1000
	maxSubscribedBytes    = 10 * 1024 * 1024 // 10MB
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
	// ```
	ConnectOptions struct {
		Username           string `json:"username,omitempty"`
		Password           string `json:"password,omitempty"`
		ClientID           string `json:"client_id,omitempty"`
		CleanSession       *bool  `json:"clean_session,omitempty"`
		KeepAlive          int    `json:"keep_alive,omitempty"`
		TLS                bool   `json:"tls,omitempty"`
		InsecureSkipVerify *bool  `json:"insecure_skip_verify,omitempty"`
		Timeout            int    `json:"timeout,omitempty"`
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
func dial(ctx context.Context, host string, port int, useTLS bool, insecureSkipVerify bool, timeout time.Duration) (net.Conn, error) {
	if host == "" || port <= 0 {
		return nil, fmt.Errorf("invalid host or port")
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := libnet.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
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
	conn, err := dial(ctx, host, port, false, true, defaultTimeout)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	pkt, err := buildConnectPacket("nuclei-probe", "", "", true, 60)
	if err != nil {
		return false, err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(defaultTimeout))
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
	conn, err := dial(ctx, host, port, false, true, defaultTimeout)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	pkt, err := buildConnectPacket("", "", "", true, 60)
	if err != nil {
		return false, err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(defaultTimeout))
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
	insecureSkipVerify := true

	if options != nil {
		if options.Timeout > 0 {
			timeout = time.Duration(options.Timeout) * time.Second
		}
		if options.KeepAlive > 0 {
			if options.KeepAlive > 65535 {
				keepAlive = 65535
			} else {
				keepAlive = uint16(options.KeepAlive)
			}
		}
		if options.ClientID != "" {
			clientID = options.ClientID
		}
		if options.CleanSession != nil {
			cleanSession = *options.CleanSession
		}
		if options.InsecureSkipVerify != nil {
			insecureSkipVerify = *options.InsecureSkipVerify
		}
		username = options.Username
		password = options.Password
		useTLS = options.TLS
	}

	c.timeout = timeout
	conn, err := dial(ctx, host, port, useTLS, insecureSkipVerify, timeout)
	if err != nil {
		return &ConnectResult{
			Success:    false,
			ReturnCode: -1,
			Reason:     err.Error(),
		}, err
	}

	pkt, err := buildConnectPacket(clientID, username, password, cleanSession, keepAlive)
	if err != nil {
		_ = conn.Close()
		return &ConnectResult{
			Success:    false,
			ReturnCode: -1,
			Reason:     err.Error(),
		}, err
	}

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
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
	clean := true
	return c.Connect(ctx, host, port, &ConnectOptions{
		Username:     username,
		Password:     password,
		CleanSession: &clean,
	})
}

// Subscribe subscribes to a topic filter and collects received messages up to timeoutSec.
// @example
// ```javascript
// const mqtt = require('nuclei/mqtt');
// const client = new mqtt.Client();
// client.Connect('acme.com', 1883);
// const msgs = client.Subscribe('#', 3);
//
//	for (const m of msgs) {
//	    log(m.Topic, m.Payload);
//	}
//
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

	subPkt, err := buildSubscribePacket(pktID, topic, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to build SUBSCRIBE: %w", err)
	}

	_ = c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if _, err := c.conn.Write(subPkt); err != nil {
		_ = c.conn.Close()
		c.conn = nil
		return nil, fmt.Errorf("failed to send SUBSCRIBE: %w", err)
	}

	waitDuration := 2 * time.Second
	if timeoutSec > 0 {
		if timeoutSec > 60 {
			timeoutSec = 60
		}
		waitDuration = time.Duration(timeoutSec) * time.Second
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < waitDuration {
			waitDuration = remaining
		}
	}

	readDeadline := time.Now().Add(waitDuration)
	_ = c.conn.SetDeadline(readDeadline)
	defer func() {
		if c.conn != nil {
			_ = c.conn.SetDeadline(time.Time{})
		}
	}()

	var messages []*Message
	var totalBytes int
	subackReceived := false

	for {
		select {
		case <-ctx.Done():
			_ = c.conn.Close()
			c.conn = nil
			return messages, ctx.Err()
		default:
		}

		header, payload, err := readPacket(c.conn)
		if err != nil {
			if errors.Is(err, errBrokenStream) {
				// The window closed in the middle of a packet. The stream cannot be
				// read in sync again, so the connection is dropped.
				_ = c.conn.Close()
				c.conn = nil
				if !subackReceived {
					return nil, fmt.Errorf("failed waiting for SUBACK: %w", err)
				}
				break
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Window finished
				break
			}
			if !subackReceived {
				_ = c.conn.Close()
				c.conn = nil
				return nil, fmt.Errorf("failed waiting for SUBACK: %w", err)
			}
			break
		}

		packetType := header >> 4
		switch packetType {
		case PacketSuback:
			subackPID, grantedQoS, err := parseSuback(payload)
			if err != nil {
				_ = c.conn.Close()
				c.conn = nil
				return nil, err
			}
			if subackPID != pktID {
				continue // Ignore stale/mismatched SUBACK from an earlier subscription
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
				totalBytes += len(msg.Topic) + len(msg.Payload)
				if len(messages) >= maxSubscribedMessages || totalBytes >= maxSubscribedBytes {
					return messages, nil
				}
			}
		}

		if time.Now().After(readDeadline) {
			break
		}
	}

	if !subackReceived {
		_ = c.conn.Close()
		c.conn = nil
		return nil, fmt.Errorf("subscription timed out waiting for SUBACK")
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

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	pkt, err := buildPublishPacket(topic, []byte(payload), 0, false, 0)
	if err != nil {
		return false, fmt.Errorf("failed to build PUBLISH: %w", err)
	}

	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.conn.Write(pkt); err != nil {
		_ = c.conn.Close()
		c.conn = nil
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

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	_ = c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.conn.Write(buildPingreqPacket()); err != nil {
		_ = c.conn.Close()
		c.conn = nil
		return false, fmt.Errorf("failed to send PINGREQ: %w", err)
	}

	for {
		header, _, err := readPacket(c.conn)
		if err != nil {
			_ = c.conn.Close()
			c.conn = nil
			return false, fmt.Errorf("failed to read PINGRESP: %w", err)
		}

		packetType := header >> 4
		if packetType == PacketPingresp {
			return true, nil
		}
		if packetType == PacketPublish {
			// Broker delivered an incoming publish message while ping was in flight; continue waiting for PINGRESP
			continue
		}
		return false, fmt.Errorf("unexpected ping response packet: %d", packetType)
	}
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
		_ = c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.conn.Write(buildDisconnectPacket())
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}
