package ipmi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	libnet "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/net"
)

// Wire constants from the IPMI v2.0 specification and DSP0136 (ASF).
const (
	rmcpVersion   = 0x06
	rmcpNoAck     = 0xff
	rmcpClassASF  = 0x06
	rmcpClassIPMI = 0x07

	asfIANA         = 0x000011be
	asfTypePing     = 0x80
	asfTypePong     = 0x40
	asfEntitiesIPMI = 0x80

	authTypeNone  = 0x00
	authTypeRMCPP = 0x06

	netFnApp              = 0x06
	cmdGetSystemGUID      = 0x37
	cmdGetChannelAuthCaps = 0x38
	cmdGetCipherSuites    = 0x54

	bmcAddress     = 0x20
	consoleAddress = 0x81
	currentChannel = 0x0e
	privAdmin      = 0x04

	payloadOpenSessionRequest  = 0x10
	payloadOpenSessionResponse = 0x11
	payloadRAKP1               = 0x12
	payloadRAKP2               = 0x13
	payloadRAKP3               = 0x14
	payloadRAKP4               = 0x15

	// rakpNameOnlyLookup asks the BMC to find the user by name alone, so the
	// role does not have to match the one the account was created with.
	rakpNameOnlyLookup = 0x10

	attempts = 2
)

var errNoResponse = errors.New("no ipmi response")

// session is one UDP exchange with a BMC. UDP is lossy, so each request is
// sent up to attempts times.
type session struct {
	conn    net.Conn
	timeout time.Duration
}

func dial(ctx context.Context, host string, port int) (*session, error) {
	conn, err := libnet.Dial(ctx, "udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	timeout := 3 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline)/attempts)
	}
	return &session{conn: conn, timeout: timeout}, nil
}

func (s *session) close() { _ = s.conn.Close() }

// exchange sends packet and returns the first reply accepted by match.
func (s *session) exchange(packet []byte, match func([]byte) bool) ([]byte, error) {
	buf := make([]byte, 1024)
	for range attempts {
		if _, err := s.conn.Write(packet); err != nil {
			return nil, err
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(s.timeout))
		for {
			n, err := s.conn.Read(buf)
			if err != nil {
				break
			}
			if reply := buf[:n]; match(reply) {
				return bytes.Clone(reply), nil
			}
		}
	}
	return nil, errNoResponse
}

func rmcpHeader(class byte) []byte {
	return []byte{rmcpVersion, 0x00, rmcpNoAck, class}
}

// ping sends an ASF presence ping and reports whether the pong advertises
// IPMI support.
func (s *session) ping() (bool, error) {
	packet := append(rmcpHeader(rmcpClassASF), 0, 0, 0, 0, asfTypePing, 0x00, 0x00, 0x00)
	binary.BigEndian.PutUint32(packet[4:8], asfIANA)
	reply, err := s.exchange(packet, func(reply []byte) bool {
		return len(reply) >= 12 && reply[3] == rmcpClassASF && reply[8] == asfTypePong
	})
	if err != nil {
		return false, err
	}
	// pong data: IANA (4), OEM (4), supported entities (1), interactions (1)
	if len(reply) < 21 {
		return false, nil
	}
	return reply[20]&asfEntitiesIPMI != 0, nil
}

func checksum(data []byte) byte {
	var sum byte
	for _, b := range data {
		sum += b
	}
	return -sum
}

// command sends a session-less IPMI 1.5 request and returns the response
// data after a successful completion code.
func (s *session) command(cmd byte, data []byte) ([]byte, error) {
	header := []byte{bmcAddress, netFnApp << 2}
	body := append([]byte{consoleAddress, 0x00, cmd}, data...)
	message := append(append(header, checksum(header)), body...)
	message = append(message, checksum(body))

	packet := append(rmcpHeader(rmcpClassIPMI), authTypeNone, 0, 0, 0, 0, 0, 0, 0, 0, byte(len(message)))
	packet = append(packet, message...)

	reply, err := s.exchange(packet, func(reply []byte) bool {
		// rmcp (4), session header (10), then rqAddr, netFn, checksum,
		// rsAddr, seq, cmd, completion code
		// ... completion code, then at least the trailing checksum
		return len(reply) >= 22 && reply[3] == rmcpClassIPMI && reply[4] == authTypeNone && reply[19] == cmd
	})
	if err != nil {
		return nil, err
	}
	if code := reply[20]; code != 0 {
		return nil, fmt.Errorf("ipmi command 0x%02x failed with completion code 0x%02x", cmd, code)
	}
	// drop the trailing checksum
	return reply[21 : len(reply)-1], nil
}

// rmcpPlus sends an IPMI 2.0 session-setup payload and returns the reply
// payload of the expected type.
func (s *session) rmcpPlus(payloadType byte, payload []byte, replyType byte) ([]byte, error) {
	packet := append(rmcpHeader(rmcpClassIPMI), authTypeRMCPP, payloadType, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.LittleEndian.PutUint16(packet[14:16], uint16(len(payload)))
	packet = append(packet, payload...)

	reply, err := s.exchange(packet, func(reply []byte) bool {
		return len(reply) >= 16 && reply[3] == rmcpClassIPMI && reply[4] == authTypeRMCPP && reply[5]&0x3f == replyType
	})
	if err != nil {
		return nil, err
	}
	length := int(binary.LittleEndian.Uint16(reply[14:16]))
	if len(reply) < 16+length {
		return nil, fmt.Errorf("truncated ipmi payload")
	}
	return reply[16 : 16+length], nil
}
