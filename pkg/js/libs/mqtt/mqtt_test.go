package mqtt

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestVarLengthEncoding(t *testing.T) {
	testCases := []int{0, 1, 64, 127, 128, 16383, 16384, 2097151}
	for _, tc := range testCases {
		encoded, err := encodeVarLength(tc)
		require.NoError(t, err)
		decoded, err := decodeVarLength(bytes.NewReader(encoded))
		require.NoError(t, err)
		require.Equal(t, tc, decoded)
	}

	// Test negative or overflow
	_, err := encodeVarLength(-1)
	require.Error(t, err)
	_, err = encodeVarLength(MaxRemainingLength + 1)
	require.Error(t, err)
}

func TestOversizedStringsAndPackets(t *testing.T) {
	hugeString := strings.Repeat("A", MaxStringLength+1)
	_, err := encodeString(hugeString)
	require.Error(t, err)

	_, err = buildConnectPacket("id", hugeString, "pass", true, 60)
	require.Error(t, err)

	_, err = buildSubscribePacket(1, hugeString, 0)
	require.Error(t, err)

	_, err = buildPublishPacket(hugeString, []byte("ok"), 0, false, 0)
	require.Error(t, err)

	// Oversized packet reading
	oversizedLen, err := encodeVarLength(MaxPacketSize + 100)
	require.NoError(t, err)
	buf := append([]byte{PacketPublish << 4}, oversizedLen...)
	_, _, err = readPacket(bytes.NewReader(buf))
	require.ErrorContains(t, err, "exceeds maximum allowed")
}

func TestPacketConnect(t *testing.T) {
	pkt, err := buildConnectPacket("test-client", "user1", "pass1", true, 60)
	require.NoError(t, err)
	require.NotEmpty(t, pkt)
	require.Equal(t, byte(PacketConnect<<4), pkt[0])

	r := bytes.NewReader(pkt)
	header, payload, err := readPacket(r)
	require.NoError(t, err)
	require.Equal(t, byte(PacketConnect<<4), header)

	// Verify protocol name "MQTT"
	protoLen := binary.BigEndian.Uint16(payload[0:2])
	require.Equal(t, uint16(4), protoLen)
	require.Equal(t, "MQTT", string(payload[2:6]))
	require.Equal(t, byte(0x04), payload[6]) // Protocol level 4 (MQTT 3.1.1)

	// CleanSession (0x02) | User (0x80) | Pass (0x40) = 0xC2
	require.Equal(t, byte(0xC2), payload[7])
}

func TestPacketPublishAndParse(t *testing.T) {
	pkt, err := buildPublishPacket("sensors/temperature", []byte("23.5C"), 0, true, 0)
	require.NoError(t, err)
	require.NotEmpty(t, pkt)

	r := bytes.NewReader(pkt)
	header, payload, err := readPacket(r)
	require.NoError(t, err)

	msg, err := parsePublish(header, payload)
	require.NoError(t, err)
	require.Equal(t, "sensors/temperature", msg.Topic)
	require.Equal(t, "23.5C", msg.Payload)
	require.Equal(t, 0, msg.QoS)
	require.True(t, msg.Retain)
}

func TestPacketSubscribe(t *testing.T) {
	pkt, err := buildSubscribePacket(42, "devices/#", 0)
	require.NoError(t, err)
	require.NotEmpty(t, pkt)
	require.Equal(t, byte((PacketSubscribe<<4)|0x02), pkt[0])

	r := bytes.NewReader(pkt)
	header, payload, err := readPacket(r)
	require.NoError(t, err)
	require.Equal(t, byte((PacketSubscribe<<4)|0x02), header)

	pid := binary.BigEndian.Uint16(payload[0:2])
	require.Equal(t, uint16(42), pid)

	subackPayload := []byte{0x00, 0x2A, 0x00} // PID 42, Success QoS 0
	subackPid, granted, err := parseSuback(subackPayload)
	require.NoError(t, err)
	require.Equal(t, uint16(42), subackPid)
	require.Equal(t, []byte{0x00}, granted)
}

func TestConnackReasons(t *testing.T) {
	require.Equal(t, "connection accepted", ConnackReason(ConnAccepted))
	require.Equal(t, "connection refused: bad user name or password", ConnackReason(ConnRefusedBadAuth))
	require.Equal(t, "connection refused: not authorized", ConnackReason(ConnRefusedNotAuthorized))
	require.Contains(t, ConnackReason(99), "connection refused: return code 99")
}

func TestRequestsHonourNetworkPolicy(t *testing.T) {
	execID := "mqtt-deny"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID, ExcludeTargets: []string{"203.0.113.50"}}))
	t.Cleanup(func() { protocolstate.Close(execID) })
	ctx := context.WithValue(context.Background(), "executionId", execID) //nolint:staticcheck

	_, err := IsMQTT(ctx, "203.0.113.50", 1883)
	require.Error(t, err)

	client := &Client{}
	_, err = client.Connect(ctx, "203.0.113.50", 1883, nil)
	require.Error(t, err)
}

func startMockMQTTBroker(t *testing.T) (net.Listener, int) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handleMockClient(conn)
		}
	}()

	return l, port
}

func handleMockClient(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	for {
		header, payload, err := readPacket(conn)
		if err != nil {
			return
		}

		packetType := header >> 4
		switch packetType {
		case PacketConnect:
			// Check if username is present (flags byte at offset 7)
			if len(payload) >= 8 {
				flags := payload[7]
				if (flags & 0x80) != 0 {
					// Check username
					offset := 10 // after proto(6) + level(1) + flags(1) + keepalive(2)
					if len(payload) >= offset+2 {
						clientLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
						offset += 2 + clientLen
						if len(payload) >= offset+2 {
							userLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
							user := string(payload[offset+2 : offset+2+userLen])
							if user == "baduser" {
								// Send CONNACK Refused Bad Auth
								_, _ = conn.Write([]byte{0x20, 0x02, 0x00, ConnRefusedBadAuth})
								return
							}
						}
					}
				}
			}
			// Send CONNACK Accepted
			_, _ = conn.Write([]byte{0x20, 0x02, 0x00, ConnAccepted})

		case PacketSubscribe:
			// Send SUBACK
			pid := binary.BigEndian.Uint16(payload[0:2])
			suback := []byte{0x90, 0x03, byte(pid >> 8), byte(pid & 0xFF), 0x00}
			_, _ = conn.Write(suback)

			// Publish test message
			pubPkt, err := buildPublishPacket("nuclei/alert", []byte("vuln-detected"), 0, false, 0)
			if err == nil {
				_, _ = conn.Write(pubPkt)
			}

		case PacketPublish:
			// QoS 0, no ack needed

		case PacketPingreq:
			// Send PINGRESP
			_, _ = conn.Write([]byte{PacketPingresp << 4, 0x00})

		case PacketDisconnect:
			return
		}
	}
}

func TestMockBrokerInteractions(t *testing.T) {
	execID := "mqtt-mock-test"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID}))
	t.Cleanup(func() { protocolstate.Close(execID) })
	ctx := context.WithValue(context.Background(), "executionId", execID) //nolint:staticcheck

	l, port := startMockMQTTBroker(t)
	defer func() { _ = l.Close() }()

	// 1. Test IsMQTT
	isMQTT, err := IsMQTT(ctx, "127.0.0.1", port)
	require.NoError(t, err)
	require.True(t, isMQTT)

	// 2. Test IsAnonymousAllowed
	anonAllowed, err := IsAnonymousAllowed(ctx, "127.0.0.1", port)
	require.NoError(t, err)
	require.True(t, anonAllowed)

	// 3. Test Client Connect Auth Failure
	badClient := &Client{}
	badRes, _ := badClient.ConnectAuth(ctx, "127.0.0.1", port, "baduser", "wrongpass")
	require.False(t, badRes.Success)
	require.Equal(t, int(ConnRefusedBadAuth), badRes.ReturnCode)

	// 4. Test Client Connect Success with default CleanSession preservation
	client := &Client{}
	res, err := client.Connect(ctx, "127.0.0.1", port, &ConnectOptions{KeepAlive: 70000})
	require.NoError(t, err)
	require.True(t, res.Success)
	require.Equal(t, int(ConnAccepted), res.ReturnCode)

	// 5. Test Ping
	alive, err := client.Ping(ctx)
	require.NoError(t, err)
	require.True(t, alive)

	// 6. Test Subscribe and Receive Message
	msgs, err := client.Subscribe(ctx, "nuclei/alert", 1)
	require.NoError(t, err)
	require.NotEmpty(t, msgs)
	require.Equal(t, "nuclei/alert", msgs[0].Topic)
	require.Equal(t, "vuln-detected", msgs[0].Payload)

	// 7. Test Publish
	pubOk, err := client.Publish(ctx, "nuclei/probe", "test payload")
	require.NoError(t, err)
	require.True(t, pubOk)

	// 8. Test Close and Double Close
	require.NoError(t, client.Close())
	require.NoError(t, client.Close())
}

func TestPasswordWithoutUsername(t *testing.T) {
	// MQTT 3.1.1 (MQTT-3.1.2-22): If Password flag is set, User Name flag MUST be set.
	pkt, err := buildConnectPacket("token-client", "", "my-secret-token", true, 60)
	require.NoError(t, err)

	r := bytes.NewReader(pkt)
	_, payload, err := readPacket(r)
	require.NoError(t, err)

	// CleanSession (0x02) | User (0x80) | Pass (0x40) = 0xC2
	require.Equal(t, byte(0xC2), payload[7])

	// The client ID comes right after the keep alive at payload[8:10], and the
	// username length follows it.
	clientIDLen := int(binary.BigEndian.Uint16(payload[10:12]))
	off := 12 + clientIDLen

	// Username length should be 0 (empty string)
	userLen := binary.BigEndian.Uint16(payload[off : off+2])
	require.Equal(t, uint16(0), userLen)
	off += 2

	// Password follows the username
	passLen := binary.BigEndian.Uint16(payload[off : off+2])
	require.Equal(t, uint16(len("my-secret-token")), passLen)
	off += 2
	require.Equal(t, "my-secret-token", string(payload[off:off+int(passLen)]))
}

// A window that closes in the middle of a PUBLISH must drop the connection.
// Keeping it would let the next read start inside that packet.
func TestSubscribePartialPacketClosesConnection(t *testing.T) {
	execID := "mqtt-partial-subscribe"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID}))
	t.Cleanup(func() { protocolstate.Close(execID) })
	ctx := context.WithValue(context.Background(), "executionId", execID) //nolint:staticcheck

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			header, payload, err := readPacket(conn)
			if err != nil {
				return
			}
			switch header >> 4 {
			case PacketConnect:
				_, _ = conn.Write([]byte{PacketConnack << 4, 0x02, 0x00, ConnAccepted})
			case PacketSubscribe:
				// SUBACK for the packet id, then a PUBLISH that promises 10 bytes
				// and sends 5. The client's window closes in the middle of it.
				_, _ = conn.Write([]byte{PacketSuback << 4, 0x03, payload[0], payload[1], 0x00})
				_, _ = conn.Write([]byte{PacketPublish << 4, 0x0a, 0x00, 0x03, 'a', '/', 'b'})
			}
		}
	}()

	client := &Client{}
	res, err := client.Connect(ctx, "127.0.0.1", port, nil)
	require.NoError(t, err)
	require.True(t, res.Success)

	msgs, err := client.Subscribe(ctx, "a/b", 1)
	require.NoError(t, err)
	require.Empty(t, msgs)
	require.Nil(t, client.conn, "a stream cut in the middle of a packet must not be reused")
}

func TestPingWithInFlightPublish(t *testing.T) {
	execID := "mqtt-ping-inflight"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID}))
	t.Cleanup(func() { protocolstate.Close(execID) })
	ctx := context.WithValue(context.Background(), "executionId", execID) //nolint:staticcheck

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		for {
			header, _, err := readPacket(conn)
			if err != nil {
				return
			}
			packetType := header >> 4
			switch packetType {
			case PacketConnect:
				_, _ = conn.Write([]byte{0x20, 0x02, 0x00, ConnAccepted})
			case PacketPingreq:
				// Send a PUBLISH packet first before PINGRESP
				pubPkt, _ := buildPublishPacket("sensors/temp", []byte("25.0"), 0, false, 0)
				_, _ = conn.Write(pubPkt)
				// Then send PINGRESP
				_, _ = conn.Write([]byte{PacketPingresp << 4, 0x00})
			case PacketDisconnect:
				return
			}
		}
	}()

	client := &Client{}
	res, err := client.Connect(ctx, "127.0.0.1", port, nil)
	require.NoError(t, err)
	require.True(t, res.Success)

	// Ping should skip the in-flight PUBLISH and successfully receive PINGRESP
	alive, err := client.Ping(ctx)
	require.NoError(t, err)
	require.True(t, alive)

	_ = client.Close()
}
