package mqtt

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestVarLengthEncoding(t *testing.T) {
	testCases := []int{0, 1, 64, 127, 128, 16383, 16384, 2097151}
	for _, tc := range testCases {
		encoded := encodeVarLength(tc)
		decoded, err := decodeVarLength(bytes.NewReader(encoded))
		require.NoError(t, err)
		require.Equal(t, tc, decoded)
	}
}

func TestPacketConnect(t *testing.T) {
	pkt := buildConnectPacket("test-client", "user1", "pass1", true, 60)
	require.NotEmpty(t, pkt)
	require.Equal(t, (PacketConnect<<4)|0x00, pkt[0])

	r := bytes.NewReader(pkt)
	header, payload, err := readPacket(r)
	require.NoError(t, err)
	require.Equal(t, (PacketConnect<<4)|0x00, header)

	// Verify protocol name "MQTT"
	protoLen := binary.BigEndian.Uint16(payload[0:2])
	require.Equal(t, uint16(4), protoLen)
	require.Equal(t, "MQTT", string(payload[2:6]))
	require.Equal(t, byte(0x04), payload[6]) // Protocol level 4 (MQTT 3.1.1)

	// CleanSession (0x02) | User (0x80) | Pass (0x40) = 0xC2
	require.Equal(t, byte(0xC2), payload[7])
}

func TestPacketPublishAndParse(t *testing.T) {
	pkt := buildPublishPacket("sensors/temperature", []byte("23.5C"), 0, true, 0)
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
	pkt := buildSubscribePacket(42, "devices/#", 0)
	require.NotEmpty(t, pkt)
	require.Equal(t, (PacketSubscribe<<4)|0x02, pkt[0])

	r := bytes.NewReader(pkt)
	header, payload, err := readPacket(r)
	require.NoError(t, err)
	require.Equal(t, (PacketSubscribe<<4)|0x02, header)

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
	ctx := context.WithValue(context.Background(), "executionId", execID)

	_, err := IsMQTT(ctx, "203.0.113.50", 1883)
	require.ErrorContains(t, err, "network policy")

	client := &Client{}
	_, err = client.Connect(ctx, "203.0.113.50", 1883, nil)
	require.ErrorContains(t, err, "network policy")
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
	defer conn.Close()

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
			pubPkt := buildPublishPacket("nuclei/alert", []byte("vuln-detected"), 0, false, 0)
			_, _ = conn.Write(pubPkt)

		case PacketPublish:
			// QoS 0, no ack needed

		case PacketPingreq:
			// Send PINGRESP
			_, _ = conn.Write([]byte{0xD0, 0x00})

		case PacketDisconnect:
			return
		}
	}
}

func TestMockBrokerInteractions(t *testing.T) {
	l, port := startMockMQTTBroker(t)
	defer l.Close()

	ctx := context.Background()

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

	// 4. Test Client Connect Success
	client := &Client{}
	res, err := client.Connect(ctx, "127.0.0.1", port, nil)
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
