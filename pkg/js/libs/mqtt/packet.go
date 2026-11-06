package mqtt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Limits to prevent DoS and buffer overflows
const (
	MaxStringLength    = 65535
	MaxRemainingLength = 268435455
	MaxPacketSize      = 10 * 1024 * 1024 // 10MB limit on incoming packets
)

// MQTT 3.1.1 Control Packet Types
const (
	PacketConnect    byte = 1
	PacketConnack    byte = 2
	PacketPublish    byte = 3
	PacketPuback     byte = 4
	PacketPubrec     byte = 5
	PacketPubrel     byte = 6
	PacketPubcomp    byte = 7
	PacketSubscribe  byte = 8
	PacketSuback     byte = 9
	PacketUnsub      byte = 10
	PacketUnsuback   byte = 11
	PacketPingreq    byte = 12
	PacketPingresp   byte = 13
	PacketDisconnect byte = 14
)

// CONNACK Return Codes (MQTT 3.1.1 table 3.1)
const (
	ConnAccepted                    byte = 0
	ConnRefusedUnacceptableProtocol byte = 1
	ConnRefusedIdentifierRejected   byte = 2
	ConnRefusedServerUnavailable    byte = 3
	ConnRefusedBadAuth              byte = 4
	ConnRefusedNotAuthorized        byte = 5
)

// ConnackReason returns a human-readable description for CONNACK return codes.
func ConnackReason(code byte) string {
	switch code {
	case ConnAccepted:
		return "connection accepted"
	case ConnRefusedUnacceptableProtocol:
		return "connection refused: unacceptable protocol version"
	case ConnRefusedIdentifierRejected:
		return "connection refused: identifier rejected"
	case ConnRefusedServerUnavailable:
		return "connection refused: server unavailable"
	case ConnRefusedBadAuth:
		return "connection refused: bad user name or password"
	case ConnRefusedNotAuthorized:
		return "connection refused: not authorized"
	default:
		return fmt.Sprintf("connection refused: return code %d", code)
	}
}

// encodeVarLength encodes a length integer as an MQTT variable byte integer.
func encodeVarLength(length int) ([]byte, error) {
	if length < 0 || length > MaxRemainingLength {
		return nil, fmt.Errorf("remaining length %d exceeds MQTT max %d", length, MaxRemainingLength)
	}
	var out []byte
	for {
		encodedByte := byte(length % 128)
		length /= 128
		if length > 0 {
			encodedByte |= 128
		}
		out = append(out, encodedByte)
		if length == 0 {
			break
		}
	}
	return out, nil
}

// decodeVarLength decodes an MQTT variable byte integer from reader.
func decodeVarLength(r io.Reader) (int, error) {
	multiplier := 1
	value := 0
	buf := make([]byte, 1)
	for i := 0; i < 4; i++ {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		encodedByte := buf[0]
		value += int(encodedByte&127) * multiplier
		if multiplier > 128*128*128 {
			return 0, errors.New("malformed remaining length")
		}
		multiplier *= 128
		if encodedByte&128 == 0 {
			return value, nil
		}
	}
	return 0, errors.New("malformed remaining length")
}

// encodeString encodes a UTF-8 string with a 2-byte big-endian length prefix.
func encodeString(s string) ([]byte, error) {
	b := []byte(s)
	if len(b) > MaxStringLength {
		return nil, fmt.Errorf("string length %d exceeds MQTT max %d", len(b), MaxStringLength)
	}
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(b)))
	copy(out[2:], b)
	return out, nil
}

// buildConnectPacket constructs an MQTT 3.1.1 CONNECT packet.
func buildConnectPacket(clientID, username, password string, cleanSession bool, keepAlive uint16) ([]byte, error) {
	var varHeader []byte
	protoName, err := encodeString("MQTT")
	if err != nil {
		return nil, err
	}
	varHeader = append(varHeader, protoName...)
	varHeader = append(varHeader, 0x04) // Protocol Level: 4 (MQTT 3.1.1)

	// Connect Flags
	var flags byte
	if cleanSession {
		flags |= 0x02
	}
	// Per MQTT 3.1.1 spec (MQTT-3.1.2-22): If the User Name Flag is 0, the Password Flag MUST be 0.
	// If a password is provided, the User Name Flag MUST be set (encoding an empty username if omitted).
	hasUsername := username != "" || password != ""
	if hasUsername {
		flags |= 0x80
	}
	if password != "" {
		flags |= 0x40
	}
	varHeader = append(varHeader, flags)

	// Keep Alive (2 bytes big endian)
	ka := make([]byte, 2)
	binary.BigEndian.PutUint16(ka, keepAlive)
	varHeader = append(varHeader, ka...)

	// Payload
	var payload []byte
	cidBytes, err := encodeString(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid clientID: %w", err)
	}
	payload = append(payload, cidBytes...)

	if hasUsername {
		userBytes, err := encodeString(username)
		if err != nil {
			return nil, fmt.Errorf("invalid username: %w", err)
		}
		payload = append(payload, userBytes...)
	}
	if password != "" {
		passBytes, err := encodeString(password)
		if err != nil {
			return nil, fmt.Errorf("invalid password: %w", err)
		}
		payload = append(payload, passBytes...)
	}

	remainingLength := len(varHeader) + len(payload)
	lenBytes, err := encodeVarLength(remainingLength)
	if err != nil {
		return nil, err
	}

	var pkt []byte
	pkt = append(pkt, PacketConnect<<4)
	pkt = append(pkt, lenBytes...)
	pkt = append(pkt, varHeader...)
	pkt = append(pkt, payload...)
	return pkt, nil
}

// buildSubscribePacket constructs an MQTT 3.1.1 SUBSCRIBE packet for a single topic.
func buildSubscribePacket(packetID uint16, topic string, qos byte) ([]byte, error) {
	var varHeader [2]byte
	binary.BigEndian.PutUint16(varHeader[:], packetID)

	topicBytes, err := encodeString(topic)
	if err != nil {
		return nil, fmt.Errorf("invalid topic: %w", err)
	}

	var payload []byte
	payload = append(payload, topicBytes...)
	payload = append(payload, qos&0x03)

	remainingLength := len(varHeader) + len(payload)
	lenBytes, err := encodeVarLength(remainingLength)
	if err != nil {
		return nil, err
	}

	var pkt []byte
	// SUBSCRIBE fixed header flags must be 0010 (0x02)
	pkt = append(pkt, (PacketSubscribe<<4)|0x02)
	pkt = append(pkt, lenBytes...)
	pkt = append(pkt, varHeader[:]...)
	pkt = append(pkt, payload...)
	return pkt, nil
}

// buildPublishPacket constructs an MQTT 3.1.1 PUBLISH packet.
func buildPublishPacket(topic string, payload []byte, qos byte, retain bool, packetID uint16) ([]byte, error) {
	headerByte := (PacketPublish << 4)
	if retain {
		headerByte |= 0x01
	}
	headerByte |= (qos & 0x03) << 1

	topicBytes, err := encodeString(topic)
	if err != nil {
		return nil, fmt.Errorf("invalid topic: %w", err)
	}

	var varHeader []byte
	varHeader = append(varHeader, topicBytes...)
	if qos > 0 {
		pid := make([]byte, 2)
		binary.BigEndian.PutUint16(pid, packetID)
		varHeader = append(varHeader, pid...)
	}

	remainingLength := len(varHeader) + len(payload)
	lenBytes, err := encodeVarLength(remainingLength)
	if err != nil {
		return nil, err
	}

	var pkt []byte
	pkt = append(pkt, headerByte)
	pkt = append(pkt, lenBytes...)
	pkt = append(pkt, varHeader...)
	pkt = append(pkt, payload...)
	return pkt, nil
}

// buildPingreqPacket constructs an MQTT PINGREQ packet.
func buildPingreqPacket() []byte {
	return []byte{PacketPingreq << 4, 0x00}
}

// buildDisconnectPacket constructs an MQTT DISCONNECT packet.
func buildDisconnectPacket() []byte {
	return []byte{PacketDisconnect << 4, 0x00}
}

// errBrokenStream means a read failed after part of a packet was consumed, or
// a packet was refused, so the next read would start in the middle of a packet.
// The connection must not be used again.
var errBrokenStream = errors.New("MQTT stream is out of sync")

// readPacket reads a full MQTT packet from reader, rejecting packets over MaxPacketSize.
// Failures before the first byte is read are returned as they are. Failures after
// it wrap errBrokenStream.
func readPacket(r io.Reader) (headerByte byte, payload []byte, err error) {
	var header [1]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	length, err := decodeVarLength(r)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", errBrokenStream, err)
	}
	if length > MaxPacketSize {
		return 0, nil, fmt.Errorf("%w: MQTT packet length %d exceeds maximum allowed %d", errBrokenStream, length, MaxPacketSize)
	}
	buf := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, nil, fmt.Errorf("%w: %w", errBrokenStream, err)
		}
	}
	return header[0], buf, nil
}

// parseConnack decodes a CONNACK variable header.
func parseConnack(payload []byte) (sessionPresent bool, returnCode byte, err error) {
	if len(payload) < 2 {
		return false, 0, errors.New("short CONNACK response")
	}
	sessionPresent = (payload[0] & 0x01) != 0
	returnCode = payload[1]
	return sessionPresent, returnCode, nil
}

// parseSuback decodes a SUBACK packet payload.
func parseSuback(payload []byte) (packetID uint16, grantedQoS []byte, err error) {
	if len(payload) < 3 {
		return 0, nil, errors.New("short SUBACK response")
	}
	packetID = binary.BigEndian.Uint16(payload[0:2])
	grantedQoS = payload[2:]
	return packetID, grantedQoS, nil
}

// parsePublish decodes a PUBLISH packet.
func parsePublish(headerByte byte, body []byte) (*Message, error) {
	qos := (headerByte >> 1) & 0x03
	retain := (headerByte & 0x01) != 0

	if len(body) < 2 {
		return nil, errors.New("short PUBLISH packet")
	}
	topicLen := int(binary.BigEndian.Uint16(body[0:2]))
	if len(body) < 2+topicLen {
		return nil, errors.New("short PUBLISH topic")
	}
	topic := string(body[2 : 2+topicLen])
	offset := 2 + topicLen

	if qos > 0 {
		if len(body) < offset+2 {
			return nil, errors.New("short PUBLISH packet ID")
		}
		offset += 2
	}

	payload := string(body[offset:])
	return &Message{
		Topic:   topic,
		Payload: payload,
		QoS:     int(qos),
		Retain:  retain,
	}, nil
}
