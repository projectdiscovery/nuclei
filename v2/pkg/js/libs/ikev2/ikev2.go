package ikev2

import (
	"io"

	"github.com/projectdiscovery/n3iwf/pkg/ike/message"
	"github.com/projectdiscovery/n3iwf/pkg/logger"
)

func init() {
	logger.Log.SetOutput(io.Discard)
}

// IKEMessage is the IKEv2 message
//
// IKEv2 implements a limited subset of IKEv2 Protocol, specifically
// the IKE_NOTIFY and IKE_NONCE payloads and the IKE_SA_INIT exchange.
type IKEMessage struct {
	InitiatorSPI uint64
	Version      uint8
	ExchangeType uint8
	Flags        uint8
	Payloads     []IKEPayload
}

// IKEPayload is the IKEv2 payload interface
//
// All the payloads like IKENotification, IKENonce, etc. implement
// this interface.
type IKEPayload interface {
	encode() (message.IKEPayload, error)
}

// IKEv2Notify is the IKEv2 Notification payload
type IKENotification struct {
	NotifyMessageType uint16
	NotificationData  []byte
}

// encode encodes the IKEv2 Notification payload
func (i *IKENotification) encode() (message.IKEPayload, error) {
	notify := message.Notification{
		NotifyMessageType: i.NotifyMessageType,
		NotificationData:  i.NotificationData,
	}
	return &notify, nil
}

const (
	// Notify message types
	IKE_NOTIFY_NO_PROPOSAL_CHOSEN = 14
	IKE_NOTIFY_USE_TRANSPORT_MODE = 16391

	IKE_VERSION_2 = 0x20

	// Exchange Type
	IKE_EXCHANGE_SA_INIT         = 34
	IKE_EXCHANGE_AUTH            = 35
	IKE_EXCHANGE_CREATE_CHILD_SA = 36
	IKE_EXCHANGE_INFORMATIONAL   = 37

	// Flags
	IKE_FLAGS_InitiatorBitCheck = 0x08
)

// IKENonce is the IKEv2 Nonce payload
type IKENonce struct {
	NonceData []byte
}

// encode encodes the IKEv2 Nonce payload
func (i *IKENonce) encode() (message.IKEPayload, error) {
	nonce := message.Nonce{
		NonceData: i.NonceData,
	}
	return &nonce, nil
}

// AppendPayload appends a payload to the IKE message
func (m *IKEMessage) AppendPayload(payload IKEPayload) {
	m.Payloads = append(m.Payloads, payload)
}

// Encode encodes the final IKE message
func (m *IKEMessage) Encode() ([]byte, error) {
	var payloads message.IKEPayloadContainer
	for _, payload := range m.Payloads {
		p, err := payload.encode()
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, p)
	}

	msg := &message.IKEMessage{
		InitiatorSPI: m.InitiatorSPI,
		Version:      m.Version,
		ExchangeType: m.ExchangeType,
		Flags:        m.Flags,
		Payloads:     payloads,
	}
	encoded, err := msg.Encode()
	return encoded, err
}
