package ikev2

import (
	"fmt"
	"io"

	"github.com/projectdiscovery/n3iwf/pkg/ike/message"
	"github.com/projectdiscovery/n3iwf/pkg/logger"
)

func init() {
	logger.Log.SetOutput(io.Discard)
}

type (
	// IKEMessage is the IKEv2 message
	//
	// IKEv2 implements a limited subset of IKEv2 Protocol, specifically
	// the IKE_NOTIFY and IKE_NONCE payloads and the IKE_SA_INIT exchange.
	IKEMessage struct {
		InitiatorSPI uint64
		Version      uint8
		ExchangeType uint8
		Flags        uint8
		payloads     []IKEPayload
	}
)

// AppendPayload appends a payload to the IKE message
// payload can be any of the payloads like IKENotification, IKENonce, etc.
// @example
// ```javascript
// const ikev2 = require('nuclei/ikev2');
// const message = new ikev2.IKEMessage();
// const nonce = new ikev2.IKENonce();
// nonce.NonceData = [1, 2, 3];
// message.AppendPayload(nonce);
// ```
func (m *IKEMessage) AppendPayload(payload any) error {
	if _, ok := payload.(IKEPayload); !ok {
		return fmt.Errorf("invalid payload type only types defined in ikev module like IKENotification, IKENonce, etc. are allowed")
	}
	m.payloads = append(m.payloads, payload.(IKEPayload))
	return nil
}

// Encode encodes the final IKE message
// @example
// ```javascript
// const ikev2 = require('nuclei/ikev2');
// const message = new ikev2.IKEMessage();
// const nonce = new ikev2.IKENonce();
// nonce.NonceData = [1, 2, 3];
// message.AppendPayload(nonce);
// log(message.Encode());
// ```
func (m *IKEMessage) Encode() ([]byte, error) {
	var payloads message.IKEPayloadContainer
	for _, payload := range m.payloads {
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

// IKEPayload is the IKEv2 payload interface
// All the payloads like IKENotification, IKENonce, etc. implement
// this interface.
type IKEPayload interface {
	encode() (message.IKEPayload, error)
}

type (
	// IKEv2Notify is the IKEv2 Notification payload
	// this implements the IKEPayload interface
	// @example
	// ```javascript
	// const ikev2 = require('nuclei/ikev2');
	// const notify = new ikev2.IKENotification();
	// notify.NotifyMessageType = ikev2.IKE_NOTIFY_NO_PROPOSAL_CHOSEN;
	// notify.NotificationData = [1, 2, 3];
	// ```
	IKENotification struct {
		NotifyMessageType uint16
		NotificationData  []byte
	}
)

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

type (
	// IKENonce is the IKEv2 Nonce payload
	// this implements the IKEPayload interface
	// @example
	// ```javascript
	// const ikev2 = require('nuclei/ikev2');
	// const nonce = new ikev2.IKENonce();
	// nonce.NonceData = [1, 2, 3];
	// ```
	IKENonce struct {
		NonceData []byte
	}
)

// encode encodes the IKEv2 Nonce payload
func (i *IKENonce) encode() (message.IKEPayload, error) {
	nonce := message.Nonce{
		NonceData: i.NonceData,
	}
	return &nonce, nil
}
