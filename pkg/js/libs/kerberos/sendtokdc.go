package kerberos

// the following code is adapted from the original library
// https://github.com/jcmturner/gokrb5/blob/855dbc707a37a21467aef6c0245fcf3328dc39ed/v8/client/network.go
// it is copied here because the library does not export "SendToKDC()"

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// sendtokdc.go deals with actual sending and receiving responses from KDC
// SendToKDC sends a message to the KDC and returns the response.
// It first tries to send the message over TCP, and if that fails, it falls back to UDP.(and vice versa)
// @example
// ```javascript
// const kerberos = require('nuclei/kerberos');
// const client = new kerberos.Client('acme.com');
// const response = kerberos.SendToKDC(client, 'message');
// ```
func SendToKDC(kclient *Client, msg string) (string, error) {
	if kclient == nil || kclient.nj == nil || kclient.Krb5Config == nil || kclient.Realm == "" {
		return "", fmt.Errorf("kerberos client is not initialized")
	}
	if kclient.config.timeout == 0 {
		kclient.config.timeout = 5 // default timeout 5 seconds
	}
	var response []byte
	var err error

	response, err = sendToKDCTcp(kclient, msg)
	if err == nil {
		// if it related to tcp
		bin, err := CheckKrbError(response)
		if err == nil {
			return string(bin), nil
		}
		// if it is krb error no need to do udp
		if e, ok := err.(messages.KRBError); ok {
			return string(response), e
		}
	}

	// fallback to udp
	response, err = sendToKDCUdp(kclient, msg)
	if err == nil {
		// if it related to udp
		bin, err := CheckKrbError(response)
		if err == nil {
			return string(bin), nil
		}
	}
	return string(response), err
}

// sendToKDCTcp sends a message to the KDC via TCP.
func sendToKDCTcp(kclient *Client, msg string) ([]byte, error) {
	_, kdcs, err := kclient.Krb5Config.GetKDCs(kclient.Realm, true)
	kclient.nj.HandleError(err, "error getting KDCs")
	kclient.nj.Require(len(kdcs) > 0, "no KDCs found")

	var errs []string
	for i := 1; i <= len(kdcs); i++ {
		host, port, err := net.SplitHostPort(kdcs[i])
		if err == nil && kclient.config.ip != "" {
			// use that ip address instead of realm/domain for resolving
			host = kclient.config.ip
		}
		tcpConn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, port))
		if err != nil {
			errs = append(errs, fmt.Sprintf("error establishing connection to %s: %v", kdcs[i], err))
			continue
		}
		defer tcpConn.Close()
		_ = tcpConn.SetDeadline(time.Now().Add(time.Duration(kclient.config.timeout) * time.Second)) //read and write deadline
		rb, err := sendTCP(tcpConn.(*net.TCPConn), []byte(msg))
		if err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
	}
	return nil, nil
}

// sendToKDCUdp sends a message to the KDC via UDP.
func sendToKDCUdp(kclient *Client, msg string) ([]byte, error) {
	_, kdcs, err := kclient.Krb5Config.GetKDCs(kclient.Realm, true)
	kclient.nj.HandleError(err, "error getting KDCs")
	kclient.nj.Require(len(kdcs) > 0, "no KDCs found")

	var errs []string
	for i := 1; i <= len(kdcs); i++ {
		host, port, err := net.SplitHostPort(kdcs[i])
		if err == nil && kclient.config.ip != "" {
			// use that ip address instead of realm/domain for resolving
			host = kclient.config.ip
		}
		udpConn, err := protocolstate.Dialer.Dial(context.TODO(), "udp", net.JoinHostPort(host, port))
		if err != nil {
			errs = append(errs, fmt.Sprintf("error establishing connection to %s: %v", kdcs[i], err))
			continue
		}
		defer udpConn.Close()
		_ = udpConn.SetDeadline(time.Now().Add(time.Duration(kclient.config.timeout) * time.Second)) //read and write deadline
		rb, err := sendUDP(udpConn.(*net.UDPConn), []byte(msg))
		if err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	if len(errs) > 0 {
		// fallback to tcp
		return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
	}
	return nil, nil
}

// sendUDP sends bytes to connection over UDP.
func sendUDP(conn *net.UDPConn, b []byte) ([]byte, error) {
	var r []byte
	defer conn.Close()
	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to (%s): %v", conn.RemoteAddr().String(), err)
	}
	udpbuf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(udpbuf)
	r = udpbuf[:n]
	if err != nil {
		return r, fmt.Errorf("sending over UDP failed to %s: %v", conn.RemoteAddr().String(), err)
	}
	if len(r) < 1 {
		return r, fmt.Errorf("no response data from %s", conn.RemoteAddr().String())
	}
	return r, nil
}

// sendTCP sends bytes to connection over TCP.
func sendTCP(conn *net.TCPConn, b []byte) ([]byte, error) {
	defer conn.Close()
	var r []byte
	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
	hb := make([]byte, 4)
	binary.BigEndian.PutUint32(hb, uint32(len(b)))
	b = append(hb, b...)

	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %v", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, 4)
	_, err = conn.Read(sh)
	if err != nil {
		return r, fmt.Errorf("error reading response size header: %v", err)
	}
	s := binary.BigEndian.Uint32(sh)

	rb := make([]byte, s)
	_, err = io.ReadFull(conn, rb)
	if err != nil {
		return r, fmt.Errorf("error reading response: %v", err)
	}
	if len(rb) < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}
	return rb, nil
}

// CheckKrbError checks if the response bytes from the KDC are a KRBError.
func CheckKrbError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}

// TGStoHashcat converts a TGS to a hashcat format.
func TGStoHashcat(tgs messages.Ticket, username string) (string, error) {
	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		tgs.EncPart.EType,
		username,
		tgs.Realm,
		strings.Join(tgs.SName.NameString[:], "/"),
		hex.EncodeToString(tgs.EncPart.Cipher[:16]),
		hex.EncodeToString(tgs.EncPart.Cipher[16:]),
	), nil
}

// ASRepToHashcat converts an AS-REP message to a hashcat format
func ASRepToHashcat(asrep messages.ASRep) (string, error) {
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		asrep.EncPart.EType,
		asrep.CName.PrincipalNameString(),
		asrep.CRealm,
		hex.EncodeToString(asrep.EncPart.Cipher[:16]),
		hex.EncodeToString(asrep.EncPart.Cipher[16:])), nil
}
