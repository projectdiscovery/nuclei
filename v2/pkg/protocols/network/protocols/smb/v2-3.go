package smb

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/LeakIX/go-smb2"
	"github.com/LeakIX/ntlmssp"
	"github.com/pkg/errors"
)

func connectWithCredentials(host, username, password, domain string, port, timeout int) (bool, error) {
	deadline := time.Duration(timeout) * time.Second

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), deadline)
	if err != nil {
		return false, errors.Wrap(err, "could not dial")
	}
	defer conn.Close()

	var options []func(*ntlmssp.Client) error
	options = append(options, ntlmssp.SetCompatibilityLevel(ntlmssp.DefaultClientCompatibilityLevel))
	if domain != "" {
		options = append(options, ntlmssp.SetDomain(domain))
	}
	if username != "" || password != "" {
		options = append(options, ntlmssp.SetUserInfo(username, password))
	}
	ntlmsspClient, err := ntlmssp.NewClient(options...)
	if err != nil {
		return false, errors.Wrap(err, "could not create ntlmssp client")
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMSSPInitiator{
			NTLMSSPClient: ntlmsspClient,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	s, err := d.DialContext(ctx, conn)
	if err != nil {
		return false, errors.Wrap(err, "could not dial smb server")
	}
	_ = s.Logoff()

	return true, nil
}
