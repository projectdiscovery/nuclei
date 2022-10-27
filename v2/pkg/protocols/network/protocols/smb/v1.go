package smb

import (
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/smb/smb"
)

func connectWithCredentialsV1(host, username, password, domain string, port, timeout int) (bool, error) {
	deadline := time.Duration(timeout) * time.Second

	options := smb.Options{
		Host:     host,
		Port:     port,
		User:     username,
		Password: password,
		Domain:   domain,
		Timeout:  deadline,
	}
	session, err := smb.NewSession(options, false)
	if err != nil {
		return false, errors.Wrap(err, "could not create smb session")
	}
	session.Close()

	if session.IsAuthenticated {
		return true, nil
	}
	return false, nil
}
