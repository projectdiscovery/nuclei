package winrm

import (
	"context"
	"time"

	"github.com/masterzen/winrm"
	"github.com/pkg/errors"
)

type noopWriter struct{}

func (n *noopWriter) Write(p []byte) (int, error) {
	return 0, nil
}

// ConnectWithCredentials connects to a server with credentials
func ConnectWithCredentials(host, username, password string, port, timeout int, https bool) (bool, error) {
	endpoint := winrm.NewEndpoint(host, port, https, true, nil, nil, nil, time.Duration(timeout)*time.Second)
	client, err := winrm.NewClient(endpoint, username, password)
	if err != nil {
		return false, errors.Wrap(err, "could not connect to winrm")
	}
	writer := &noopWriter{}
	res, err := client.RunWithContext(context.Background(), "echo ISOK", writer, writer)
	if err != nil {
		return false, errors.Wrap(err, "could not run winrm")
	}
	if res == 0 {
		return true, nil
	}
	return false, nil
}
