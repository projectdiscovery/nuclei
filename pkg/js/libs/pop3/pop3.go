package pop3

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/pop3"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// IsPOP3Response is the response from the IsPOP3 function.
	// this is returned by IsPOP3 function.
	// @example
	// ```javascript
	// const pop3 = require('nuclei/pop3');
	// const isPOP3 = pop3.IsPOP3('acme.com', 110);
	// log(toJSON(isPOP3));
	// ```
	IsPOP3Response struct {
		IsPOP3 bool
		Banner string
	}
)

// IsPOP3 checks if a host is running a POP3 server.
// @example
// ```javascript
// const pop3 = require('nuclei/pop3');
// const isPOP3 = pop3.IsPOP3('acme.com', 110);
// log(toJSON(isPOP3));
// ```
func IsPOP3(host string, port int) (IsPOP3Response, error) {
	return memoizedisPoP3(host, port)
}

// @memo
func isPoP3(host string, port int) (IsPOP3Response, error) {
	resp := IsPOP3Response{}

	timeout := 5 * time.Second
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return resp, err
	}
	defer conn.Close()

	pop3Plugin := pop3.POP3Plugin{}
	service, err := pop3Plugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return resp, err
	}
	if service == nil {
		return resp, nil
	}
	resp.Banner = service.Metadata().(plugins.ServicePOP3).Banner
	resp.IsPOP3 = true
	return resp, nil
}
