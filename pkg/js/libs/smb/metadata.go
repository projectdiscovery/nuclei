package smb

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/services/smb"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// collectSMBv2Metadata collects metadata for SMBv2 services.
func collectSMBv2Metadata(host string, port int, timeout time.Duration) (*plugins.ServiceSMB, error) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	metadata, err := smb.DetectSMBv2(conn, timeout)
	if err != nil {
		return nil, err
	}
	return metadata, nil
}
