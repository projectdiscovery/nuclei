// Warning - This is generated code
package smb

import (
	"errors"
	"fmt"

	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedcollectSMBv2Metadata(executionId string, host string, port int, timeout time.Duration) (*plugins.ServiceSMB, error) {
	hash := "collectSMBv2Metadata" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(timeout)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return collectSMBv2Metadata(executionId, host, port, timeout)
	})
	if err != nil {
		return nil, err
	}
	if value, ok := v.(*plugins.ServiceSMB); ok {
		return value, nil
	}

	return nil, errors.New("could not convert cached result")
}
