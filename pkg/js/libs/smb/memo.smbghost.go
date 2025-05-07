// Warning - This is generated code
package smb

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizeddetectSMBGhost(executionId string, host string, port int) (bool, error) {
	hash := "detectSMBGhost" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return detectSMBGhost(executionId, host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}
