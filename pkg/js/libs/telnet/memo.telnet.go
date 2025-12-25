// Warning - This is generated code
package telnet

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisTelnet(executionId string, host string, port int) (IsTelnetResponse, error) {
	hash := "isTelnet" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isTelnet(executionId, host, port)
	})
	if err != nil {
		return IsTelnetResponse{}, err
	}
	if value, ok := v.(IsTelnetResponse); ok {
		return value, nil
	}

	return IsTelnetResponse{}, errors.New("could not convert cached result")
}
