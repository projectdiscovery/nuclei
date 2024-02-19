// Warning - This is generated code
package vnc

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisVnc(host string, port int) (IsVNCResponse, error) {
	hash := "isVnc" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isVnc(host, port)
	})
	if err != nil {
		return IsVNCResponse{}, err
	}
	if value, ok := v.(IsVNCResponse); ok {
		return value, nil
	}

	return IsVNCResponse{}, errors.New("could not convert cached result")
}
