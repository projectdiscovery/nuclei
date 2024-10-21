// Warning - This is generated code
package rdp

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisRDP(host string, port int) (IsRDPResponse, error) {
	hash := "isRDP" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isRDP(host, port)
	})
	if err != nil {
		return IsRDPResponse{}, err
	}
	if value, ok := v.(IsRDPResponse); ok {
		return value, nil
	}

	return IsRDPResponse{}, errors.New("could not convert cached result")
}

func memoizedcheckRDPAuth(host string, port int) (CheckRDPAuthResponse, error) {
	hash := "checkRDPAuth" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return checkRDPAuth(host, port)
	})
	if err != nil {
		return CheckRDPAuthResponse{}, err
	}
	if value, ok := v.(CheckRDPAuthResponse); ok {
		return value, nil
	}

	return CheckRDPAuthResponse{}, errors.New("could not convert cached result")
}
