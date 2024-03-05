// Warning - This is generated code
package smb

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"

	"github.com/zmap/zgrab2/lib/smb/smb"
)

func memoizedconnectSMBInfoMode(host string, port int) (*smb.SMBLog, error) {
	hash := "connectSMBInfoMode" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connectSMBInfoMode(host, port)
	})
	if err != nil {
		return nil, err
	}
	if value, ok := v.(*smb.SMBLog); ok {
		return value, nil
	}

	return nil, errors.New("could not convert cached result")
}

func memoizedlistShares(host string, port int, user string, password string) ([]string, error) {
	hash := "listShares" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(user) + ":" + fmt.Sprint(password)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return listShares(host, port, user, password)
	})
	if err != nil {
		return []string{}, err
	}
	if value, ok := v.([]string); ok {
		return value, nil
	}

	return []string{}, errors.New("could not convert cached result")
}
