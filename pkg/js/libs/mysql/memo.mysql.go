// Warning - This is generated code
package mysql

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisMySQL(executionId string, host string, port int) (bool, error) {
	hash := "isMySQL" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isMySQL(executionId, host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}

func memoizedfingerprintMySQL(executionId string, host string, port int) (MySQLInfo, error) {
	hash := "fingerprintMySQL" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return fingerprintMySQL(executionId, host, port)
	})
	if err != nil {
		return MySQLInfo{}, err
	}
	if value, ok := v.(MySQLInfo); ok {
		return value, nil
	}

	return MySQLInfo{}, errors.New("could not convert cached result")
}
