// Warning - This is generated code
package redis

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedgetServerInfo(executionId string, host string, port int) (string, error) {
	hash := "getServerInfo" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return getServerInfo(executionId, host, port)
	})
	if err != nil {
		return "", err
	}
	if value, ok := v.(string); ok {
		return value, nil
	}

	return "", errors.New("could not convert cached result")
}

func memoizedconnect(executionId string, host string, port int, password string) (bool, error) {
	hash := "connect" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(password)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connect(executionId, host, port, password)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}

func memoizedgetServerInfoAuth(executionId string, host string, port int, password string) (string, error) {
	hash := "getServerInfoAuth" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(password)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return getServerInfoAuth(executionId, host, port, password)
	})
	if err != nil {
		return "", err
	}
	if value, ok := v.(string); ok {
		return value, nil
	}

	return "", errors.New("could not convert cached result")
}

func memoizedisAuthenticated(executionId string, host string, port int) (bool, error) {
	hash := "isAuthenticated" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isAuthenticated(executionId, host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}
