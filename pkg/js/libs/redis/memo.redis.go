// Warning - This is generated code
package redis

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedgetServerInfo(host string, port int) (string, error) {
	hash := "getServerInfo" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return getServerInfo(host, port)
	})
	if err != nil {
		return "", err
	}
	if value, ok := v.(string); ok {
		return value, nil
	}

	return "", errors.New("could not convert cached result")
}

func memoizedconnect(host string, port int, password string) (bool, error) {
	hash := "connect" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(password)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connect(host, port, password)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}

func memoizedgetServerInfoAuth(host string, port int, password string) (string, error) {
	hash := "getServerInfoAuth" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(password)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return getServerInfoAuth(host, port, password)
	})
	if err != nil {
		return "", err
	}
	if value, ok := v.(string); ok {
		return value, nil
	}

	return "", errors.New("could not convert cached result")
}

func memoizedisAuthenticated(host string, port int) (bool, error) {
	hash := "isAuthenticated" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isAuthenticated(host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}
