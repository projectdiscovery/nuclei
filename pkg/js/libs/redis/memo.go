package redis

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedgetServerInfo(host string, port int) (string, error) {
	hash := "getServerInfo:" + host + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return getServerInfo(host, port)
	})
	if err != nil {
		return "", err
	}
	if value, ok := v.(string); ok {
		return value, nil
	}

	return "", errors.New("could not convert cached result to string")
}

func memoizedconnect(host string, port int, password string) (bool, error) {
	hash := "connect:" + host + ":" + fmt.Sprint(port) + ":" + password

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connect(host, port, password)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result to bool")
}

func memoizedgetServerInfoAuth(host string, port int, password string) (string, error) {
	hash := "getServerInfo:" + host + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return getServerInfoAuth(host, port, password)
	})
	if err != nil {
		return "", err
	}
	if value, ok := v.(string); ok {
		return value, nil
	}

	return "", errors.New("could not convert cached result to string")
}

func memoizedisAuthenticated(host string, port int) (bool, error) {
	hash := "isAuthenticated:" + host + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isAuthenticated(host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result to bool")
}
