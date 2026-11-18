// Warning - This is generated code
package redis

import (
	"context"
	"errors"

	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedgetServerInfo(ctx context.Context, executionId string, host string, port int) (string, error) {
	hash := "getServerInfo" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return getServerInfo(ctx, executionId, host, port)
	})
	if err != nil {
		return "", err
	}
	if value, ok := v.(string); ok {
		return value, nil
	}

	return "", errors.New("could not convert cached result")
}

func memoizedconnect(ctx context.Context, executionId string, host string, port int, password string) (bool, error) {
	hash := "connect" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(password)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connect(ctx, executionId, host, port, password)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}

func memoizedgetServerInfoAuth(ctx context.Context, executionId string, host string, port int, password string) (string, error) {
	hash := "getServerInfoAuth" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(password)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return getServerInfoAuth(ctx, executionId, host, port, password)
	})
	if err != nil {
		return "", err
	}
	if value, ok := v.(string); ok {
		return value, nil
	}

	return "", errors.New("could not convert cached result")
}

func memoizedisAuthenticated(ctx context.Context, executionId string, host string, port int) (bool, error) {
	hash := "isAuthenticated" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isAuthenticated(ctx, executionId, host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}
