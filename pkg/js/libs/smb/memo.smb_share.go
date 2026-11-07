// Warning - This is generated code
package smb

import (
	"context"
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedlistShares(ctx context.Context, executionId string, host string, port int, user string, password string) ([]string, error) {
	hash := "listShares" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(user) + ":" + fmt.Sprint(password)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return listShares(ctx, executionId, host, port, user, password)
	})
	if err != nil {
		return []string{}, err
	}
	if value, ok := v.([]string); ok {
		return value, nil
	}

	return []string{}, errors.New("could not convert cached result")
}

func memoizedlistDir(ctx context.Context, executionId string, host string, port int, user string, password string, share string, dir string) ([]ShareEntry, error) {
	hash := "listDir" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(user) + ":" + fmt.Sprint(password) + ":" + fmt.Sprint(share) + ":" + fmt.Sprint(dir)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return listDir(ctx, executionId, host, port, user, password, share, dir)
	})
	if err != nil {
		return []ShareEntry{}, err
	}
	if value, ok := v.([]ShareEntry); ok {
		return value, nil
	}

	return []ShareEntry{}, errors.New("could not convert cached result")
}

func memoizedreadFile(ctx context.Context, executionId string, host string, port int, user string, password string, share string, filePath string) (string, error) {
	hash := "readFile" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(user) + ":" + fmt.Sprint(password) + ":" + fmt.Sprint(share) + ":" + fmt.Sprint(filePath)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return readFile(ctx, executionId, host, port, user, password, share, filePath)
	})
	if err != nil {
		return "", err
	}
	if value, ok := v.(string); ok {
		return value, nil
	}

	return "", errors.New("could not convert cached result")
}

func memoizedlistTree(ctx context.Context, executionId string, host string, port int, user string, password string, share string, dir string) ([]ShareEntry, error) {
	hash := "listTree" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(user) + ":" + fmt.Sprint(password) + ":" + fmt.Sprint(share) + ":" + fmt.Sprint(dir)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return listTree(ctx, executionId, host, port, user, password, share, dir)
	})
	if err != nil {
		return []ShareEntry{}, err
	}
	if value, ok := v.([]ShareEntry); ok {
		return value, nil
	}

	return []ShareEntry{}, errors.New("could not convert cached result")
}
