// Warning - This is generated code
package smb

import (
	"context"
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/zmap/zgrab2/lib/smb/smb"
)

func memoizedconnectSMBInfoMode(ctx context.Context, executionId string, host string, port int) (*smb.SMBLog, error) {
	hash := "connectSMBInfoMode" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connectSMBInfoMode(ctx, executionId, host, port)
	})
	if err != nil {
		return nil, err
	}
	if value, ok := v.(*smb.SMBLog); ok {
		return value, nil
	}

	return nil, errors.New("could not convert cached result")
}

func memoizedlistShares(ctx context.Context, executionId string, host string, port int, user string, password string) ([]string, error) {
	hash := smbMemoKey("listShares", executionId, host, fmt.Sprint(port), user, password)

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
	hash := smbMemoKey("listDir", executionId, host, fmt.Sprint(port), user, password, share, dir)

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
	hash := smbMemoKey("readFile", executionId, host, fmt.Sprint(port), user, password, share, filePath)

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
	hash := smbMemoKey("listTree", executionId, host, fmt.Sprint(port), user, password, share, dir)

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
