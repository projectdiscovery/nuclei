// Warning - This is generated code
package mysql

import (
	"context"
	"errors"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisMySQL(ctx context.Context, executionId string, host string, port int) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	hash := "isMySQL:" + executionId + ":" + host + ":" + string(rune(port))

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isMySQL(ctx, executionId, host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}

func memoizedfingerprintMySQL(ctx context.Context, executionId string, host string, port int) (MySQLInfo, error) {
	if err := ctx.Err(); err != nil {
		return MySQLInfo{}, err
	}
	hash := "fingerprintMySQL:" + executionId + ":" + host + ":" + string(rune(port))

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return fingerprintMySQL(ctx, executionId, host, port)
	})
	if err != nil {
		return MySQLInfo{}, err
	}
	if value, ok := v.(MySQLInfo); ok {
		return value, nil
	}

	return MySQLInfo{}, errors.New("could not convert cached result")
}
