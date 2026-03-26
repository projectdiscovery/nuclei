// Warning - This is generated code
package mssql

import (
	"context"
	"errors"

	"fmt"

	_ "github.com/microsoft/go-mssqldb"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedconnect(ctx context.Context, executionId string, host string, port int, username string, password string, dbName string) (bool, error) {
	hash := "connect" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(username) + ":" + fmt.Sprint(password) + ":" + fmt.Sprint(dbName)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connect(ctx, executionId, host, port, username, password, dbName)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}

func memoizedisMssql(ctx context.Context, executionId string, host string, port int) (bool, error) {
	hash := "isMssql" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isMssql(ctx, executionId, host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}
