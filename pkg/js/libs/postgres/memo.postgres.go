// Warning - This is generated code
package postgres

import (
	"context"
	"errors"

	"fmt"

	utils "github.com/projectdiscovery/nuclei/v3/pkg/js/utils"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisPostgres(ctx context.Context, executionId string, host string, port int) (bool, error) {
	hash := "isPostgres" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isPostgres(ctx, executionId, host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}

func memoizedexecuteQuery(ctx context.Context, executionId string, host string, port int, username string, password string, dbName string, query string) (*utils.SQLResult, error) {
	hash := "executeQuery" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(username) + ":" + fmt.Sprint(password) + ":" + fmt.Sprint(dbName) + ":" + fmt.Sprint(query)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return executeQuery(ctx, executionId, host, port, username, password, dbName, query)
	})
	if err != nil {
		return nil, err
	}
	if value, ok := v.(*utils.SQLResult); ok {
		return value, nil
	}

	return nil, errors.New("could not convert cached result")
}

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
