package postgres

import (
	"errors"
	"fmt"

	utils "github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisPostgres(host string, port int) (bool, error) {
	hash := "isPostgres:" + host + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isPostgres(host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}

func memoizedexecuteQuery(host string, port int, username, password, dbName, query string) (*utils.SQLResult, error) {
	hash := "executeQuery:" + host + ":" + fmt.Sprint(port) + ":" + username + ":" + password + ":" + dbName + ":" + query

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return executeQuery(host, port, username, password, dbName, query)
	})
	if err != nil {
		return &utils.SQLResult{}, err
	}
	if value, ok := v.(*utils.SQLResult); ok {
		return value, nil
	}

	return &utils.SQLResult{}, errors.New("could not convert cached result")
}

func memoizedconnect(host string, port int, username, password, dbName string) (bool, error) {
	hash := "connect:" + host + ":" + fmt.Sprint(port) + ":" + username + ":" + password + ":" + dbName

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connect(host, port, username, password, dbName)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}
