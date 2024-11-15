// Warning - This is generated code
package mssql

import (
	"errors"
	"fmt"

	_ "github.com/microsoft/go-mssqldb"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedconnect(host string, port int, username string, password string, dbName string) (bool, error) {
	hash := "connect" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(username) + ":" + fmt.Sprint(password) + ":" + fmt.Sprint(dbName)

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

func memoizedisMssql(host string, port int) (bool, error) {
	hash := "isMssql" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isMssql(host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}
