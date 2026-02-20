// Warning - This is generated code
package mysql

import (
	"context"
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// memoizedisMySQL is a memoized wrapper for isMySQL that supports context.
func memoizedisMySQL(ctx context.Context, executionId string, host string, port int) (bool, error) {
	// we use executionId, host and port as the cache key
	hash := "isMySQL" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		// we pass the context down to the actual isMySQL function
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

// memoizedfingerprintMySQL is a memoized wrapper for fingerprintMySQL that supports context.
func memoizedfingerprintMySQL(ctx context.Context, executionId string, host string, port int) (MySQLInfo, error) {
	// we use executionId, host and port as the cache key
	hash := "fingerprintMySQL" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		// we pass the context down to the actual fingerprintMySQL function
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
