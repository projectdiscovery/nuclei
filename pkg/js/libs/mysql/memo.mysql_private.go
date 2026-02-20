// Warning - This is generated code
package mysql

import (
	"context"
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// memoizedconnectWithDSN is a memoized wrapper for connectWithDSN that supports context.
func memoizedconnectWithDSN(ctx context.Context, executionId string, dsn string) (bool, error) {
	// we use executionId and dsn as the cache key
	hash := "connectWithDSN" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(dsn)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		// we pass the context down to the actual connection function
		return connectWithDSN(ctx, executionId, dsn)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}
