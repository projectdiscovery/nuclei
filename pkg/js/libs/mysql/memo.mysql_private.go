package mysql

import (
	"context"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedconnectWithDSN(ctx context.Context, executionId string, dsn string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	// Optimization: String concatenation is faster than fmt.Sprint for keys
	hash := "connectWithDSN:" + executionId + ":" + dsn

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connectWithDSN(context.Background(), executionId, dsn)
	})

	if err != nil { return false, err }
	return v.(bool), nil
}
