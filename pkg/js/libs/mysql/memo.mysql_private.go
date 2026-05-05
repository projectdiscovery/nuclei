// Warning - This is generated code
package mysql

import (
	"context"
	"errors"

	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedconnectWithDSN(ctx context.Context, executionId string, dsn string) (bool, error) {
	hash := "connectWithDSN" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(dsn)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
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
