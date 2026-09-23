// Warning - This is generated code
package mssql

import (
	"context"

	"errors"

	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedfingerprintMssql(ctx context.Context, executionId string, host string, port int) (MSSQLInfo, error) {
	hash := "fingerprintMssql" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return fingerprintMssql(ctx, executionId, host, port)
	})
	if err != nil {
		return MSSQLInfo{}, err
	}
	if value, ok := v.(MSSQLInfo); ok {
		return value, nil
	}

	return MSSQLInfo{}, errors.New("could not convert cached result")
}
