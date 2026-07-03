// Warning - This is generated code
package telnet

import (
	"context"
	"errors"

	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisTelnet(ctx context.Context, executionId string, host string, port int) (IsTelnetResponse, error) {
	hash := "isTelnet" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isTelnet(ctx, executionId, host, port)
	})
	if err != nil {
		return IsTelnetResponse{}, err
	}
	if value, ok := v.(IsTelnetResponse); ok {
		return value, nil
	}

	return IsTelnetResponse{}, errors.New("could not convert cached result")
}
