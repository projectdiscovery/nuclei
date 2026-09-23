// Warning - This is generated code
package smb

import (
	"context"
	"errors"

	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"

	"github.com/zmap/zgrab2/lib/smb/smb"
)

func memoizedconnectSMBInfoMode(ctx context.Context, executionId string, host string, port int) (*smb.SMBLog, error) {
	hash := "connectSMBInfoMode" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connectSMBInfoMode(ctx, executionId, host, port)
	})
	if err != nil {
		return nil, err
	}
	if value, ok := v.(*smb.SMBLog); ok {
		return value, nil
	}

	return nil, errors.New("could not convert cached result")
}
