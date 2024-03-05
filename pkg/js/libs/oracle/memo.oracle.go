// Warning - This is generated code
package oracle

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisOracle(host string, port int) (IsOracleResponse, error) {
	hash := "isOracle" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isOracle(host, port)
	})
	if err != nil {
		return IsOracleResponse{}, err
	}
	if value, ok := v.(IsOracleResponse); ok {
		return value, nil
	}

	return IsOracleResponse{}, errors.New("could not convert cached result")
}
