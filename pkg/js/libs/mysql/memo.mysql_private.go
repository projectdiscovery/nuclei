// Warning - This is generated code
package mysql

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedconnectWithDSN(dsn string) (bool, error) {
	hash := "connectWithDSN" + ":" + fmt.Sprint(dsn)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connectWithDSN(dsn)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}
