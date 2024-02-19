// Warning - This is generated code
package smtp

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisOpenRelay(host string, port int, msg *SMTPMessage) (bool, error) {
	hash := "isOpenRelay" + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port) + ":" + fmt.Sprint(msg)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isOpenRelay(host, port, msg)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result")
}
