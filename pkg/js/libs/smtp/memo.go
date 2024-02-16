package smtp

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisOpenRelay(host string, port int, msg *SMTPMessage) (bool, error) {
	hash := "isOpenRelay:" + fmt.Sprint(port) + fmt.Sprintf("%#v\n", msg)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isOpenRelay(host, port, msg)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result to bool")
}
