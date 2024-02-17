package pop3

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisPOP3(host string, port int) (IsPOP3Response, error) {
	hash := "isPOP3:" + host + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isPOP3(host, port)
	})
	if err != nil {
		return IsPOP3Response{}, err
	}
	if value, ok := v.(IsPOP3Response); ok {
		return value, nil
	}

	return IsPOP3Response{}, errors.New("could not convert cached result")
}
