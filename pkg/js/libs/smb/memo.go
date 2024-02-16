package smb

import (
	"errors"
	"fmt"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/zmap/zgrab2/lib/smb/smb"
)

func memoizedcollectSMBv2Metadata(host string, port int, timeout time.Duration) (*plugins.ServiceSMB, error) {
	hash := "collectSMBv2Metadata:" + host + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return collectSMBv2Metadata(host, port, timeout)
	})
	if err != nil {
		return &plugins.ServiceSMB{}, err
	}
	if value, ok := v.(*plugins.ServiceSMB); ok {
		return value, nil
	}

	return &plugins.ServiceSMB{}, errors.New("could not convert cached result to *plugins.ServiceSMB")
}

func memoizedDetectSMBGhost(host string, port int) (bool, error) {
	hash := "memoizedDetectSMBGhost:" + host + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return detectSMBGhost(host, port)
	})
	if err != nil {
		return false, err
	}
	if value, ok := v.(bool); ok {
		return value, nil
	}

	return false, errors.New("could not convert cached result to bool")
}

func memoizedlistShares(host string, port int, user, password string) ([]string, error) {
	hash := "listShares:" + host + ":" + fmt.Sprint(port) + ":" + user + ":" + password

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return listShares(host, port, user, password)
	})
	if err != nil {
		return nil, err
	}
	if value, ok := v.([]string); ok {
		return value, nil
	}

	return nil, errors.New("could not convert cached result to []string")
}

func memoizedconnectSMBInfoMode(host string, port int) (*smb.SMBLog, error) {
	hash := "listShares:" + host + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return connectSMBInfoMode(host, port)
	})
	if err != nil {
		return nil, err
	}
	if value, ok := v.(*smb.SMBLog); ok {
		return value, nil
	}

	return nil, errors.New("could not convert cached result to *smb.SMBLog")
}
