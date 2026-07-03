// Warning - This is generated code
package rdp

import (
	"context"
	"errors"

	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

func memoizedisRDP(ctx context.Context, executionId string, host string, port int) (IsRDPResponse, error) {
	hash := "isRDP" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return isRDP(ctx, executionId, host, port)
	})
	if err != nil {
		return IsRDPResponse{}, err
	}
	if value, ok := v.(IsRDPResponse); ok {
		return value, nil
	}

	return IsRDPResponse{}, errors.New("could not convert cached result")
}

func memoizedcheckRDPAuth(ctx context.Context, executionId string, host string, port int) (CheckRDPAuthResponse, error) {
	hash := "checkRDPAuth" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return checkRDPAuth(ctx, executionId, host, port)
	})
	if err != nil {
		return CheckRDPAuthResponse{}, err
	}
	if value, ok := v.(CheckRDPAuthResponse); ok {
		return value, nil
	}

	return CheckRDPAuthResponse{}, errors.New("could not convert cached result")
}

func memoizedcheckRDPEncryption(ctx context.Context, executionId string, host string, port int) (RDPEncryptionResponse, error) {
	hash := "checkRDPEncryption" + ":" + fmt.Sprint(executionId) + ":" + fmt.Sprint(host) + ":" + fmt.Sprint(port)

	v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
		return checkRDPEncryption(ctx, executionId, host, port)
	})
	if err != nil {
		return RDPEncryptionResponse{}, err
	}
	if value, ok := v.(RDPEncryptionResponse); ok {
		return value, nil
	}

	return RDPEncryptionResponse{}, errors.New("could not convert cached result")
}
