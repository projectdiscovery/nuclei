package signer

import (
	"context"
	"errors"
	"net/http"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// An Argument that can be passed to Signer
type SignerArg string

type Signer interface {
	SignHTTP(ctx context.Context, request *http.Request) error
}

type SignerArgs interface {
	Validate() error
}

func NewSigner(args SignerArgs) (signer Signer, err error) {
	switch signerArgs := args.(type) {
	case *AWSOptions:
		awsSigner, err := NewAwsSigner(signerArgs)
		if err != nil {
			awsSigner, err = NewAwsSignerFromConfig(signerArgs)
			if err != nil {
				return nil, err
			}
		}
		return awsSigner, err
	default:
		return nil, errors.New("unknown signature arguments type")
	}
}

// GetCtxWithArgs creates and returns context with signature args
func GetCtxWithArgs(maps ...map[string]interface{}) context.Context {
	var region, service string
	for _, v := range maps {
		for key, val := range v {
			if key == "region" && region == "" {
				region = types.ToString(val)
			}
			if key == "service" && service == "" {
				service = types.ToString(val)
			}
		}
	}
	// type ctxkey string
	ctx := context.WithValue(context.Background(), SignerArg("service"), service)
	return context.WithValue(ctx, SignerArg("region"), region)
}
