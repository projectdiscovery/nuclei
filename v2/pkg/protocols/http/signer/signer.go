package signer

import (
	"context"
	"errors"
	"net/http"
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
