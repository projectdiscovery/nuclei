package signer

import (
	"errors"
	"net/http"
)

type Signer interface {
	SignHTTP(request *http.Request, args interface{}) error
	CalculateHTTPHeaders(request *http.Request, args interface{}) (map[string]string, error)
}

type SignerArgs interface {
	Validate() error
}

type SignatureArguments interface {
	Validate() error
}

func NewSigner(args SignerArgs) (signer Signer, err error) {
	switch signerArgs := args.(type) {
	case AwsSignerArgs:
		awsSigner, err := NewAwsSigner(signerArgs)
		if err != nil {
			// $HOME/.aws/credentials
			awsSigner, err = NewAwsSignerFromFile()
			if err != nil {
				// env variables
				awsSigner, err = NewAwsSignerFromEnv()
				if err != nil {
					return nil, err
				}
			}
		}
		return awsSigner, err
	default:
		return nil, errors.New("unknown signature arguments type")
	}
}
