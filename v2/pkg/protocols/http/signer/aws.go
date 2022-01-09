package signer

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
)

type AwsSigner struct {
	creds  *credentials.Credentials
	signer *v4.Signer
}

type AwsSignerArgs struct {
	AwsId          string
	AwsSecretToken string
}

func (awsSignerArgs AwsSignerArgs) Validate() error {
	if awsSignerArgs.AwsId == "" {
		return errors.New("empty id")
	}
	if awsSignerArgs.AwsSecretToken == "" {
		return errors.New("empty token")
	}

	return nil
}

type AwsSignatureArguments struct {
	Service string
	Region  string
	Time    time.Time
}

func (awsSignatureArguments AwsSignatureArguments) Validate() error {
	if awsSignatureArguments.Region == "" {
		return errors.New("empty region")
	}
	if awsSignatureArguments.Service == "" {
		return errors.New("empty service")
	}

	return nil
}

func NewAwsSigner(args AwsSignerArgs) (*AwsSigner, error) {
	if err := args.Validate(); err != nil {
		return nil, err
	}
	creds := credentials.NewStaticCredentials(args.AwsId, args.AwsSecretToken, "")
	if creds == nil {
		return nil, errors.New("couldn't create the credentials structure")
	}
	signer := v4.NewSigner(creds)
	return &AwsSigner{creds: creds, signer: signer}, nil
}

func NewAwsSignerFromEnv() (*AwsSigner, error) {
	creds := credentials.NewEnvCredentials()
	if creds == nil {
		return nil, errors.New("couldn't create the credentials structure")
	}
	signer := v4.NewSigner(creds)
	return &AwsSigner{creds: creds, signer: signer}, nil
}

func NewAwsSignerFromFile() (*AwsSigner, error) {
	creds := credentials.NewSharedCredentials("", "")
	if creds == nil {
		return nil, errors.New("couldn't create the credentials structure")
	}
	signer := v4.NewSigner(creds)
	return &AwsSigner{creds: creds, signer: signer}, nil
}

func (awsSigner *AwsSigner) SignHTTP(request *http.Request, args interface{}) error {
	signatureArgs, err := awsSigner.checkSignatureArgs(args)
	if err != nil {
		return err
	}

	awsSigner.prepareRequest(request)
	var body *bytes.Reader
	if request.Body != nil {
		bodyBytes, err := ioutil.ReadAll(request.Body)
		if err != nil {
			return err
		}
		request.Body.Close()
		body = bytes.NewReader(bodyBytes)
	}
	if _, err := awsSigner.signer.Sign(request, body, signatureArgs.Service, signatureArgs.Region, signatureArgs.Time); err != nil {
		return err
	}
	return nil
}

func (awsSigner *AwsSigner) CalculateHTTPHeaders(request *http.Request, args interface{}) (map[string]string, error) {
	signatureArgs, err := awsSigner.checkSignatureArgs(args)
	if err != nil {
		return nil, err
	}

	reqClone := request.Clone(context.Background())
	awsSigner.prepareRequest(reqClone)
	err = awsSigner.SignHTTP(reqClone, signatureArgs)
	if err != nil {
		return nil, err
	}
	headers := make(map[string]string)
	headers["X-Amz-Date"] = reqClone.Header.Get("X-Amz-Date")
	headers["Authorization"] = reqClone.Header.Get("Authorization")
	return headers, nil
}

func (awsSigner *AwsSigner) checkSignatureArgs(args interface{}) (AwsSignatureArguments, error) {
	if signatureArgs, ok := args.(AwsSignatureArguments); ok {
		return signatureArgs, signatureArgs.Validate()
	}
	return AwsSignatureArguments{}, errors.New("wrong signature type")
}

func (awsSigner *AwsSigner) prepareRequest(request *http.Request) {
	request.Header.Del("Host")
}

var AwsSkipList = map[string]interface{}{
	"region": struct{}{},
}

var AwsDefaultVars = map[string]interface{}{
	"region": "us-east-2",
}

var AwsInternaOnlyVars = map[string]interface{}{
	"aws-id":     struct{}{},
	"aws-secret": struct{}{},
}
