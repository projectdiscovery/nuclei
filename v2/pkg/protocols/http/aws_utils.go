package http

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

type SignArguments struct {
	Service string
	Region  string
	Time    time.Time
}

func NewAwsSigner(awsId, awsSecretToken string) (*AwsSigner, error) {
	if awsId == "" {
		return nil, errors.New("empty id")
	}
	if awsSecretToken == "" {
		return nil, errors.New("empty token")
	}

	creds := credentials.NewStaticCredentials(awsId, awsSecretToken, "")
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
	return &AwsSigner{creds: creds}, nil
}

func NewAwsSignerFromFile() (*AwsSigner, error) {
	creds := credentials.NewSharedCredentials("", "")
	if creds == nil {
		return nil, errors.New("couldn't create the credentials structure")
	}
	return &AwsSigner{creds: creds}, nil
}

func (awsSigner *AwsSigner) SignHTTP(request *http.Request, args SignArguments) error {
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

	if _, err := awsSigner.signer.Sign(request, body, args.Service, args.Region, args.Time); err != nil {
		return err
	}
	return nil
}

func (awsSigner *AwsSigner) CalculateHTTPHeaders(request *http.Request, args SignArguments) (map[string]string, error) {
	reqClone := request.Clone(context.Background())
	awsSigner.prepareRequest(reqClone)
	err := awsSigner.SignHTTP(reqClone, args)
	if err != nil {
		return nil, err
	}
	headers := make(map[string]string)
	headers["X-Amz-Date"] = reqClone.Header.Get("X-Amz-Date")
	headers["Authorization"] = reqClone.Header.Get("Authorization")
	return headers, nil
}

func (awsSigner *AwsSigner) prepareRequest(request *http.Request) {
	request.Header.Del("Host")
}
