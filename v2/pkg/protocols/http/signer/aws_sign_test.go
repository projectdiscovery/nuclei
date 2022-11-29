package signer_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/signer"
)

func Test_AWSSign(t *testing.T) {
	signer, er := signer.NewAwsSignerFromConfig(&signer.AWSOptions{
		Region:  "us-east-1",
		Service: "sts",
	})
	if er != nil {
		t.Logf("skipping aws signer test creds not found")
		return
	}

	body := strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15")

	req, _ := http.NewRequest("POST", "https://sts.amazonaws.com/", body)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	err := signer.SignHTTP(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	bin, _ := httputil.DumpResponse(resp, true)
	fmt.Println(string(bin))
}
