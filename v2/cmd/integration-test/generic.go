package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/julienschmidt/httprouter"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var genericTestcases = []TestCaseInfo{
	{Path: "generic/auth/certificate/http-get.yaml", TestCase: &clientCertificate{}},
}

var (
	serverCRT = `-----BEGIN CERTIFICATE-----
MIIDETCCAfkCFHA1RpGfOY5p/vQmeMQ1oRFqH+CGMA0GCSqGSIb3DQEBCwUAMEUx
CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjMwNjIxMDA0MjQ2WhcNMjMwNzIxMDA0
MjQ2WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE
CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA3VdrKR5hmZ+vyvg6NB2dOL5vEIQ/9DevivnKWqX5mserYLMj
Wq0knVfogewZnrDe+zVC3kOogBQvYk8Z53kTY9qpJT85dMCuW4xDx0JU+cWHul9a
pzF+bvws4paCWIcsGONyocPAx5g07LbPU9civC80QkQqELo1zYiRU1bX8vRJJqbN
TW2mzl9MN3AnCAYTwq8WhVG/1QR3LPQhPR68/1LWrFefQaEWaXT2s+Xv7K7NDXro
WSba4SgKdFd6fyUVMVr/ioT1KT45TP5jbRrW5JJUTdpkiXaIucrZg39f6F5gTZGA
U7bNROUMkqrJJngN9+Hp+YH1GpkKgu9EKA30EQIDAQABMA0GCSqGSIb3DQEBCwUA
A4IBAQAw91bxiAi7DIVsKL3k4B0I+50ZKq9VMVNE3YCTPygpfuRiGQvlITZ5I8I5
3Ok2wWltgKx6EnicHIlLg42yRj7j3mdgOLMFMrUCfJmdogwnS+k6veG3G1RHUs9r
ATfX49u/hEX2pe7Rvx2VYVIugwrQESgQ21iaf6uUMsrq6W8eYZ31as1nJKpqIGbu
W1fZMSi0RIUJP+mpVBE82IW+gJRi3uKU4HKPqyrU3dviBFdBxb3lNbh34/vdNkIw
4H2CfBxEvdwLYAhWDerlm4wWCmjkMiHfBHPBhhOICTkR25a7NFy27h/UDHjVC/6m
fGshVSBtxVPJP7kcvZ1scIctvFZZ
-----END CERTIFICATE-----
`
	serverKey = `-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDdV2spHmGZn6/K
+Do0HZ04vm8QhD/0N6+K+cpapfmax6tgsyNarSSdV+iB7BmesN77NULeQ6iAFC9i
TxnneRNj2qklPzl0wK5bjEPHQlT5xYe6X1qnMX5u/CziloJYhywY43Khw8DHmDTs
ts9T1yK8LzRCRCoQujXNiJFTVtfy9Ekmps1NbabOX0w3cCcIBhPCrxaFUb/VBHcs
9CE9Hrz/UtasV59BoRZpdPaz5e/srs0NeuhZJtrhKAp0V3p/JRUxWv+KhPUpPjlM
/mNtGtbkklRN2mSJdoi5ytmDf1/oXmBNkYBTts1E5QySqskmeA334en5gfUamQqC
70QoDfQRAgMBAAECggEBALtPsHMSr9vW5Giq2m6iJRwRJGJg2NJukZLVwuYlkW7n
zGNAFgo1fkfdTfks+Z1u5rTGJPl9XkpNSrAyaqSVtNALCptnvtLMAIGe2Pj2bH0X
Kb6R1WCqJOn9ZGq4nkQW2D2Ttb2psCn458jvB9NWu6FvfRUbJFIVk1SFXx6c3pFN
kPCUudAiscaldUDCiz4FccKGXdRjq6HIeeWqvdErteb6JPTs9QXCHfBql9Esl4rK
SHt9RmAFNY+CLExHiFPBR15hHZRtiVkAVrgnPg1CPGAyVG0hGXj7YMMWpAyfFWpn
8gWVt7XJ4UX2knUwfU8p8dWe6qwf+AMrhravYJyccoUCgYEA8Ts0kHFnLga8Ewao
nyDQs5uYGG0PWkbXqnFVYnMeSbXzyC4ouInIk/eOQABCxdjy3NF9QuYvVLpfLJ+9
a97q1Vyg6lZ4PPuK8ZcPrHFSNNaj4eWNTOMo/Qdzz4bfflTsv8vjeeMxsqb6woXV
+E23UKCPlQPf86jugZVdaMtvZKsCgYEA6uR7glji70pVoG/f3soX1vllmVTtiLnh
zYMmwPyTRDvoGgg/nGK+GCq//Xyn8D900hbX8KKqGX7ca5FGk5pOpW/QE9uLcuWK
xcy8KAc05k1u4VaS5loWKnPGWreIpj3RbCfbPs5X/jBC+fPIA4Q8Qor5ZGdqVBvW
IKejnNqasjMCgYEAqltPUbpkTWLAKweGyWnZOR3mmUlbkDt7Toje7bmyaAew82t1
omzbU3N958DHZwVA7aSbu0TnpARB9jeRA77XRHo3wYXzP828X8R4cyVMEriJ35vG
38eESLyckrAC4SqETyZjrM4/aJT3fawaYVIw5SWegHPOEjr4xFaBMuKH9iUCgYEA
wFpC2kc374UMAcobpjIQu7aYAKyPqDuwMb+I6NjtMB9uvoKqtMIXsWqwtkBytkcA
v1p9k01hxmcg0eWxygW/CbM6zkgnNfvLXJeALbdZFo+qkVV4DrMPG8ybToalnJ1a
9hrda91GKZ4T+uQrktWjE0sDV7loVWBGRY+CaFyL+gkCgYEA3Z0j8VOLJnAKdCDp
3N74460pykwJ2suEYSJG6glXfU3fZ5VwAYjimxgD0S2VU4qK8PYBfa/oFH2vRX5p
11dWQWbfBdREO70UmJD4Pr6g3q9AF6DXLXb7dVm4y+hX065Xshk8oIuITVyO/XVK
wWqBD5GScI+Q7PLMes7aqtsDDJI=
-----END PRIVATE KEY-----
`
)

type clientCertificate struct{}

// Execute executes a test case and returns an error if occurred
func (h *clientCertificate) Execute(filePath string) error {
	router := httprouter.New()

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Client certificate required", http.StatusForbidden)
			return
		}

		fmt.Fprintf(w, "Hello, %s!\n", r.TLS.PeerCertificates[0].Subject)
	})

	_ = os.WriteFile("server.crt", []byte(serverCRT), os.ModePerm)
	_ = os.WriteFile("server.key", []byte(serverKey), os.ModePerm)
	defer os.Remove("server.crt")
	defer os.Remove("server.key")

	serverCert, _ := tls.LoadX509KeyPair("server.crt", "server.key")

	certPool := x509.NewCertPool()
	caCert, _ := os.ReadFile("server.crt")
	certPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	ts := httptest.NewUnstartedServer(router)

	ts.TLS = tlsConfig

	ts.StartTLS()
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug,
		"-ca", "generic/auth/certificate/assets/server.crt",
		"-cc", "generic/auth/certificate/assets/client.crt",
		"-ck", "generic/auth/certificate/assets/client.key")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}
