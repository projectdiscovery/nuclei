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
	permissionutil "github.com/projectdiscovery/utils/permission"
)

var genericTestcases = []TestCaseInfo{
	{Path: "generic/auth/certificate/http-get.yaml", TestCase: &clientCertificate{}},
}

var (
	serverCRT = `-----BEGIN CERTIFICATE-----
MIIDEzCCAfsCFC21Zw7U0tGDyLyMalwfo9cWbL6dMA0GCSqGSIb3DQEBCwUAMEUx
CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGQwIBcNMjMwNzI4MTAwNzI3WhgPMzAwMzA5Mjkx
MDA3MjdaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCjMlvOKQX9yn9SOYPJ8p+jeDUU/JWPwT4LRfqaxvvKSnS7
NZzd7lS4AR0YTjyjiRj3+t0QnEDHVKBD8cMh9kMXkQ2S0r7psCURLvvZOYt4v6KM
CyZpBbp8b/pG3aJQHDZjRDOApQrXhx62XJDIs64YKA8NybYOLqNisrWGrfqF4uEz
RMgVGlthuQcXo3n2HzobuYN7RsHBzCWGLn9fRMDC2j3IAnQLf4YOznOJ57CjMd2W
mn/yhHK8h9s4iU5zw3+PK+X/IM4GeAfeJMx8c5uq2A8A24uzMidyhxJCK7VUprjK
/ckdNYya6dkG2De+LR7W82ygfWbFDOnZKM26cPG/AgMBAAEwDQYJKoZIhvcNAQEL
BQADggEBAH5+Wdb/1jgBhihN6Pb6SWJmDvwkOEP3t00E3fBao4TDqdDOhPsLYrAm
8gt16OcGrrXDQA3bi79mAVqAqCvaf4hk0vSI0L4rNcCSP4D3fUBjRO3fY3fM4Qw8
xg9AusF5hRrvzFbEak7lPJ01kLOJEgBA1l457HrLnXcpDTml8Y46WqdWa6yVM33l
7tNaXWrPwYZYMTcRumIytsYtIJXp/sMLBIT0AO/QR4yarvVOeMSJ1va459PjKLBG
JGGmf2rigaT050e71QOrGyMXgT6xsNjJgzeVhUgPO422mPT692kDi2oB5DA0Fau0
4qm5CMFgmYcC3zQoN53aDs1mHyWeroc=
-----END CERTIFICATE-----	
`
	serverKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCjMlvOKQX9yn9S
OYPJ8p+jeDUU/JWPwT4LRfqaxvvKSnS7NZzd7lS4AR0YTjyjiRj3+t0QnEDHVKBD
8cMh9kMXkQ2S0r7psCURLvvZOYt4v6KMCyZpBbp8b/pG3aJQHDZjRDOApQrXhx62
XJDIs64YKA8NybYOLqNisrWGrfqF4uEzRMgVGlthuQcXo3n2HzobuYN7RsHBzCWG
Ln9fRMDC2j3IAnQLf4YOznOJ57CjMd2Wmn/yhHK8h9s4iU5zw3+PK+X/IM4GeAfe
JMx8c5uq2A8A24uzMidyhxJCK7VUprjK/ckdNYya6dkG2De+LR7W82ygfWbFDOnZ
KM26cPG/AgMBAAECggEAFtRko2J5xBcf2JDTLt0SF/wo8Nak1Ydi9pDDjgNoFdR0
n/vQBfvhPhxpxYysTvRO2eHuKvSw2zGredXIRmf82r8f9vokWuyZQt4fvTOfnzSv
uIeWx/pVLDM9/8vhePN5aEmSKtzrt1rfoQMx/eGk6RwxfuxI25MKqDP30O9lrHTn
Y0lW7dthgdDMlQnSpOqUm2ldDsykYCBFteh4i5RDzAhiGx1ryaz3FMg+/y0VTTk0
BM43qW6H9PD8P4iOau3DGIPNqtIlFSnWoYaM6Ta2osfzzdsnFbe5F7JbdMrf5MBc
Jq3VMUqffRmHubz7di03qRsRqGYQn2cJeiuVC+y6gQKBgQDYpq3MfMjwzPeoB1Ay
ZQdzx+T290XRxFZwkiv3uugsYMlFGEabdAMFx5oIIOdjWSBLI92RvXbg7qMd/xMC
ya/GzbKQd+5GbRLW+TZ0odGkMFkTo+DEkt07yEM8mrPJ6XePUndHbiNFSdpVKx4g
KdmiRHinm3R8Lr5/puvISrOdcwKBgQDA1kln9aD1mvIdObI6MubPitb+NuNcpVDo
myc1UrEJbcn8nBbLb+0Q+7gckjau2C8GN7Olnd8RCYLc7kU1On2pY+f19Ru/PdZX
cjCCTcxqCJvWkNWOzw14ag6UrDTF5nxtoVl/eXbHxWqFjdt0a211sa1mp3Gn3ZNq
m/teImYHhQKBgQCzWUA1MPPzi+pU2kEEhugla8xauha9cUiRhiAJw1uiKTlVDqSc
2ewKo9MaeYqzjruSGI26sVqxGDxGf7tQKoBuFiiFOhMxj+fxuHrhEHiI8FE9VgOj
F2U3sTAgAn1lX/VO21jM9BsUp++rY7dbrulwUDiFn8ZNazDeYeN8eoK4iwKBgQCb
cqJN+YW9NyCBSqdPnwTMvSE+YES7xFAKkjfzFiu8bBJtXe5KJHm4PRJXhc4q9/5A
Rtq8YR0WgNJLApArrnDqAa1Vajbp3RFSAKz1/X0Q5MurFanxqxsyvFvwoTkRZxFa
1rxstB96Prv12TrVCFx+ibI8lDJcnZNeV0s0wQn6eQKBgQDXkfPuX5TFBpNe1bWI
KUFmw9R1ynmUlIOaU3ITLv9C+w8zaJSpxFDZgJdv3uT8PfnXrsHm+lWjaOunvjri
quZSc06mLlEbggYoIFQNPeNPRyN0+GLvefMS3mCotzanZTmD5GrH9XG451tVPiH9
G/lpNA1ccRCCsLslcG/aaa5PQw==
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

	_ = os.WriteFile("server.crt", []byte(serverCRT), permissionutil.ConfigFilePermission)
	_ = os.WriteFile("server.key", []byte(serverKey), permissionutil.ConfigFilePermission)
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
