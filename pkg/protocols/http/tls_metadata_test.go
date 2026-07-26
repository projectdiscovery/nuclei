package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

func TestEnrichEventWithTLSMetadata(t *testing.T) {
	cert, err := selfSignedTestCertificate(t, "example.com", []string{"example.com", "www.example.com"})
	require.NoError(t, err)

	resp := &http.Response{
		TLS: &tls.ConnectionState{
			Version:          tls.VersionTLS13,
			CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
			ServerName:       "foo.com",
			PeerCertificates: []*x509.Certificate{cert},
		},
	}

	event := make(map[string]interface{})
	enrichEventWithTLSMetadata(event, resp)

	require.Equal(t, "tls13", event["tls_version"])
	require.Equal(t, "TLS_AES_128_GCM_SHA256", event["cipher"])
	require.Equal(t, "foo.com", event["sni"])
	require.Equal(t, "example.com", event["subject_cn"])
	require.Contains(t, event["subject_dn"], "CN=example.com")
	require.Equal(t, []string{"example.com", "www.example.com"}, event["subject_an"])
	require.NotEmpty(t, event["issuer_cn"])
	require.NotEmpty(t, event["serial"])
	require.Equal(t, true, event["mismatched"]) // cert for example.com, SNI foo.com
	require.Equal(t, true, event["self_signed"])
	require.Equal(t, false, event["expired"])
	require.Equal(t, false, event["wildcard_certificate"])

	domains, ok := event["domains"].([]string)
	require.True(t, ok)
	require.ElementsMatch(t, []string{"example.com", "www.example.com"}, domains)

	fp, ok := event["fingerprint_hash"].(map[string]string)
	require.True(t, ok)
	require.NotEmpty(t, fp["md5"])
	require.NotEmpty(t, fp["sha1"])
	require.NotEmpty(t, fp["sha256"])
}

func TestEnrichEventWithTLSMetadataNilSafe(t *testing.T) {
	event := make(map[string]interface{})
	enrichEventWithTLSMetadata(nil, &http.Response{})
	enrichEventWithTLSMetadata(event, nil)
	enrichEventWithTLSMetadata(event, &http.Response{})
	require.Empty(t, event)
}

func TestResponseToDSLMapIncludesTLSMetadata(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &Request{
		ID:     "testing-http-tls",
		Name:   "testing",
		Path:   []string{"{{BaseURL}}"},
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-http-tls",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	cert, err := selfSignedTestCertificate(t, "docs.example", []string{"docs.example"})
	require.NoError(t, err)

	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Server", "test")
	resp.TLS = &tls.ConnectionState{
		Version:          tls.VersionTLS12,
		CipherSuite:      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ServerName:       "docs.example",
		PeerCertificates: []*x509.Certificate{cert},
	}

	event := request.responseToDSLMap(resp, "https://docs.example/", "https://docs.example/",
		exampleRawRequest, exampleRawResponse, exampleResponseBody, exampleResponseHeader,
		time.Millisecond, nil)

	require.Equal(t, "tls12", event["tls_version"])
	require.Equal(t, "docs.example", event["subject_cn"])
	require.Equal(t, "docs.example", event["sni"])
	require.Equal(t, false, event["mismatched"])
	require.Equal(t, "test", event["server"])
}

func selfSignedTestCertificate(t *testing.T, cn string, dnsNames []string) (*x509.Certificate, error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Nuclei Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
