package dsl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

type publicIPTestProxy struct {
	address string
	calls   atomic.Int32
}

func (p *publicIPTestProxy) Dial(network, address string) (net.Conn, error) {
	p.calls.Add(1)
	if address == "8.8.8.8:443" {
		address = p.address
	}
	return net.DialTimeout(network, address, time.Second)
}

// A subprocess isolates the test CA from the process-wide TLS root store.
func TestPublicIPAllowedAndRedirectPolicy(t *testing.T) {
	if os.Getenv("NUCLEI_TEST_PUBLIC_IP_CHILD") != "1" {
		executable, err := os.Executable()
		require.NoError(t, err)
		for _, restricted := range []bool{false, true} {
			t.Run(fmt.Sprintf("lna-%t", restricted), func(t *testing.T) {
				command := exec.Command(executable, "-test.run=^TestPublicIPAllowedAndRedirectPolicy$", "-test.timeout=30s")
				command.Env = append(os.Environ(), "NUCLEI_TEST_PUBLIC_IP_CHILD=1", "NUCLEI_TEST_PUBLIC_IP_LNA="+strconv.FormatBool(restricted), "GODEBUG=x509usefallbackroots=1")
				output, err := command.CombinedOutput()
				require.NoError(t, err, string(output))
			})
		}
		return
	}
	restricted := os.Getenv("NUCLEI_TEST_PUBLIC_IP_LNA") == "true"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "checkip.amazonaws.com"}, DNSNames: []string{"checkip.amazonaws.com"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	x509.SetFallbackRoots(roots)
	var redirect atomic.Bool
	var requests atomic.Int32
	var localRequests atomic.Int32
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localRequests.Add(1)
		_, _ = w.Write([]byte("8.8.4.4\n"))
	}))
	defer local.Close()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if redirect.Load() {
			http.Redirect(w, r, local.URL, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("8.8.4.4\n"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	resolver, _ := networkTestDNS(t, "8.8.8.8")
	options := networkTestOptions(t, &types.Options{RestrictLocalNetworkAccess: restricted, InternalResolversList: []string{resolver}})
	state := protocolstate.GetDialersWithId(options.ExecutionId)
	controlledProxy := &publicIPTestProxy{address: server.Listener.Addr().String()}
	var proxyDialer proxy.Dialer = controlledProxy
	dialerOptions := fastdialer.DefaultOptions
	dialerOptions.ResolversFile = false
	dialerOptions.BaseResolvers = []string{resolver}
	dialerOptions.NetworkPolicy = state.NetworkPolicy
	dialerOptions.ProxyDialer = &proxyDialer
	controlledDialer, err := fastdialer.NewDialer(dialerOptions)
	require.NoError(t, err)
	state.Fastdialer.Close()
	state.Fastdialer = controlledDialer
	for _, source := range []string{`public_ip()`, `publicip()`} {
		result, err := evalNetworkTest(t, source, options)
		require.NoError(t, err)
		require.Equal(t, "8.8.4.4", result)
	}
	redirect.Store(true)
	result, err := evalNetworkTest(t, `public_ip()`, options)
	if restricted {
		require.ErrorContains(t, err, "network policy")
		require.Zero(t, localRequests.Load())
		require.EqualValues(t, 3, controlledProxy.calls.Load(), "redirect must not reach the proxy")
	} else {
		require.NoError(t, err)
		require.Equal(t, "8.8.4.4", result)
		require.EqualValues(t, 1, localRequests.Load())
		require.EqualValues(t, 4, controlledProxy.calls.Load())
	}
	require.EqualValues(t, 3, requests.Load())
	options.ExcludeTargets = []string{"8.8.8.8"}
	require.NoError(t, protocolstate.Init(options))
	_, err = evalNetworkTest(t, `public_ip()`, options)
	require.Error(t, err, "a prior result must not bypass changed exclusions")
	require.EqualValues(t, 3, requests.Load())
}
