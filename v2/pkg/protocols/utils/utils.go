package utils

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"io/ioutil"
	"log"
)

// AddConfiguredClientCertToRequest adds the client certificate authentication to the tls.Config object and returns it
func AddConfiguredClientCertToRequest(tlsConfig *tls.Config, options *types.Options) *tls.Config {
	// Build the TLS config with the client certificate if it has been configured with the appropriate options.
	// Only one of the options needs to be checked since the validation checks in main.go ensure that all three
	// files are set if any of the client certification configuration options are.
	if len(options.ClientCertFile) > 0 {
		// Load the client certificate using the PEM encoded client certificate and the private key file
		cert, err := tls.LoadX509KeyPair(options.ClientCertFile, options.ClientKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		// Load the certificate authority PEM certificate into the TLS configuration
		caCert, err := ioutil.ReadFile(options.ClientCAFile)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}
	return tlsConfig
}
