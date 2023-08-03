package utils

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// CleanStructFieldJSONTag cleans struct json tag field
func CleanStructFieldJSONTag(tag string) string {
	return strings.TrimSuffix(strings.TrimSuffix(tag, ",omitempty"), ",inline")
}

// AddConfiguredClientCertToRequest adds the client certificate authentication to the tls.Config object and returns it
func AddConfiguredClientCertToRequest(tlsConfig *tls.Config, options *types.Options) (*tls.Config, error) {
	// Build the TLS config with the client certificate if it has been configured with the appropriate options.
	// Only one of the options needs to be checked since the validation checks in main.go ensure that all three
	// files are set if any of the client certification configuration options are.
	if len(options.ClientCertFile) > 0 {
		// Load the client certificate using the PEM encoded client certificate and the private key file
		cert, err := tls.LoadX509KeyPair(options.ClientCertFile, options.ClientKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		// Load the certificate authority PEM certificate into the TLS configuration
		caCert, err := os.ReadFile(options.ClientCAFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}
	return tlsConfig, nil
}

// CalculateContentLength calculates content-length of the http response
func CalculateContentLength(contentLength, bodyLength int64) int64 {
	if contentLength > -1 {
		return contentLength
	}
	return bodyLength
}

// headersToString converts http headers to string
func HeadersToString(headers http.Header) string {
	builder := &strings.Builder{}

	for header, values := range headers {
		builder.WriteString(header)
		builder.WriteString(": ")

		for i, value := range values {
			builder.WriteString(value)

			if i != len(values)-1 {
				builder.WriteRune('\n')
				builder.WriteString(header)
				builder.WriteString(": ")
			}
		}
		builder.WriteRune('\n')
	}
	return builder.String()
}
