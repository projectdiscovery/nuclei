package engine

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// newhttpClient creates a new http client for headless communication with a timeout
func newhttpClient(options *types.Options) (*http.Client, error) {
	opts := fastdialer.DefaultOptions
	if options.SystemResolvers {
		opts.EnableFallback = true
	}
	if options.ResolversFile != "" {
		opts.BaseResolvers = options.InternalResolversList
	}
	dialer, err := fastdialer.NewDialer(opts)
	if err != nil {
		return nil, errors.Wrap(err, "could not create dialer")
	}

	transport := &http.Transport{
		DialContext:         dialer.Dial,
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     500,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{Transport: transport, Timeout: time.Duration(options.Timeout*3) * time.Second}, nil
}
