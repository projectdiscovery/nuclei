package http

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hostbackoff"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

func TestHostBackoffKeyKeepsHTTPSPort(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/secret", nil)
	require.NoError(t, err)
	gr := &generatedRequest{request: raw}

	key := hostBackoffKey(gr, nil)
	require.Equal(t, "example.com:443", httpclientpool.NormalizeHostPort(key))
	// request.URL.Host drops the default port. That is what executeRequest used
	// to observe, and it lands on port 80.
	require.Equal(t, "example.com", raw.URL.Host)
	require.Equal(t, "example.com:80", httpclientpool.NormalizeHostPort(raw.URL.Host))
}

func TestObserveIgnoresCanceledRequest(t *testing.T) {
	g := hostbackoff.New(hostbackoff.Config{Step: 100 * time.Millisecond})
	req := &Request{options: &protocols.ExecutorOptions{HostBackoff: g}}
	target := "https://example.com/x"
	key := httpclientpool.NormalizeHostPort(target)

	req.observeHostBackoff(target, nil, context.Canceled)
	require.Zero(t, g.Delay(key))

	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}
	req.observeHostBackoff(target, resp, context.Canceled)
	require.Equal(t, 100*time.Millisecond, g.Delay(key))
}

func TestHostBackoffKeyKeepsIPv6OnHTTPS(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "https://[2001:db8::1]/secret", nil)
	require.NoError(t, err)
	key := httpclientpool.NormalizeHostPort(hostBackoffKey(&generatedRequest{request: raw}, nil))
	// URL.Host has no port, so the old observation key took the http default.
	require.NotEqual(t, key, httpclientpool.NormalizeHostPort(raw.URL.Host))
	require.Contains(t, key, "443")
}

func TestHostBackoffKeyFallsBackToInput(t *testing.T) {
	input := contextargs.NewWithInput(context.Background(), "https://example.com/from-input")
	require.Equal(t, "https://example.com/from-input", hostBackoffKey(nil, input))
	require.Equal(t, "example.com:443", httpclientpool.NormalizeHostPort(hostBackoffKey(nil, input)))
}

// A pipeline or unsafe request stored parsed.Host, which is empty when ParseURL
// fails or when it clears a single-label host. The wait used the original URL.
func TestParsedHostCanMissTheWaitKey(t *testing.T) {
	_, err := urlutil.ParseURL("http:///no-host", true)
	require.Error(t, err)

	parsed, err := urlutil.ParseURL("http://intranet/admin", true)
	require.NoError(t, err)
	require.Empty(t, parsed.Host)
	require.Equal(t, "intranet:80", httpclientpool.NormalizeHostPort("http://intranet/admin"))
}
