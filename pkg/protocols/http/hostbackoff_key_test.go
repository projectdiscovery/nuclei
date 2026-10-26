package http

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hostbackoff"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hostratelimit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httputils"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

func TestHostBackoffKeyKeepsHTTPSPort(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/secret", nil)
	require.NoError(t, err)
	gr := &generatedRequest{request: raw}

	key := hostBackoffKey(gr, nil)
	require.Equal(t, "example.com:443", hostratelimit.NormalizeHostPort(key))
	// request.URL.Host drops the default port. That is what executeRequest used
	// to observe, and it lands on port 80.
	require.Equal(t, "example.com", raw.URL.Host)
	require.Equal(t, "example.com:80", hostratelimit.NormalizeHostPort(raw.URL.Host))
}

func TestObserveIgnoresCanceledRequest(t *testing.T) {
	g := hostbackoff.New(hostbackoff.Config{Step: 100 * time.Millisecond})
	req := &Request{options: &protocols.ExecutorOptions{HostBackoff: g}}
	target := "https://example.com/x"
	key := hostratelimit.NormalizeHostPort(target)

	req.observeHostBackoff(target, nil, context.Canceled)
	require.Zero(t, g.Delay(key))

	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}
	req.observeHostBackoff(target, resp, context.Canceled)
	require.Equal(t, 100*time.Millisecond, g.Delay(key))
}

func TestHostBackoffKeyKeepsIPv6OnHTTPS(t *testing.T) {
	raw, err := retryablehttp.NewRequest(http.MethodGet, "https://[2001:db8::1]/secret", nil)
	require.NoError(t, err)
	key := hostratelimit.NormalizeHostPort(hostBackoffKey(&generatedRequest{request: raw}, nil))
	// URL.Host has no port, so the old observation key took the http default.
	require.NotEqual(t, key, hostratelimit.NormalizeHostPort(raw.URL.Host))
	require.Contains(t, key, "443")
}

func TestHostBackoffKeyFallsBackToInput(t *testing.T) {
	input := contextargs.NewWithInput(context.Background(), "https://example.com/from-input")
	require.Equal(t, "https://example.com/from-input", hostBackoffKey(nil, input))
	require.Equal(t, "example.com:443", hostratelimit.NormalizeHostPort(hostBackoffKey(nil, input)))
}

// A pipeline or unsafe request stored parsed.Host, which is empty when ParseURL
// fails or when it clears a single-label host. The wait used the original URL.
func TestParsedHostCanMissTheWaitKey(t *testing.T) {
	_, err := urlutil.ParseURL("http:///no-host", true)
	require.Error(t, err)

	parsed, err := urlutil.ParseURL("http://intranet/admin", true)
	require.NoError(t, err)
	require.Empty(t, parsed.Host)
	require.Equal(t, "intranet:80", hostratelimit.NormalizeHostPort("http://intranet/admin"))
}

func TestWaitHostBackoffStopsWhenHandlerTriggers(t *testing.T) {
	g := hostbackoff.New(hostbackoff.Config{Step: 2 * time.Second, Max: 2 * time.Second})
	req := &Request{options: &protocols.ExecutorOptions{HostBackoff: g}}
	target := "https://example.com/x"
	req.observeHostBackoff(target, &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}, nil)

	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	handler := httputils.NewNonBlockingSPMHandler[struct{}](parent, 1, true)
	waitCtx, cancelWait := stopWithHandler(parent, handler)
	defer cancelWait()

	done := make(chan error, 1)
	go func() {
		done <- req.waitHostBackoff(waitCtx, target)
	}()
	time.Sleep(20 * time.Millisecond)
	handler.Trigger()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("backoff wait outlived the handler")
	}
}
