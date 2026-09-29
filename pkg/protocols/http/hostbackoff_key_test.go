package http

import (
	"context"
	"net/http"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
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
