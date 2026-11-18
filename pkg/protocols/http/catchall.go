package http

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/catchall"
	"github.com/projectdiscovery/retryablehttp-go"
	httpUtils "github.com/projectdiscovery/utils/http"
)

// catchAllCheck returns the lazy check for whether resp is the page the host
// serves for any missing path, or nil when calibration cannot judge this
// request. Fuzzed and raced requests target real endpoints on purpose, and
// only GET and HEAD are probed so that calibration never sends a body.
func (request *Request) catchAllCheck(client *retryablehttp.Client, generated *generatedRequest, resp catchall.Response, rateLimitKey string) func() bool {
	detector := request.options.CatchAll
	sent := generated.request
	if detector == nil || client == nil || sent == nil || sent.URL == nil || generated.fuzzGeneratedRequest.Request != nil || request.Race {
		return nil
	}
	if sent.Method != http.MethodGet && sent.Method != http.MethodHead {
		return nil
	}
	// The response buffers are reused for the next response in the chain,
	// and the check may run after that.
	resp.Body = strings.Clone(resp.Body)
	requestURL := *sent.URL.URL
	header := sent.Header.Clone()
	hostHeader := sent.Host
	limit := int64(request.getEffectiveReadLimit())

	probe := func(ctx context.Context, path string) (catchall.Response, error) {
		if err := request.rateLimitTake(ctx, rateLimitKey); err != nil {
			return catchall.Response{}, err
		}
		target := requestURL
		target.Path, target.RawPath, target.RawQuery = path, "", ""
		probeReq, err := retryablehttp.NewRequestWithContext(ctx, sent.Method, target.String(), nil)
		if err != nil {
			return catchall.Response{}, err
		}
		probeReq.Header = header.Clone()
		probeReq.Host = hostHeader
		probeResp, err := client.Do(probeReq)
		if err != nil {
			return catchall.Response{}, err
		}
		chain := httpUtils.NewResponseChain(probeResp, limit)
		defer chain.Close()
		if err := chain.Fill(); err != nil {
			return catchall.Response{}, err
		}
		final := chain.Response()
		return catchall.Response{StatusCode: final.StatusCode, Location: final.Header.Get("Location"), Body: chain.BodyString()}, nil
	}
	ctx := sent.Context()
	return sync.OnceValue(func() bool { return detector.Matches(ctx, &requestURL, resp, probe) })
}
