package http

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/baseline"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/retryablehttp-go"
	httpUtils "github.com/projectdiscovery/utils/http"
	urlutil "github.com/projectdiscovery/utils/url"
)

// ErrNoClient is returned when no http client is available to fetch the baseline.
var ErrNoClient = errors.New("no http client available for baseline request")

// BaselineMatchedKey marks an event whose match also fired against the host's
// catch-all baseline, signalling the scorer to lower confidence.
const BaselineMatchedKey = "baseline_matched"

// baselineMatched reports whether this template's matchers also fire against the
// host's catch-all baseline: a control request to a path that almost certainly
// does not exist. When they do, the match is not specific to the target (the
// host answers everything the same way) and is very likely a false positive, so
// the caller lowers the reported confidence.
//
// Replaying the compiled operators against the baseline is deliberately binary
// and needs no body normalization: we are not diffing responses, only asking
// "would this template have matched a non-existent path too?".
func (request *Request) baselineMatched(input *contextargs.Context, generatedRequest *generatedRequest) bool {
	if request.options.BaselineCache == nil || request.CompiledOperators == nil {
		return false
	}

	target := ""
	if generatedRequest != nil {
		target = generatedRequest.URL()
	}
	if target == "" && input != nil {
		target = input.MetaInput.Input
	}
	parsed, err := urlutil.Parse(target)
	if err != nil || parsed.Host == "" {
		return false
	}
	baseURL := parsed.Scheme + "://" + parsed.Host

	baselineMap, ok := request.options.BaselineCache.GetOrFetch(baseURL, func() (baseline.Map, error) {
		return request.fetchBaseline(baseURL, parsed.Host)
	})
	if !ok || baselineMap == nil {
		return false
	}

	result, matched := request.CompiledOperators.Execute(baselineMap, request.Match, request.Extract, false)
	return matched && result != nil && result.Matched
}

// fetchBaseline sends a single control request to a random, almost-certainly
// non-existent path on the host and converts the response into a DSL map a
// template's operators can be replayed against. It reuses the same client pool
// and response decoding as a normal request so the baseline map is keyed
// identically to real responses.
func (request *Request) fetchBaseline(baseURL, host string) (baseline.Map, error) {
	client := request.getHTTPClientForHost(host)
	if client == nil {
		return nil, ErrNoClient
	}

	target := strings.TrimRight(baseURL, "/") + "/" + randomBaselinePath()
	req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}

	// respect user rate limiting for the extra control request
	request.rateLimitTake(baseURL)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	maxBodyLimit := int64(MaxBodyRead)
	if request.MaxSize > 0 {
		maxBodyLimit = int64(request.MaxSize)
	}
	if request.options.Options.ResponseReadSize != 0 {
		maxBodyLimit = int64(request.options.Options.ResponseReadSize)
	}

	respChain := httpUtils.NewResponseChain(resp, maxBodyLimit)
	defer respChain.Close()
	if err := respChain.Fill(); err != nil {
		return nil, err
	}

	dslMap := request.responseToDSLMap(respChain.Response(), baseURL, target, "", respChain.FullResponseString(), respChain.BodyString(), respChain.HeadersString(), 0, nil)
	return baseline.Map(dslMap), nil
}

// randomBaselinePath returns a high-entropy path that is almost certainly absent
// on the target, so a 200/match against it indicates catch-all behavior.
func randomBaselinePath() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "nuclei-baseline-control-path"
	}
	return hex.EncodeToString(buf)
}
