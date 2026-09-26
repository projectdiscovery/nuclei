package http

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/baseline"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
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

	baselineRequest, client, cacheKey, err := request.prepareBaseline(input, baseURL, parsed.Host)
	if err != nil {
		return false
	}
	baselineMap, ok := request.options.BaselineCache.GetOrFetch(cacheKey, func() (baseline.Map, error) {
		return request.fetchBaseline(client, baselineRequest, baseURL)
	})
	if !ok || baselineMap == nil {
		return false
	}

	result, matched := request.CompiledOperators.Execute(baselineMap, request.Match, request.Extract, false)
	return matched && result != nil && result.Matched
}

// prepareBaseline creates a control request with the same effective custom
// headers, authentication, and per-input cookie jar as a normal request.
func (request *Request) prepareBaseline(input *contextargs.Context, baseURL, host string) (*retryablehttp.Request, *retryablehttp.Client, string, error) {
	target := strings.TrimRight(baseURL, "/") + "/" + randomBaselinePath()
	req, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, "", err
	}
	generated := &generatedRequest{original: request, request: req}
	request.setCustomHeaders(generated)
	if !request.SkipSecretFile {
		generated.ApplyAuth(request.options.AuthProvider)
	}

	connConfig := request.connConfiguration
	if input != nil && input.CookieJar != nil && !request.DisableCookie {
		connConfig = connConfig.Clone()
		connConfig.Connection.SetCookieJar(input.CookieJar)
	}
	client, err := httpclientpool.Get(request.options.Options, connConfig, host)
	if err != nil {
		client, err = httpclientpool.Get(request.options.Options, connConfig, "")
	}
	if err != nil || client == nil {
		return nil, nil, "", ErrNoClient
	}
	return req, client, baselineContextKey(baseURL, req, input), nil
}

// baselineContextKey prevents authenticated baselines from being shared across
// different header, query-auth, host-header, or cookie contexts.
func baselineContextKey(baseURL string, req *retryablehttp.Request, input *contextargs.Context) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "host=%q\nquery=%q\n", req.Host, req.RawQuery)
	keys := make([]string, 0, len(req.Header))
	for key := range req.Header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := append([]string(nil), req.Header.Values(key)...)
		sort.Strings(values)
		_, _ = fmt.Fprintf(hash, "header=%q:%q\n", key, values)
	}
	if input != nil && input.CookieJar != nil && req.Request != nil && req.Request.URL != nil {
		cookies := input.CookieJar.Cookies(req.Request.URL)
		values := make([]string, 0, len(cookies))
		for _, cookie := range cookies {
			values = append(values, cookie.String())
		}
		sort.Strings(values)
		for _, cookie := range values {
			_, _ = fmt.Fprintf(hash, "cookie=%q\n", cookie)
		}
	}
	return baseURL + "#" + hex.EncodeToString(hash.Sum(nil))
}

// fetchBaseline sends the prepared control request and converts the response
// into a DSL map a template's operators can replay against.
func (request *Request) fetchBaseline(client *retryablehttp.Client, req *retryablehttp.Request, baseURL string) (baseline.Map, error) {

	// respect user rate limiting for the extra control request
	if err := request.rateLimitTake(baseURL); err != nil {
		return nil, err
	}

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

	dslMap := request.responseToDSLMap(respChain.Response(), baseURL, req.String(), "", respChain.FullResponseString(), respChain.BodyString(), respChain.HeadersString(), 0, nil)
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
