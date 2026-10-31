package runner

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/core/techfilter"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	httpProtocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httprespcache"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/retryablehttp-go"
	syncutil "github.com/projectdiscovery/utils/sync"
	unitutils "github.com/projectdiscovery/utils/unit"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const (
	techFilterWorkers      = 50
	techFilterMaxBody      = 1 * unitutils.Mega
	techFilterHTTPTimeout  = 5 * time.Second
	techFilterMaxRedirects = 5
)

// techReachabilityIndex filters template×target pairs by product/macro tags.
type techReachabilityIndex struct {
	byInput map[string]techfilter.HostProfile // keyed by normalizeInputKey

	// boundTags memoizes template ID -> product tags. It is filled lazily from
	// the template execution goroutines, so every access needs the mutex.
	tagsMu    sync.RWMutex
	boundTags map[string][]string
}

func normalizeInputKey(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

// Allow is fail-open: missing profile or unbound template => true.
func (idx *techReachabilityIndex) Allow(t *templates.Template, mi *contextargs.MetaInput) bool {
	if idx == nil || t == nil || mi == nil {
		return true
	}
	profile, ok := idx.lookup(mi.Input)
	if !ok {
		return true
	}
	return techfilter.AllowTags(profile, idx.tagsFor(t))
}

func (idx *techReachabilityIndex) tagsFor(t *templates.Template) []string {
	if t == nil {
		return nil
	}
	idx.tagsMu.RLock()
	tags, ok := idx.boundTags[t.ID]
	idx.tagsMu.RUnlock()
	if ok {
		return tags
	}

	tags = techfilter.TemplateProductTags(t)

	idx.tagsMu.Lock()
	defer idx.tagsMu.Unlock()
	if idx.boundTags == nil {
		idx.boundTags = make(map[string][]string)
	}
	// Another goroutine may have won the race; keep one slice per template ID.
	if existing, ok := idx.boundTags[t.ID]; ok {
		return existing
	}
	idx.boundTags[t.ID] = tags
	return tags
}

func (idx *techReachabilityIndex) lookup(raw string) (techfilter.HostProfile, bool) {
	if idx == nil || idx.byInput == nil {
		return techfilter.HostProfile{}, false
	}
	if p, ok := idx.byInput[normalizeInputKey(raw)]; ok {
		return p, true
	}
	if p, ok := idx.byInput[raw]; ok {
		return p, true
	}
	return techfilter.HostProfile{}, false
}

// buildTechReachability fingerprints HTTP(S) targets and builds a tag index.
// When cache is non-nil, fingerprint GET responses seed it so matching template
// GETs pay no extra RTT.
func (r *Runner) buildTechReachability(tpls []*templates.Template, httpHelper *input.Helper, cache *httprespcache.Cache) (*techReachabilityIndex, error) {
	_ = tpls
	wapp, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}
	// Redirects must be followed. A site that answers "/" with a 302 to its real
	// entry point (WordPress -> /wp-admin/install.php, any app -> /login) returns
	// an empty body, so the probe would detect nothing and every template bound
	// to the undetected product would be pruned. Same-host only, so the probe
	// never leaves the target authority.
	httpclient, err := httpclientpool.Get(r.options, &httpclientpool.Configuration{
		DisableCookie:         true,
		ResponseHeaderTimeout: techFilterHTTPTimeout,
		RedirectFlow:          httpclientpool.FollowSameHostRedirect,
		MaxRedirects:          techFilterMaxRedirects,
	}, "")
	if err != nil {
		return nil, err
	}

	idx := &techReachabilityIndex{
		byInput:   make(map[string]techfilter.HostProfile),
		boundTags: make(map[string][]string),
	}
	var mu sync.Mutex
	sg, err := syncutil.New(syncutil.WithSize(techFilterWorkers))
	if err != nil {
		return nil, err
	}

	fingerprinted := 0
	eligible := 0
	r.inputProvider.Iterate(func(mi *contextargs.MetaInput) bool {
		if mi == nil || mi.Input == "" {
			return true
		}
		fpURL := fingerprintURLForInput(mi.Input, httpHelper)
		if fpURL == "" {
			return true
		}
		eligible++
		sg.Add()
		go func(inputKey, url string) {
			defer sg.Done()
			profile := fingerprintTarget(wapp, httpclient, url, cache)
			key := normalizeInputKey(inputKey)
			mu.Lock()
			idx.byInput[key] = profile
			if profile.HasTags() {
				fingerprinted++
			}
			mu.Unlock()
		}(mi.Input, fpURL)
		return true
	})
	sg.Wait()

	gologger.Info().Msgf("tech-filter: fingerprinted=%d/%d hosts with tags (eligible=%d)", fingerprinted, len(idx.byInput), eligible)
	return idx, nil
}

// fingerprintURLForInput returns an absolute http(s) URL to fingerprint, or "".
// Bare hosts reuse InputsHTTP probed URLs when available.
func fingerprintURLForInput(raw string, helper *input.Helper) string {
	if looksLikeHTTPTarget(raw) {
		return raw
	}
	if helper != nil && helper.InputsHTTP != nil {
		if probed, ok := helper.InputsHTTP.Get(raw); ok && len(probed) > 0 {
			return string(probed)
		}
	}
	return ""
}

func looksLikeHTTPTarget(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func fingerprintTarget(wapp *wappalyzer.Wappalyze, client *retryablehttp.Client, rawURL string, cache *httprespcache.Cache) techfilter.HostProfile {
	// Prefer a trailing-slash form that matches typical {{BaseURL}}/ template URLs.
	seedURL := rawURL
	if !strings.HasSuffix(seedURL, "/") {
		seedURL = seedURL + "/"
	}
	req, err := retryablehttp.NewRequest(http.MethodGet, seedURL, nil)
	if err != nil {
		return techfilter.HostProfile{}
	}
	// Same user agent the templates will send, so the response seeded below is
	// reachable from the cache instead of being stored under a key nothing hits.
	req.Header.Set("User-Agent", httpProtocol.StableUserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return techfilter.HostProfile{}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, techFilterMaxBody))
	if err != nil {
		return techfilter.HostProfile{}
	}
	if cache != nil {
		seedFingerprintResponse(cache, req, resp, body, seedURL)
	}
	info := wapp.FingerprintWithInfo(resp.Header, body)
	products := make(map[string][]string, len(info))
	for name, app := range info {
		products[name] = append([]string(nil), app.Categories...)
	}
	return techfilter.ProfileFromFingerprint(products)
}

// seedFingerprintResponse stores the probe response under the URL it actually
// belongs to, so templates can reuse the RTT.
//
// The probe follows redirects, so resp may describe a different URL than the one
// requested. Seeding it under the requested URL would hand every template that
// asks for that URL the redirect target's status, headers and body instead of
// the redirect itself, which silently changes what they match on.
func seedFingerprintResponse(cache *httprespcache.Cache, req *retryablehttp.Request, resp *http.Response, body []byte, seedURL string) {
	finalURL := seedURL
	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	if finalURL == seedURL {
		cache.SeedHTTP(req.Request, resp, body, techFilterMaxBody)
		return
	}
	finalReq := req.Request.Clone(req.Context())
	finalReq.URL = resp.Request.URL
	finalReq.Host = ""
	cache.SeedHTTP(finalReq, resp, body, techFilterMaxBody)
}

// estimateTechFilteredExecutions counts template×host pairs that survive the tech filter.
func estimateTechFilteredExecutions(tpls []*templates.Template, idx *techReachabilityIndex, hostCount int) (baseline, filtered int) {
	baseline = estimateTemplateRequests(tpls) * hostCount
	if idx == nil || len(idx.byInput) == 0 {
		return baseline, baseline
	}
	filtered = 0
	for _, t := range tpls {
		reqs := t.TotalRequests
		if reqs <= 0 {
			reqs = 1
		}
		if len(t.Workflows) > 0 {
			continue
		}
		tags := idx.tagsFor(t)
		for _, profile := range idx.byInput {
			if techfilter.AllowTags(profile, tags) {
				filtered += reqs
			}
		}
		missing := hostCount - len(idx.byInput)
		if missing > 0 {
			filtered += reqs * missing
		}
	}
	return baseline, filtered
}

// composeTemplateFilters ANDs optional filters; nil filters are ignored.
func composeTemplateFilters(filters ...func(*templates.Template, *contextargs.MetaInput) bool) func(*templates.Template, *contextargs.MetaInput) bool {
	var active []func(*templates.Template, *contextargs.MetaInput) bool
	for _, f := range filters {
		if f != nil {
			active = append(active, f)
		}
	}
	if len(active) == 0 {
		return nil
	}
	return func(t *templates.Template, mi *contextargs.MetaInput) bool {
		for _, f := range active {
			if !f(t, mi) {
				return false
			}
		}
		return true
	}
}
