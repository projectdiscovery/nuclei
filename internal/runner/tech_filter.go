package runner

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/core/techfilter"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httprespcache"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/useragent"
	syncutil "github.com/projectdiscovery/utils/sync"
	unitutils "github.com/projectdiscovery/utils/unit"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const (
	techFilterWorkers     = 50
	techFilterMaxBody     = 1 * unitutils.Mega
	techFilterHTTPTimeout = 5 * time.Second
)

// techReachabilityIndex filters template×target pairs by product/macro tags.
type techReachabilityIndex struct {
	byInput map[string]techfilter.HostProfile // keyed by normalizeInputKey
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
	return techfilter.Allow(profile, t)
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

// AllowClusterMember adapts Allow for ClusterExecuter (template ID + info only).
func (idx *techReachabilityIndex) AllowClusterMember(templateID string, info model.Info, mi *contextargs.MetaInput) bool {
	stub := &templates.Template{ID: templateID, Info: info}
	return idx.Allow(stub, mi)
}

// buildTechReachability fingerprints HTTP(S) targets and builds a tag index.
// When cache is non-nil, fingerprint GET responses seed it so matching template
// GETs pay no extra RTT.
func (r *Runner) buildTechReachability(tpls []*templates.Template, cache *httprespcache.Cache) (*techReachabilityIndex, error) {
	_ = tpls
	wapp, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}
	httpclient, err := httpclientpool.Get(r.options, &httpclientpool.Configuration{
		DisableCookie:         true,
		ResponseHeaderTimeout: techFilterHTTPTimeout,
	}, "")
	if err != nil {
		return nil, err
	}

	idx := &techReachabilityIndex{byInput: make(map[string]techfilter.HostProfile)}
	var mu sync.Mutex
	sg, err := syncutil.New(syncutil.WithSize(techFilterWorkers))
	if err != nil {
		return nil, err
	}

	fingerprinted := 0
	r.inputProvider.Iterate(func(mi *contextargs.MetaInput) bool {
		if mi == nil || mi.Input == "" {
			return true
		}
		if !looksLikeHTTPTarget(mi.Input) {
			return true
		}
		sg.Add()
		go func(input *contextargs.MetaInput) {
			defer sg.Done()
			profile := fingerprintTarget(wapp, httpclient, input.Input, cache)
			key := normalizeInputKey(input.Input)
			mu.Lock()
			idx.byInput[key] = profile
			if profile.HasTags() {
				fingerprinted++
			}
			mu.Unlock()
		}(mi)
		return true
	})
	sg.Wait()

	gologger.Info().Msgf("tech-filter: fingerprinted=%d/%d hosts with tags", fingerprinted, len(idx.byInput))
	return idx, nil
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
	req.Header.Set("User-Agent", useragent.PickRandom().Raw)
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
		// Seed both the requested URL and the absolute URL the client ended on.
		cache.SeedHTTP(http.MethodGet, seedURL, resp, body)
		if resp.Request != nil && resp.Request.URL != nil {
			cache.SeedHTTP(http.MethodGet, resp.Request.URL.String(), resp, body)
		}
	}
	info := wapp.FingerprintWithInfo(resp.Header, body)
	products := make(map[string][]string, len(info))
	for name, app := range info {
		products[name] = append([]string(nil), app.Categories...)
	}
	return techfilter.ProfileFromFingerprint(products)
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
		for _, profile := range idx.byInput {
			if techfilter.Allow(profile, t) {
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
