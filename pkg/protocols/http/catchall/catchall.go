// Package catchall recognises a match that only happened because the host
// answers every path with the same page.
//
// Many hosts return 200 for paths that do not exist: single page apps, catch-all
// routes, login redirects. A template that requests /.env and matches on a
// status code and a loose word then reports a file that is not there. Directory
// brute forcers solved this long ago (ffuf -ac, skipfish, dirsearch, sqlmap's
// page comparison): ask the host for paths that cannot exist, remember what it
// answers, and discount anything that looks the same.
//
// The baseline is per host, parent directory and path shape, because a .php
// path, a nested path and a trailing slash are often routed to different
// handlers. It is only built once a template matches, so hosts without findings
// never see a probe.
package catchall

import (
	"context"
	"crypto/rand"
	"html"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/projectdiscovery/gcache"
)

const (
	// Threshold is the token similarity at which two pages count as the same.
	// Pages generated from one template differ only in reflected values and
	// tokens, which normalisation removes; real content differs far more.
	Threshold = 0.95
	// DefaultMaxBaselines bounds the cached baselines. Losing one only costs
	// the probes to rebuild it.
	DefaultMaxBaselines = 4096
	// samples is how many random paths are fetched per baseline. Two is the
	// fewest that shows whether the host answers consistently at all.
	samples = 2
	// minReflection is the shortest echoed path worth removing.
	minReflection = 3
)

// dynamic matches values that change on every load, such as CSRF tokens,
// session ids, timestamps and cache busters.
var dynamic = regexp.MustCompile(`[A-Za-z0-9_\-+=]{24,}|\d{6,}`)

// Response is the part of an HTTP response that identifies a catch-all page.
type Response struct {
	StatusCode int
	Location   string
	Body       string
}

// Prober fetches path from the scanned host the same way the matched request
// was sent, so the baseline sees the same redirects, headers and session.
type Prober func(ctx context.Context, path string) (Response, error)

// Detector caches catch-all baselines across templates.
type Detector struct {
	mu        sync.Mutex
	baselines gcache.Cache[string, *baseline]
}

type baseline struct {
	once    sync.Once
	samples []fingerprint
}

type fingerprint struct {
	statusCode int
	location   string
	tokens     map[string]int
	total      int
}

// New returns a detector that keeps up to maxBaselines baselines, or
// DefaultMaxBaselines when maxBaselines is not positive.
func New(maxBaselines int) *Detector {
	if maxBaselines <= 0 {
		maxBaselines = DefaultMaxBaselines
	}
	return &Detector{baselines: gcache.New[string, *baseline](maxBaselines).LRU().Build()}
}

// Matches reports whether resp, received for requestURL, is the page the host
// serves for paths that do not exist.
//
// It only answers yes for 2xx and 3xx responses. A real 404 or 500 page is
// what the host says about every missing path, so a template that matches it
// found something true of the whole host, such as a version in an error page.
func (d *Detector) Matches(ctx context.Context, requestURL *url.URL, resp Response, probe Prober) bool {
	if d == nil || requestURL == nil || !redirectOrSuccess(resp.StatusCode) {
		return false
	}
	requestPath := requestURL.EscapedPath()
	if requestPath == "" || requestPath == "/" {
		return false
	}
	key, shape := shapeOf(requestURL)
	b := d.baseline(key)
	b.once.Do(func() { b.samples = collect(ctx, shape, probe) })
	if len(b.samples) == 0 {
		return false
	}
	got := fingerprintOf(resp, requestPath)
	for _, sample := range b.samples {
		if got.like(sample) {
			return true
		}
	}
	return false
}

func (d *Detector) baseline(key string) *baseline {
	d.mu.Lock()
	defer d.mu.Unlock()
	if b, err := d.baselines.GetIFPresent(key); err == nil {
		return b
	}
	b := &baseline{}
	_ = d.baselines.Set(key, b)
	return b
}

// collect fetches random paths of one shape. It returns nothing when the host
// answers honestly (4xx or 5xx) or so inconsistently that no single page
// stands for "not found"; both mean nothing can be discounted.
func collect(ctx context.Context, shape func(string) string, probe Prober) []fingerprint {
	fingerprints := make([]fingerprint, 0, samples)
	for range samples {
		probePath := shape(strings.ToLower(rand.Text()))
		resp, err := probe(ctx, probePath)
		if err != nil || !redirectOrSuccess(resp.StatusCode) {
			return nil
		}
		fingerprints = append(fingerprints, fingerprintOf(resp, probePath))
	}
	if !fingerprints[0].like(fingerprints[1]) {
		return nil
	}
	return fingerprints
}

// shapeOf returns the cache key for requestURL and a function that builds a
// path of the same shape around a random name: same origin, same extension or
// leading dot, same trailing slash, and nested when the request was.
//
// Probes start at the root rather than in the requested directory. An app
// mounted under a directory, such as Swagger UI under /api-docs/, answers
// every path below it with itself; probing there would mistake the app for
// the host's catch-all page.
func shapeOf(requestURL *url.URL) (string, func(string) string) {
	p := requestURL.EscapedPath()
	trailing := strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")
	dir, name := path.Split(p)
	if dir != "/" {
		dir = "/" + strings.ToLower(rand.Text()) + "/"
	}

	var kind string
	switch {
	case trailing:
		kind = "/"
	case strings.HasPrefix(name, "."):
		kind = "."
	default:
		kind = strings.ToLower(path.Ext(name))
	}
	key := requestURL.Scheme + "://" + requestURL.Host + "\x00" + kind + "\x00" + strconv.FormatBool(dir != "/")
	return key, func(random string) string {
		switch kind {
		case "/":
			return dir + random + "/"
		case ".":
			return dir + "." + random
		default:
			return dir + random + kind
		}
	}
}

func fingerprintOf(resp Response, requestPath string) fingerprint {
	body := normalise(resp.Body, requestPath)
	tokens := map[string]int{}
	total := 0
	for _, token := range strings.FieldsFunc(body, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		tokens[token]++
		total++
	}
	return fingerprint{
		statusCode: resp.StatusCode,
		location:   normalise(resp.Location, requestPath),
		tokens:     tokens,
		total:      total,
	}
}

// normalise removes what differs between two answers for missing paths: the
// requested path echoed back in any of its usual encodings, and values that
// change on every load.
func normalise(s, requestPath string) string {
	if s == "" {
		return s
	}
	decoded, err := url.PathUnescape(requestPath)
	if err != nil {
		decoded = requestPath
	}
	variants := []string{
		requestPath,
		decoded,
		url.QueryEscape(decoded),
		url.PathEscape(decoded),
		html.EscapeString(decoded),
		strings.TrimPrefix(decoded, "/"),
	}
	// Longest first, so a full path is removed before a fragment of it.
	slices.SortFunc(variants, func(a, b string) int { return len(b) - len(a) })
	for _, v := range variants {
		// Removing a one or two letter path would erase unrelated text.
		if len(v) >= minReflection {
			s = strings.ReplaceAll(s, v, "")
		}
	}
	return dynamic.ReplaceAllString(s, "")
}

// like reports whether two fingerprints are the same page: same status, same
// redirect target and nearly the same words, compared as a Dice coefficient
// over word counts.
func (f fingerprint) like(other fingerprint) bool {
	if f.statusCode != other.statusCode || f.location != other.location {
		return false
	}
	if f.total == 0 || other.total == 0 {
		return f.total == other.total
	}
	shared := 0
	for token, count := range f.tokens {
		shared += min(count, other.tokens[token])
	}
	return 2*float64(shared)/float64(f.total+other.total) >= Threshold
}

func redirectOrSuccess(statusCode int) bool {
	return statusCode >= 200 && statusCode < 400
}
