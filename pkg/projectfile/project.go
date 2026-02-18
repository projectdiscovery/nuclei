package projectfile

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/hmap/store/hybrid"
)

var (
	ErrNotFound          = errors.New("not found")
	regexUserAgent       = regexp.MustCompile(`(?mi)\r\nUser-Agent: .+\r\n`)
	regexDefaultInteract = regexp.MustCompile(`(?mi)[a-zA-Z1-9%.]+interact.sh`)
)

type Options struct {
	Path    string
	Cleanup bool
}

type ProjectFile struct {
	Path string
	hm   *hybrid.HybridMap
}

func New(options *Options) (*ProjectFile, error) {
	var p ProjectFile
	hOptions := hybrid.DefaultDiskOptions
	hOptions.Path = options.Path
	hOptions.Cleanup = options.Cleanup
	var err error
	p.hm, err = hybrid.New(hOptions)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func (pf *ProjectFile) cleanupData(data []byte) []byte {
	// ignore all user agents
	data = regexUserAgent.ReplaceAll(data, []byte("\r\n"))
	// ignore interact markers
	return regexDefaultInteract.ReplaceAll(data, []byte(""))
}

// normalizeURL canonicalizes a URL for use as a cache key prefix.
// It lowercases scheme and host, strips default ports (80/443),
// and ensures a trailing slash on bare-host URLs.
func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// Strip default ports
	hostname := u.Hostname()
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		u.Host = hostname
	}

	// Ensure root path has trailing slash for consistency
	if u.Path == "" {
		u.Path = "/"
	}

	return u.String()
}

// cacheKey builds a unique cache key from the request data and optional URL.
// Including the URL ensures requests to different schemes (http vs https)
// or ports produce distinct cache entries.
func (pf *ProjectFile) cacheKey(req []byte, reqURL string) []byte {
	cleaned := pf.cleanupData(req)
	if reqURL == "" {
		return cleaned
	}
	return append([]byte(normalizeURL(reqURL)+"\n"), cleaned...)
}

// Get retrieves a cached response. The reqURL parameter is included in the
// cache key to isolate entries by scheme and port (e.g. http vs https).
func (pf *ProjectFile) Get(req []byte, reqURL string) (*http.Response, error) {
	reqHash, err := hash(pf.cacheKey(req, reqURL))
	if err != nil {
		return nil, err
	}

	data, ok := pf.hm.Get(reqHash)
	if !ok {
		return nil, ErrNotFound
	}

	var httpRecord HTTPRecord
	httpRecord.Response = newInternalResponse()
	if err := unmarshal(data, &httpRecord); err != nil {
		return nil, err
	}

	return fromInternalResponse(httpRecord.Response), nil
}

// Set stores a response in the cache. The reqURL parameter is included in the
// cache key to isolate entries by scheme and port (e.g. http vs https).
func (pf *ProjectFile) Set(req []byte, reqURL string, resp *http.Response, data []byte) error {
	reqHash, err := hash(pf.cacheKey(req, reqURL))
	if err != nil {
		return err
	}

	var httpRecord HTTPRecord
	httpRecord.Request = req
	httpRecord.Response = toInternalResponse(resp, data)
	data, err = marshal(httpRecord)
	if err != nil {
		return err
	}

	return pf.hm.Set(reqHash, data)
}

func (pf *ProjectFile) Close() {
	_ = pf.hm.Close()
}
