package http

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	httputil "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils/http"
	"github.com/projectdiscovery/retryablehttp-go"
	"golang.org/x/net/http/httpguts"
)

// fuzzCookieJar leaves the cookies under test to the request while retaining
// scope checks and response updates in the shared jar.
type fuzzCookieJar struct {
	http.CookieJar
	names  map[string]struct{}
	fields []fuzzCookieField
	host   string
}

type fuzzCookieField struct {
	name string
	raw  string
	auth bool
}

func (j *fuzzCookieJar) Cookies(u *url.URL) []*http.Cookie {
	cookies := j.CookieJar.Cookies(u)
	retained := cookies[:0]
	for _, cookie := range cookies {
		if _, fuzzed := j.names[cookie.Name]; !fuzzed {
			retained = append(retained, cookie)
		}
	}
	return retained
}

// prepare rebuilds from known field boundaries before each send. Parsing the
// header here would mistake delimiters inside fuzzed values for cookie fields.
func (j *fuzzCookieJar) prepare(req *http.Request) {
	if !j.trustsHost(req) {
		return
	}
	var cookies []*http.Cookie
	if j.CookieJar != nil {
		cookies = j.Cookies(httputil.CookieURL(req))
	}
	stored := make(map[string]struct{}, len(cookies))
	for _, cookie := range cookies {
		stored[cookie.Name] = struct{}{}
	}
	// Analyzer follow-up requests rebuild the component with a different
	// payload. Use that request's fields rather than the initial payload.
	current := httputil.CookieFields(req)
	var retained []string
	for _, field := range j.fields {
		raw := field.raw
		if _, fuzzed := j.names[field.name]; fuzzed {
			for _, candidate := range current {
				name, _, _ := strings.Cut(candidate, "=")
				if name == field.name {
					raw = candidate
					break
				}
			}
		} else if _, exists := stored[field.name]; exists && !field.auth {
			continue
		}
		retained = append(retained, raw)
	}
	if len(retained) == 0 {
		req.Header.Del("Cookie")
	} else {
		req.Header.Set("Cookie", strings.Join(retained, "; "))
	}
}

func (j *fuzzCookieJar) trustsHost(req *http.Request) bool {
	if req.URL == nil {
		return false
	}
	// Match net/http's sensitive-header forwarding rule, including IDNA and
	// the IPv6 zone guard. Cookie jar domain/path/secure checks remain separate.
	host, hostErr := httpguts.PunycodeHostPort(req.URL.Hostname())
	parent, parentErr := httpguts.PunycodeHostPort(j.host)
	if hostErr != nil || parentErr != nil {
		return false
	}
	host, parent = strings.ToLower(host), strings.ToLower(parent)
	return host == parent || (!strings.ContainsAny(host, ":%") && strings.HasSuffix(host, "."+parent))
}

func removeFuzzedCookieFields(req *http.Request, keys []string) {
	fields := httputil.CookieFields(req)
	if strings.Join(fields, "; ") != strings.Join(req.Header.Values("Cookie"), "; ") {
		fields = nil
		for _, header := range req.Header.Values("Cookie") {
			fields = append(fields, httputil.SplitCookieHeader(header)...)
		}
	}
	retained := fields[:0]
	for _, field := range fields {
		name, _, _ := strings.Cut(field, "=")
		if !slices.Contains(keys, strings.TrimSpace(name)) {
			retained = append(retained, field)
		}
	}
	// Auth must not parse delimiter fragments inside the target payload as
	// independent cookies. The immutable structured fields retain that payload
	// for restoration after auth has installed the non-target credentials.
	if len(retained) == 0 {
		req.Header.Del("Cookie")
	} else {
		req.Header.Set("Cookie", strings.Join(retained, "; "))
	}
}

func restoreFuzzedCookieFields(req *http.Request, keys []string) {
	original := httputil.CookieFields(req)
	if strings.Join(original, "; ") == strings.Join(req.Header.Values("Cookie"), "; ") {
		return
	}
	// Auth or custom headers can replace cookies. Keep their non-target
	// fields, then restore only the fields deliberately selected for fuzzing.
	var fields []string
	for _, header := range req.Header.Values("Cookie") {
		for _, field := range httputil.SplitCookieHeader(header) {
			name, _, _ := strings.Cut(field, "=")
			if !slices.Contains(keys, strings.TrimSpace(name)) {
				fields = append(fields, strings.TrimLeft(field, " \t"))
			}
		}
	}
	for _, field := range original {
		name, _, _ := strings.Cut(field, "=")
		if slices.Contains(keys, name) {
			fields = append(fields, field)
		}
	}
	req.Header.Set("Cookie", strings.Join(fields, "; "))
	httputil.SetCookieFields(req, fields)
}

func (request *Request) preserveFuzzedCookies(client *retryablehttp.Client, config *httpclientpool.Configuration, hostname string, req *http.Request, keys []string) (*retryablehttp.Client, error) {
	jar := client.HTTPClient.Jar
	// Explicit input jars already get an isolated client. If an input has no
	// jar, obtain one using the cached jar without modifying the cached client.
	if config.Connection == nil || !config.Connection.HasCookieJar() {
		isolatedJar, ok := jar.(*cookiejar.Jar)
		if jar != nil && !ok {
			return nil, fmt.Errorf("could not isolate cookie jar for cookie fuzzing: unsupported jar %T", jar)
		}
		if jar == nil {
			var err error
			isolatedJar, err = cookiejar.New(nil)
			if err != nil {
				return nil, fmt.Errorf("could not create isolated cookie fuzzing client: %w", err)
			}
		}
		config = config.Clone()
		if config.Connection == nil {
			config.Connection = &httpclientpool.ConnectionConfiguration{}
		}
		config.Connection.SetCookieJar(isolatedJar)
		var err error
		client, err = httpclientpool.Get(request.options.Options, config, hostname)
		if err != nil {
			return nil, fmt.Errorf("could not get isolated cookie fuzzing client: %w", err)
		}
	}
	names := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		names[key] = struct{}{}
	}
	view := &fuzzCookieJar{CookieJar: jar, names: names, host: req.URL.Hostname()}
	for _, field := range httputil.CookieFields(req) {
		name, _, _ := strings.Cut(field, "=")
		name = strings.TrimSpace(name)
		view.fields = append(view.fields, fuzzCookieField{name: name, raw: field, auth: authx.IsAuthCookie(req.Context(), name)})
	}
	if jar != nil {
		client.HTTPClient.Jar = view
	} else {
		// The temporary explicit jar only bypassed the client cache. Cookie
		// reuse remains disabled, including learning response cookies.
		client.HTTPClient.Jar = nil
	}
	// This client belongs to one generated request and its synchronous analyzer
	// follow-ups. Reset protection before each attempt, after any prior redirect.
	client.RequestLogHook = func(req *http.Request, _ int) {
		if jar != nil {
			client.HTTPClient.Jar = view
		}
		view.prepare(req)
	}
	checkRedirect := client.HTTPClient.CheckRedirect
	client.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		trusted := view.trustsHost(req)
		for _, previous := range via {
			trusted = trusted && view.trustsHost(previous)
		}
		if !trusted {
			// Go permanently strips the explicit cookies after an untrusted
			// hop. Use the base jar from then on, including a return to the origin.
			client.HTTPClient.Jar = jar
		}
		if err := checkRedirect(req, via); err != nil {
			return err
		}
		if trusted {
			view.prepare(req)
		}
		return nil
	}
	return client, nil
}
