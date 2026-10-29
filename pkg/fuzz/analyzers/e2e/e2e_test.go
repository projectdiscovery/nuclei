// Package e2e contains end-to-end tests for every fuzzer analyzer. Each test
// spins up an httptest server that genuinely simulates the target vulnerability
// (and a benign variant for false-positive checks), builds a real fuzz
// GeneratedRequest from a real query Component, and drives the registered
// analyzer's full Analyze() path through a real retryablehttp client.
//
// This exercises the production code paths end to end: registration, value
// mutation, request rebuild + auth-header preservation, transport, and
// response analysis — not just the pure detection helpers.
package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"

	// register every analyzer under test
	_ "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/cmdi"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/cors"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/crlf"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/hostheader"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/lfi"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/redirect"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/sqli"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/ssrf"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers/ssti"
)

// newClient builds a retryablehttp client; when follow is false redirects are
// not followed (matching nuclei's default), so the Location header is visible.
func newClient(follow bool) *retryablehttp.Client {
	c := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	if !follow {
		c.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}

// newGeneratedRequest builds a real GeneratedRequest fuzzing the "q" query
// parameter of the given server, using the production query Component.
func newGeneratedRequest(t *testing.T, serverURL, key, origValue string) fuzz.GeneratedRequest {
	t.Helper()
	target := serverURL + "/?" + key + "=" + url.QueryEscape(origValue)
	raw, err := retryablehttp.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)

	q := component.NewQuery()
	parsed, err := q.Parse(raw)
	require.NoError(t, err)
	require.True(t, parsed, "query component must parse")

	return fuzz.GeneratedRequest{
		Request:       raw,
		Component:     q,
		Parameter:     key,
		Key:           key,
		Value:         origValue,
		OriginalValue: origValue,
	}
}

// run fetches the named analyzer and runs Analyze against the given request.
func run(t *testing.T, name string, gr fuzz.GeneratedRequest, client *retryablehttp.Client) (bool, string) {
	t.Helper()
	a := analyzers.GetAnalyzer(name)
	require.NotNil(t, a, "analyzer %q must be registered", name)
	matched, reason, err := a.Analyze(&analyzers.Options{
		FuzzGenerated: gr,
		HttpClient:    client,
	})
	require.NoError(t, err)
	return matched, reason
}

func qparam(r *http.Request) string { return r.URL.Query().Get("q") }

// ---------------------------------------------------------------------------
// SSTI
// ---------------------------------------------------------------------------

// reTpl emulates a template engine: it matches an arithmetic expression wrapped
// in a delimiter pair (EL ${}, Jinja {{}}, #{}, *{}, Razor @(), ERB <%= %>,
// Smarty {}) and replaces the WHOLE delimited expression with its product, the
// way a real engine would — so the surrounding sentinels become adjacent to the
// computed value.
var reTpl = regexp.MustCompile(`(?:\$\{|\{\{|#\{|\*\{|@\(|<%=|\{)\s*(\d+)\s*\*\s*(\d+)\s*(?:\}\}|%>|\}|\))`)

func TestSSTI_E2E(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := reTpl.ReplaceAllStringFunc(qparam(r), func(m string) string {
			sub := reTpl.FindStringSubmatch(m)
			return fmt.Sprintf("%d", atoi(sub[1])*atoi(sub[2]))
		})
		_, _ = fmt.Fprintf(w, "<html><body>%s</body></html>", out)
	}))
	defer vuln.Close()

	matched, reason := run(t, "ssti", newGeneratedRequest(t, vuln.URL, "q", "test"), newClient(true))
	require.True(t, matched, "ssti should be detected on evaluating server")
	require.Contains(t, reason, "ssti")

	// benign server reflects the payload verbatim (no evaluation)
	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "<html><body>%s</body></html>", qparam(r))
	}))
	defer benign.Close()

	matched, _ = run(t, "ssti", newGeneratedRequest(t, benign.URL, "q", "test"), newClient(true))
	require.False(t, matched, "ssti must not fire when payload is only reflected")
}

// ---------------------------------------------------------------------------
// SQL injection (error-based)
// ---------------------------------------------------------------------------

func TestSQLi_E2E(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := qparam(r)
		if strings.ContainsAny(q, "'\"`\\") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''")
			return
		}
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer vuln.Close()

	matched, reason := run(t, "sqli_error", newGeneratedRequest(t, vuln.URL, "q", "test"), newClient(true))
	require.True(t, matched)
	require.Contains(t, reason, "MySQL")

	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "results for %q", qparam(r))
	}))
	defer benign.Close()
	matched, _ = run(t, "sqli_error", newGeneratedRequest(t, benign.URL, "q", "test"), newClient(true))
	require.False(t, matched)
}

// ---------------------------------------------------------------------------
// LFI / path traversal
// ---------------------------------------------------------------------------

func TestLFI_E2E(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := qparam(r)
		switch {
		case strings.Contains(q, "etc/passwd"):
			_, _ = fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
		case strings.Contains(strings.ToLower(q), "win.ini"):
			_, _ = fmt.Fprint(w, "; for 16-bit app support\r\n[fonts]\r\n")
		default:
			_, _ = fmt.Fprint(w, "file not found")
		}
	}))
	defer vuln.Close()

	matched, reason := run(t, "lfi", newGeneratedRequest(t, vuln.URL, "q", "home.txt"), newClient(true))
	require.True(t, matched)
	require.Contains(t, reason, "/etc/passwd")

	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "file not found")
	}))
	defer benign.Close()
	matched, _ = run(t, "lfi", newGeneratedRequest(t, benign.URL, "q", "home.txt"), newClient(true))
	require.False(t, matched)
}

// ---------------------------------------------------------------------------
// SSRF (cloud metadata)
// ---------------------------------------------------------------------------

func TestSSRF_E2E(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := qparam(r)
		if strings.Contains(q, "169.254.169.254") || strings.Contains(q, "metadata.google.internal") {
			_, _ = fmt.Fprint(w, `{"accountId":"123456789012","imageId":"ami-0abcd1234ef567890","instanceId":"i-0abcd1234ef567890","region":"us-east-1"}`)
			return
		}
		_, _ = fmt.Fprint(w, "fetched: nothing interesting")
	}))
	defer vuln.Close()

	matched, reason := run(t, "ssrf", newGeneratedRequest(t, vuln.URL, "q", "https://example.com/avatar.png"), newClient(true))
	require.True(t, matched)
	require.Contains(t, reason, "AWS")

	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "fetched ok")
	}))
	defer benign.Close()
	matched, _ = run(t, "ssrf", newGeneratedRequest(t, benign.URL, "q", "https://example.com/a.png"), newClient(true))
	require.False(t, matched)
}

// ---------------------------------------------------------------------------
// OS command injection (in-band)
// ---------------------------------------------------------------------------

func TestCMDi_E2E(t *testing.T) {
	seps := []string{";id", "|id", "||id", "&&id", "&id", "`id`", "$(id)", "\nid"}
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := qparam(r)
		for _, s := range seps {
			if strings.Contains(q, s) {
				_, _ = fmt.Fprint(w, "uid=0(root) gid=0(root) groups=0(root)")
				return
			}
		}
		_, _ = fmt.Fprintf(w, "ping output for %s", q)
	}))
	defer vuln.Close()

	matched, reason := run(t, "cmdi", newGeneratedRequest(t, vuln.URL, "q", "127.0.0.1"), newClient(true))
	require.True(t, matched)
	require.Contains(t, reason, "cmdi")

	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "ping output for %s", qparam(r))
	}))
	defer benign.Close()
	matched, _ = run(t, "cmdi", newGeneratedRequest(t, benign.URL, "q", "127.0.0.1"), newClient(true))
	require.False(t, matched)
}

// ---------------------------------------------------------------------------
// CRLF injection / response splitting
// ---------------------------------------------------------------------------

func TestCRLF_E2E(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// naive Location built from user input, splitting on newlines (the bug)
		q := qparam(r)
		for _, line := range strings.Split(q, "\n") {
			line = strings.TrimRight(line, "\r")
			idx := strings.Index(line, ": ")
			if idx <= 0 || strings.ContainsAny(line[:idx], " \t") {
				continue
			}
			name, val := line[:idx], line[idx+2:]
			if strings.EqualFold(name, "Set-Cookie") {
				w.Header().Add("Set-Cookie", val)
			} else {
				w.Header().Set(name, val)
			}
		}
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer vuln.Close()

	matched, reason := run(t, "crlf", newGeneratedRequest(t, vuln.URL, "q", "/home"), newClient(false))
	require.True(t, matched)
	require.Contains(t, reason, "crlf")

	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer benign.Close()
	matched, _ = run(t, "crlf", newGeneratedRequest(t, benign.URL, "q", "/home"), newClient(false))
	require.False(t, matched)
}

// ---------------------------------------------------------------------------
// Open redirect
// ---------------------------------------------------------------------------

func TestOpenRedirect_E2E(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// reflects the user-controlled destination straight into Location
		w.Header().Set("Location", qparam(r))
		w.WriteHeader(http.StatusFound)
	}))
	defer vuln.Close()

	matched, reason := run(t, "open_redirect", newGeneratedRequest(t, vuln.URL, "q", "/dashboard"), newClient(false))
	require.True(t, matched)
	require.Contains(t, reason, "open redirect")

	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// always redirects to a fixed, trusted location regardless of input
		w.Header().Set("Location", "/dashboard")
		w.WriteHeader(http.StatusFound)
	}))
	defer benign.Close()
	matched, _ = run(t, "open_redirect", newGeneratedRequest(t, benign.URL, "q", "/dashboard"), newClient(false))
	require.False(t, matched)
}

// ---------------------------------------------------------------------------
// CORS misconfiguration
// ---------------------------------------------------------------------------

func TestCORS_E2E(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin) // reflects arbitrary origin
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer vuln.Close()

	matched, reason := run(t, "cors", newGeneratedRequest(t, vuln.URL, "q", "x"), newClient(true))
	require.True(t, matched)
	require.Contains(t, reason, "cors")

	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// only allows a single trusted origin
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer benign.Close()
	matched, _ = run(t, "cors", newGeneratedRequest(t, benign.URL, "q", "x"), newClient(true))
	require.False(t, matched)
}

// ---------------------------------------------------------------------------
// Host header injection
// ---------------------------------------------------------------------------

func TestHostHeader_E2E(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		_, _ = fmt.Fprintf(w, `<a href="https://%s/reset?token=abc">reset</a>`, host)
	}))
	defer vuln.Close()

	matched, reason := run(t, "host_header_injection", newGeneratedRequest(t, vuln.URL, "q", "x"), newClient(true))
	require.True(t, matched)
	require.Contains(t, reason, "host header injection")

	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// always uses a fixed, trusted host
		_, _ = fmt.Fprint(w, `<a href="https://app.example.com/reset?token=abc">reset</a>`)
	}))
	defer benign.Close()
	matched, _ = run(t, "host_header_injection", newGeneratedRequest(t, benign.URL, "q", "x"), newClient(true))
	require.False(t, matched)
}

// ---------------------------------------------------------------------------
// Auth-header preservation across follow-up probes
// ---------------------------------------------------------------------------

// TestAuthHeaderPreserved_E2E proves the analyzer's rebuilt probe requests carry
// post-parse injected headers (e.g. the Authorization header an authprovider
// would add). The server only reveals the SQL error to authenticated requests,
// so detection succeeds only if the header survived Rebuild — exactly what the
// shared SetValueAndRebuild helper guarantees.
func TestAuthHeaderPreserved_E2E(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cr3t" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, "unauthorized")
			return
		}
		if strings.ContainsAny(qparam(r), "'\"") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax")
			return
		}
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer vuln.Close()

	// authenticated: header injected post-parse, like the authprovider does
	gr := newGeneratedRequest(t, vuln.URL, "q", "test")
	gr.Request.Header.Set("Authorization", "Bearer s3cr3t")
	matched, _ := run(t, "sqli_error", gr, newClient(true))
	require.True(t, matched, "auth header must be preserved on rebuilt probes for detection")

	// control: no auth header => server always 401 => nothing detectable. Proves
	// the positive result depended on header preservation, not luck.
	matched2, _ := run(t, "sqli_error", newGeneratedRequest(t, vuln.URL, "q", "test"), newClient(true))
	require.False(t, matched2, "without the auth header the server stays benign (401)")
}

// ---------------------------------------------------------------------------
// Non-query component (JSON body) end-to-end
// ---------------------------------------------------------------------------

// TestBodyComponentCMDi_E2E drives an analyzer through a real JSON body
// Component instead of the query component, exercising body mutation + rebuild.
func TestBodyComponentCMDi_E2E(t *testing.T) {
	seps := []string{";id", "|id", "&&id", "$(id)", "`id`"}
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		s := string(data)
		for _, sep := range seps {
			if strings.Contains(s, sep) {
				_, _ = fmt.Fprint(w, "uid=0(root) gid=0(root) groups=0(root)")
				return
			}
		}
		_, _ = fmt.Fprint(w, "pong")
	}))
	defer vuln.Close()

	raw, err := retryablehttp.NewRequest(http.MethodPost, vuln.URL+"/", strings.NewReader(`{"host":"127.0.0.1"}`))
	require.NoError(t, err)
	raw.Header.Set("Content-Type", "application/json")

	b := component.NewBody()
	parsed, err := b.Parse(raw)
	require.NoError(t, err)
	require.True(t, parsed, "body component must parse JSON")

	gr := fuzz.GeneratedRequest{
		Request:       raw,
		Component:     b,
		Parameter:     "host",
		Key:           "host",
		Value:         "127.0.0.1",
		OriginalValue: "127.0.0.1",
	}
	matched, reason := run(t, "cmdi", gr, newClient(true))
	require.True(t, matched, "cmdi should be detected through a JSON body component")
	require.Contains(t, reason, "cmdi")
}

// ---------------------------------------------------------------------------
// Component breadth: the same analyzer must work across all fuzzable component
// types (query already covered above; here header, cookie and path).
// ---------------------------------------------------------------------------

// sqlErrorIf returns a handler that emits a MySQL error when value contains a
// quote, else a benign page. extract pulls the relevant value from the request.
func sqlErrorIf(extract func(*http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(extract(r), "'\"") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax")
			return
		}
		_, _ = fmt.Fprint(w, "ok")
	}
}

func grFor(t *testing.T, raw *retryablehttp.Request, comp component.Component, key, origValue string) fuzz.GeneratedRequest {
	t.Helper()
	parsed, err := comp.Parse(raw)
	require.NoError(t, err)
	require.True(t, parsed, "%s component must parse", comp.Name())
	return fuzz.GeneratedRequest{
		Request:       raw,
		Component:     comp,
		Parameter:     key,
		Key:           key,
		Value:         origValue,
		OriginalValue: origValue,
	}
}

func TestSQLi_HeaderComponent_E2E(t *testing.T) {
	srv := httptest.NewServer(sqlErrorIf(func(r *http.Request) string { return r.Header.Get("X-Search") }))
	defer srv.Close()

	raw, err := retryablehttp.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	raw.Header.Set("X-Search", "term")

	matched, _ := run(t, "sqli_error", grFor(t, raw, component.NewHeader(), "X-Search", "term"), newClient(true))
	require.True(t, matched, "sqli must be detected when fuzzing a header component")
}

func TestSSTI_CookieComponent_E2E(t *testing.T) {
	// SQL quote payloads can't survive in a cookie value (Go strips RFC6265
	// forbidden bytes), so we demonstrate cookie-component fuzzing with SSTI,
	// whose payload characters ({ } * $) are cookie-legal.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("lang")
		val := "en"
		if err == nil {
			val = c.Value
		}
		out := reTpl.ReplaceAllStringFunc(val, func(m string) string {
			sub := reTpl.FindStringSubmatch(m)
			return fmt.Sprintf("%d", atoi(sub[1])*atoi(sub[2]))
		})
		_, _ = fmt.Fprintf(w, "<html><body>lang=%s</body></html>", out)
	}))
	defer srv.Close()

	raw, err := retryablehttp.NewRequest(http.MethodGet, srv.URL+"/", nil)
	require.NoError(t, err)
	raw.Header.Set("Cookie", "lang=en")

	matched, _ := run(t, "ssti", grFor(t, raw, component.NewCookie(), "lang", "en"), newClient(true))
	require.True(t, matched, "ssti must be detected when fuzzing a cookie component")
}

func TestSQLi_PathComponent_E2E(t *testing.T) {
	// any quote anywhere in the decoded path triggers the error
	srv := httptest.NewServer(sqlErrorIf(func(r *http.Request) string {
		dec, _ := url.PathUnescape(r.URL.EscapedPath())
		return dec
	}))
	defer srv.Close()

	raw, err := retryablehttp.NewRequest(http.MethodGet, srv.URL+"/user/75/profile", nil)
	require.NoError(t, err)

	path := component.NewPath()
	parsed, err := path.Parse(raw)
	require.NoError(t, err)
	require.True(t, parsed)

	// locate the path segment whose value is "75"
	var key string
	require.NoError(t, path.Iterate(func(k string, v interface{}) error {
		if fmt.Sprint(v) == "75" {
			key = k
		}
		return nil
	}))
	require.NotEmpty(t, key, "expected to find the id path segment")

	gr := fuzz.GeneratedRequest{Request: raw, Component: path, Parameter: key, Key: key, Value: "75", OriginalValue: "75"}
	matched, _ := run(t, "sqli_error", gr, newClient(true))
	require.True(t, matched, "sqli must be detected when fuzzing a path component")
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}
