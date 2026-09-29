//go:build regression

// Package sdk_test contains an opt-in, large-scale regression harness for the
// HTTP engine. It is gated behind the "regression" build tag so it never runs
// as part of the normal unit/integration suites; run it explicitly with:
//
//	go test -tags regression ./lib/tests/ -run TestScaleRegression -v
//
// Tune the host count with NUCLEI_SCALE_HOSTS (default 50).
//
// The harness stands up many independent loopback HTTP hosts and runs a diverse
// template set (word/header/regex/status/dsl/extractor matchers, redirects, raw
// requests and a multi-step cookie-reuse flow) through the engine, asserting
// that every host yields the full expected finding set. It also includes a host
// that emits the "plain HTTP request was sent to HTTPS port" 400 body to
// exercise the HTTP->HTTPS port tracker: a wrongly detected/false-positive scheme
// rewrite must not silently drop findings of unrelated templates hitting the
// same host:port (regression guard for the tracker fallback).
package sdk_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

// scaleTemplates is the diverse template set exercised by the harness. Each one
// deterministically matches every host so per-template finding counts must
// equal the number of hosts.
var scaleTemplates = map[string]string{
	"01-basic-word.yaml": `id: scale-basic-word
info: {name: Scale Basic Word, author: regression, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers-condition: and
    matchers:
      - {type: word, part: body, words: ["REGRESSION-OK"]}
      - {type: status, status: [200]}
`,
	"02-header-match.yaml": `id: scale-header-match
info: {name: Scale Header Match, author: regression, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - {type: word, part: header, words: ["nuclei-regression"]}
`,
	"03-regex.yaml": `id: scale-regex
info: {name: Scale Regex, author: regression, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - {type: regex, part: body, regex: ["token=[A-Z0-9]{6}"]}
`,
	"04-multi-cookie.yaml": `id: scale-multi-cookie
info: {name: Scale Multi-step Cookie Reuse, author: regression, severity: info}
http:
  - cookie-reuse: true
    raw:
      - |
        GET /login HTTP/1.1
        Host: {{Hostname}}
        User-Agent: regression

      - |
        GET /profile HTTP/1.1
        Host: {{Hostname}}
        User-Agent: regression

    matchers:
      - {type: word, part: body, words: ["welcome-admin"]}
`,
	"05-redirect.yaml": `id: scale-redirect
info: {name: Scale Redirect, author: regression, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/redirect"]
    host-redirects: true
    max-redirects: 3
    matchers:
      - {type: word, part: body, words: ["REGRESSION-OK"]}
`,
	"06-raw.yaml": `id: scale-raw
info: {name: Scale Raw Request, author: regression, severity: info}
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        User-Agent: regression-raw

    matchers-condition: and
    matchers:
      - {type: status, status: [200]}
      - {type: word, part: body, words: ["build=stable"]}
`,
	"07-dsl-json.yaml": `id: scale-dsl-json
info: {name: Scale DSL JSON, author: regression, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/api"]
    matchers:
      - {type: dsl, dsl: ['contains(body, "\"admin\":true") && status_code == 200']}
`,
	"08-extractor.yaml": `id: scale-extractor
info: {name: Scale Extractor, author: regression, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/api"]
    extractors:
      - {type: regex, part: body, regex: ['"version":"([0-9.]+)"'], group: 1}
    matchers:
      - {type: word, part: body, words: ["active"]}
`,
	// This template triggers the HTTP->HTTPS port tracker. With the fallback in
	// place, the tracker must not cause the other plain-HTTP templates above to
	// be dropped on the same host:port.
	"09-httpsport.yaml": `id: scale-httpsport
info: {name: Scale HTTP to HTTPS Port, author: regression, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/httpsport"]
    matchers:
      - {type: word, part: body, words: ["plain HTTP request was sent to HTTPS port"]}
`,
}

// scaleHandler serves deterministic, template-matchable content. The /httpsport
// endpoint mimics a server that received plain HTTP on an HTTPS port.
func scaleHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Reg", "nuclei-regression")
		w.Header().Set("Server", "regression-test/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("REGRESSION-OK token=ABC123 build=stable\n"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sess", Value: "valid-token", Path: "/"})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("logged-in\n"))
	})
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sess"); err != nil || c.Value != "valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("welcome-admin profile-data\n"))
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("/httpsport", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Client sent an HTTP request to an HTTPS server.\nThe plain HTTP request was sent to HTTPS port\n"))
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"active","version":"2.4.1","admin":true}`))
	})
	return mux
}

func TestScaleRegression(t *testing.T) {
	hosts := 50
	if v, err := strconv.Atoi(os.Getenv("NUCLEI_SCALE_HOSTS")); err == nil && v > 0 {
		hosts = v
	}

	// Stand up N independent loopback hosts (distinct host:port each, so the
	// per-host pool / connection-reuse / http->https machinery is exercised
	// across many keys).
	handler := scaleHandler()
	targets := make([]string, 0, hosts)
	servers := make([]*httptest.Server, 0, hosts)
	for i := 0; i < hosts; i++ {
		srv := httptest.NewServer(handler)
		servers = append(servers, srv)
		targets = append(targets, srv.URL)
	}
	defer func() {
		for _, srv := range servers {
			srv.Close()
		}
	}()

	// Write the template set to a temp directory.
	tplDir := t.TempDir()
	for name, content := range scaleTemplates {
		require.NoError(t, os.WriteFile(filepath.Join(tplDir, name), []byte(content), 0o644))
	}

	ne, err := nuclei.NewNucleiEngineCtx(
		context.Background(),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{tplDir}}),
		nuclei.WithSandboxOptions(true, false),
		nuclei.DisableUpdateCheck(),
	)
	require.NoError(t, err)
	defer ne.Close()

	ne.LoadTargets(targets, false)
	require.NoError(t, ne.LoadAllTemplates())

	var mu sync.Mutex
	perTemplate := map[string]int{}
	perTemplateHost := map[string]map[string]struct{}{}
	require.NoError(t, ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		if event == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		perTemplate[event.TemplateID]++
		if perTemplateHost[event.TemplateID] == nil {
			perTemplateHost[event.TemplateID] = map[string]struct{}{}
		}
		// key on matched-at (includes host:port) since Host alone is 127.0.0.1
		// for every loopback server
		perTemplateHost[event.TemplateID][event.Matched] = struct{}{}
	}))

	// Every template must match on every host. In particular scale-multi-cookie
	// and the other plain-HTTP templates must reach the full host count even
	// though scale-httpsport marks each host:port as "requires HTTPS" — proving
	// the http->https tracker fallback prevents silent finding loss.
	wantIDs := []string{
		"scale-basic-word", "scale-header-match", "scale-regex", "scale-multi-cookie",
		"scale-redirect", "scale-raw", "scale-dsl-json", "scale-extractor", "scale-httpsport",
	}
	for _, id := range wantIDs {
		unique := len(perTemplateHost[id])
		require.Equalf(t, hosts, unique,
			"template %q matched on %d/%d hosts (per-template hits=%d)", id, unique, hosts, perTemplate[id])
	}

	t.Logf("scale regression OK: %d hosts x %d templates = %d findings",
		hosts, len(wantIDs), hosts*len(wantIDs))
}
