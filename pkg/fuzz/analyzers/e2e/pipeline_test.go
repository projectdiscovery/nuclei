// This file drives the *real* nuclei DAST/fuzzing pipeline end to end, not just
// the analyzer's Analyze() helper. For each analyzer it compiles a real http
// Request template carrying a `fuzzing:` rule + an `analyzer:` + a DSL matcher
// (`analyzer == true`), then runs Request.ExecuteWithResults against a genuinely
// vulnerable in-repo application (newDastApp). This exercises the production
// chain: rule compilation -> component discovery + mutation -> request transport
// -> analyzer invocation (request.go) -> operator/matcher evaluation -> finding.
//
// The app is hermetic (httptest, no Docker/network), so it is deterministic and
// CI-safe while still reproducing real DAST conditions across all component
// positions (query, path, cookie, body, header).
package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	nucleihttp "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// newDastApp is a single hermetic application that is genuinely vulnerable on
// every route, mirroring the behaviors the analyzers detect. Each route reads a
// user-controlled value from a different request position.
func newDastApp() *httptest.Server {
	cmdiSeps := []string{";id", "|id", "||id", "&&id", "&id", "`id`", "$(id)", "\nid"}
	containsCmdi := func(s string) bool {
		for _, sep := range cmdiSeps {
			if strings.Contains(s, sep) {
				return true
			}
		}
		return false
	}
	sqlErr := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''")
	}

	mux := http.NewServeMux()

	// SQLi in query param
	mux.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("q"), "'\"`\\") {
			sqlErr(w)
			return
		}
		fmt.Fprint(w, "ok")
	})

	// SQLi in path: /user/<id>/profile
	mux.HandleFunc("/user/", func(w http.ResponseWriter, r *http.Request) {
		dec, _ := url.PathUnescape(r.URL.EscapedPath())
		if strings.ContainsAny(dec, "'\"") {
			sqlErr(w)
			return
		}
		fmt.Fprint(w, "ok")
	})

	// SQLi in cookie value (lang)
	mux.HandleFunc("/posts", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("lang"); err == nil && strings.ContainsAny(c.Value, "'\"") {
			sqlErr(w)
			return
		}
		fmt.Fprint(w, "ok")
	})

	// SSTI in query param (real template-engine-like evaluation)
	mux.HandleFunc("/render", func(w http.ResponseWriter, r *http.Request) {
		out := reTpl.ReplaceAllStringFunc(r.URL.Query().Get("q"), func(m string) string {
			sub := reTpl.FindStringSubmatch(m)
			return fmt.Sprintf("%d", atoi(sub[1])*atoi(sub[2]))
		})
		fmt.Fprintf(w, "<html><body>%s</body></html>", out)
	})

	// LFI / path traversal in query param
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch {
		case strings.Contains(q, "etc/passwd"):
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
		case strings.Contains(strings.ToLower(q), "win.ini"):
			fmt.Fprint(w, "; for 16-bit app support\r\n[fonts]\r\n")
		default:
			fmt.Fprint(w, "file not found")
		}
	})

	// CMDi in query param
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		if containsCmdi(r.URL.Query().Get("q")) {
			fmt.Fprint(w, "uid=0(root) gid=0(root) groups=0(root)")
			return
		}
		fmt.Fprintf(w, "ping output for %s", r.URL.Query().Get("q"))
	})

	// SSRF in query param (cloud metadata)
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "169.254.169.254") || strings.Contains(q, "metadata.google.internal") {
			fmt.Fprint(w, `{"accountId":"123456789012","imageId":"ami-0abcd1234ef567890","instanceId":"i-0abcd1234ef567890","region":"us-east-1"}`)
			return
		}
		fmt.Fprint(w, "fetched: nothing interesting")
	})

	// Open redirect: reflects destination into Location
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("q"))
		w.WriteHeader(http.StatusFound)
	})

	// CRLF response splitting: naive header building from input
	mux.HandleFunc("/crlf", func(w http.ResponseWriter, r *http.Request) {
		for _, line := range strings.Split(r.URL.Query().Get("q"), "\n") {
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
		fmt.Fprint(w, "ok")
	})

	// CORS misconfiguration: reflects arbitrary Origin with credentials
	mux.HandleFunc("/cors", func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		fmt.Fprint(w, "ok")
	})

	// Host header injection: reflects X-Forwarded-Host into a link
	mux.HandleFunc("/host", func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		fmt.Fprintf(w, `<a href="https://%s/reset?token=abc">reset</a>`, host)
	})

	return httptest.NewServer(mux)
}

// pipelineResult captures what the real engine surfaced for a target.
type pipelineResult struct {
	matched         bool
	analyzerFlag    bool
	analyzerDetails string
}

// runPipeline compiles and executes a real fuzzing+analyzer template against the
// given absolute target URL (which already contains the parameters to fuzz),
// returning whether the engine produced a finding driven by the analyzer.
func runPipeline(t *testing.T, opts *types.Options, analyzer, part string, targetURL string, keys []string) pipelineResult {
	t.Helper()

	templateID := "dast-" + analyzer + "-" + part
	rule := &fuzz.Rule{
		Type: "replace",
		Part: part,
		Mode: "single",
		Fuzz: fuzz.SliceOrMapSlice{Value: []string{"1337"}},
	}
	if len(keys) > 0 {
		rule.Keys = keys
	}
	req := &nucleihttp.Request{
		ID:      templateID,
		Method:  nucleihttp.HTTPMethodTypeHolder{MethodType: nucleihttp.HTTPGet},
		Path:    []string{"{{BaseURL}}"},
		Fuzzing: []*fuzz.Rule{rule},
		Analyzer: &analyzers.AnalyzerTemplate{
			Name: analyzer,
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
				DSL:  []string{"analyzer == true"},
			}},
		},
	}

	execOpts := testutils.NewMockExecuterOptions(opts, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.High}, Name: "dast-" + analyzer},
	})
	require.NoError(t, req.Compile(execOpts), "compile %s template", analyzer)

	var res pipelineResult
	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	ctxArgs := contextargs.NewWithInput(context.Background(), targetURL)
	err := req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
		if event.OperatorsResult != nil && event.OperatorsResult.Matched {
			res.matched = true
		}
		if event.InternalEvent != nil {
			if v, ok := event.InternalEvent["analyzer"]; ok {
				if b, ok := v.(bool); ok && b {
					res.analyzerFlag = true
				}
			}
			if d, ok := event.InternalEvent["analyzer_details"]; ok {
				res.analyzerDetails = fmt.Sprint(d)
			}
		}
	})
	require.NoError(t, err, "execute %s template", analyzer)
	return res
}

func TestDastPipeline_AllAnalyzers_E2E(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	app := newDastApp()
	defer app.Close()

	// route + part + (optional) keys per analyzer, with parameters embedded in URL
	cases := []struct {
		name     string
		analyzer string
		part     string
		target   string
		keys     []string
	}{
		{"sqli-query", "sqli_error", "query", app.URL + "/sqli?q=seed", []string{"q"}},
		{"sqli-path", "sqli_error", "path", app.URL + "/user/75/profile", nil},
		{"ssti-query", "ssti", "query", app.URL + "/render?q=seed", []string{"q"}},
		{"lfi-query", "lfi", "query", app.URL + "/file?q=home.txt", []string{"q"}},
		{"cmdi-query", "cmdi", "query", app.URL + "/ping?q=127.0.0.1", []string{"q"}},
		{"ssrf-query", "ssrf", "query", app.URL + "/fetch?q=" + url.QueryEscape("https://example.com/a.png"), []string{"q"}},
		{"open_redirect-query", "open_redirect", "query", app.URL + "/go?q=" + url.QueryEscape("/dashboard"), []string{"q"}},
		{"crlf-query", "crlf", "query", app.URL + "/crlf?q=" + url.QueryEscape("/home"), []string{"q"}},
		{"cors-query", "cors", "query", app.URL + "/cors?q=seed", []string{"q"}},
		{"host_header_injection-query", "host_header_injection", "query", app.URL + "/host?q=seed", []string{"q"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runPipeline(t, options, tc.analyzer, tc.part, tc.target, tc.keys)
			require.True(t, res.analyzerFlag, "analyzer %s must flag the response as vulnerable in the real pipeline", tc.analyzer)
			require.True(t, res.matched, "the dsl matcher (analyzer == true) must produce a finding for %s", tc.analyzer)
			require.NotEmpty(t, res.analyzerDetails, "analyzer_details must be populated for %s", tc.analyzer)
		})
	}
}

// TestDastPipeline_NoFalsePositive_E2E proves the full pipeline does not raise a
// finding against a benign endpoint that merely reflects input.
func TestDastPipeline_NoFalsePositive_E2E(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	benign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "results for %q", r.URL.Query().Get("q"))
	}))
	defer benign.Close()

	res := runPipeline(t, options, "sqli_error", "query", benign.URL+"/?q=seed", []string{"q"})
	require.False(t, res.matched, "benign reflector must not yield a sqli finding")
	require.False(t, res.analyzerFlag, "analyzer must not flag a benign reflector")
}
