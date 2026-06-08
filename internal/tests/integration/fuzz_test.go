//go:build integration
// +build integration

package integration_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

const (
	targetFile = "fuzz/testData/ginandjuice.proxify.yaml"
)

var fuzzingTestCases = []integrationCase{
	{Path: "fuzz/fuzz-mode.yaml", TestCase: &fuzzModeOverride{}},
	{Path: "fuzz/fuzz-multi-mode.yaml", TestCase: &fuzzMultipleMode{}},
	{Path: "fuzz/fuzz-type.yaml", TestCase: &fuzzTypeOverride{}},
	{Path: "fuzz/fuzz-query.yaml", TestCase: &httpFuzzQuery{}},
	{Path: "fuzz/fuzz-headless.yaml", TestCase: &HeadlessFuzzingQuery{}},
	// for fuzzing we should prioritize adding test case related backend
	// logic in fuzz playground server instead of adding them here
	{Path: "fuzz/fuzz-query-num-replace.yaml", TestCase: &genericFuzzTestCase{expectedResults: 2}},
	{Path: "fuzz/fuzz-host-header-injection.yaml", TestCase: &genericFuzzTestCase{expectedResults: 1}},
	{Path: "fuzz/fuzz-path-sqli.yaml", TestCase: &genericFuzzTestCase{expectedResults: 1}},
	{Path: "fuzz/fuzz-cookie-error-sqli.yaml", TestCase: &genericFuzzTestCase{expectedResults: 1}},
	{Path: "fuzz/fuzz-body-json-sqli.yaml", TestCase: &genericFuzzTestCase{expectedResults: 1}},
	{Path: "fuzz/fuzz-body-multipart-form-sqli.yaml", TestCase: &genericFuzzTestCase{expectedResults: 1}},
	{Path: "fuzz/fuzz-body-params-sqli.yaml", TestCase: &genericFuzzTestCase{expectedResults: 1}},
	{Path: "fuzz/fuzz-body-xml-sqli.yaml", TestCase: &genericFuzzTestCase{expectedResults: 1}},
	{Path: "fuzz/fuzz-body-generic-sqli.yaml", TestCase: &genericFuzzTestCase{expectedResults: 4}},

	// Analyzer-driven DAST cases: each runs a real fuzzing template whose
	// detection is delegated to a built-in analyzer, against the dedicated
	// analyzer bench in the fuzz playground. A finding is produced only when the
	// analyzer (not a static matcher) confirms the vulnerability.
	{Path: "fuzz/analyzer-sqli.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/sqli?q=en", expectedResults: 1}},
	{Path: "fuzz/analyzer-ssti.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/ssti?q=test", expectedResults: 1}},
	{Path: "fuzz/analyzer-lfi.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/lfi?q=home.txt", expectedResults: 1}},
	{Path: "fuzz/analyzer-cmdi.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/cmdi?q=127.0.0.1", expectedResults: 1}},
	{Path: "fuzz/analyzer-ssrf.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/ssrf?q=https://example.com/a.png", expectedResults: 1}},
	{Path: "fuzz/analyzer-open-redirect.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/redirect?q=/dashboard", expectedResults: 1}},
	{Path: "fuzz/analyzer-crlf.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/crlf?q=/home", expectedResults: 1}},
	{Path: "fuzz/analyzer-cors.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/cors?q=x", expectedResults: 1}},
	{Path: "fuzz/analyzer-host-header.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/host-header?q=x", expectedResults: 1}},

	// Negative cases: the same analyzer templates against benign routes must
	// produce zero findings (false-positive guard at the CLI level).
	{Path: "fuzz/analyzer-sqli.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/safe/reflect?q=en", expectedResults: 0}},
	{Path: "fuzz/analyzer-ssti.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/safe/reflect?q=test", expectedResults: 0}},
	{Path: "fuzz/analyzer-lfi.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/safe/reflect?q=home.txt", expectedResults: 0}},
	{Path: "fuzz/analyzer-cmdi.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/safe/reflect?q=127.0.0.1", expectedResults: 0}},
	{Path: "fuzz/analyzer-ssrf.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/safe/reflect?q=https://example.com/a.png", expectedResults: 0}},
	{Path: "fuzz/analyzer-open-redirect.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/safe/redirect?q=/dashboard", expectedResults: 0}},
	{Path: "fuzz/analyzer-crlf.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/safe/headers?q=/home", expectedResults: 0}},
	{Path: "fuzz/analyzer-cors.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/safe/cors?q=x", expectedResults: 0}},
	{Path: "fuzz/analyzer-host-header.yaml", TestCase: &analyzerFuzzTestCase{route: "/analyzer/safe/host?q=x", expectedResults: 0}},

	// Non-query positions: each template fuzzes a different request component
	// (path / header / body / cookie) of a captured request and relies on an
	// analyzer for detection. Driven via the proxify-format capture file.
	{Path: "fuzz/analyzer-path-sqli.yaml", TestCase: &analyzerPositionTestCase{expectedResults: 1}},
	{Path: "fuzz/analyzer-header-sqli.yaml", TestCase: &analyzerPositionTestCase{expectedResults: 1}},
	{Path: "fuzz/analyzer-body-sqli.yaml", TestCase: &analyzerPositionTestCase{expectedResults: 1}},
	{Path: "fuzz/analyzer-cookie-ssti.yaml", TestCase: &analyzerPositionTestCase{expectedResults: 1}},

	// Crawl-to-fuzz via the katana input format: each analyzer template is driven
	// against a one-line katana JSONL crawl entry for the matching playground
	// endpoint, exercising the full crawl -> input-format -> fuzz -> analyzer
	// pipeline through the CLI (-im katana ... -dast) across GET-query,
	// GET-with-cookie and POST-JSON-body crawl shapes. (nuclei DAST scopes
	// fuzzing to one request per host, so each case uses its own crawl entry.)
	{Path: "fuzz/analyzer-sqli.yaml", TestCase: &analyzerKatanaTestCase{method: "GET", endpoint: "http://localhost:8082/analyzer/sqli?q=en", expectedResults: 1}},
	{Path: "fuzz/analyzer-ssti.yaml", TestCase: &analyzerKatanaTestCase{method: "GET", endpoint: "http://localhost:8082/analyzer/ssti?q=test", expectedResults: 1}},
	{Path: "fuzz/analyzer-lfi.yaml", TestCase: &analyzerKatanaTestCase{method: "GET", endpoint: "http://localhost:8082/analyzer/lfi?q=home.txt", expectedResults: 1}},
	{Path: "fuzz/analyzer-cmdi.yaml", TestCase: &analyzerKatanaTestCase{method: "GET", endpoint: "http://localhost:8082/analyzer/cmdi?q=127.0.0.1", expectedResults: 1}},
	{Path: "fuzz/analyzer-ssrf.yaml", TestCase: &analyzerKatanaTestCase{method: "GET", endpoint: "http://localhost:8082/analyzer/ssrf?q=https://example.com/a.png", expectedResults: 1}},
	{Path: "fuzz/analyzer-open-redirect.yaml", TestCase: &analyzerKatanaTestCase{method: "GET", endpoint: "http://localhost:8082/analyzer/redirect?q=/dashboard", expectedResults: 1}},
	{Path: "fuzz/analyzer-crlf.yaml", TestCase: &analyzerKatanaTestCase{method: "GET", endpoint: "http://localhost:8082/analyzer/crlf?q=/home", expectedResults: 1}},
	{Path: "fuzz/analyzer-cors.yaml", TestCase: &analyzerKatanaTestCase{method: "GET", endpoint: "http://localhost:8082/analyzer/cors?q=x", expectedResults: 1}},
	{Path: "fuzz/analyzer-host-header.yaml", TestCase: &analyzerKatanaTestCase{method: "GET", endpoint: "http://localhost:8082/analyzer/host-header?q=x", expectedResults: 1}},
	{Path: "fuzz/analyzer-cookie-ssti.yaml", TestCase: &analyzerKatanaTestCase{method: "GET", endpoint: "http://localhost:8082/analyzer/cookie/ssti", headers: map[string]string{"Cookie": "lang=en"}, expectedResults: 1}},
	{Path: "fuzz/analyzer-body-sqli.yaml", TestCase: &analyzerKatanaTestCase{method: "POST", endpoint: "http://localhost:8082/analyzer/body/sqli", headers: map[string]string{"Content-Type": "application/json"}, body: `{"name":"en"}`, expectedResults: 1}},
}

// analyzerKatanaTestCase drives an analyzer template against a katana JSONL
// crawl entry for the matching playground endpoint, exercising the full crawl
// -> input-format -> fuzz -> analyzer pipeline through the CLI
// (-im katana ... -dast).
type analyzerKatanaTestCase struct {
	method          string
	endpoint        string
	headers         map[string]string
	body            string
	expectedResults int
}

func (a *analyzerKatanaTestCase) Execute(filePath string) error {
	crawlFile, cleanup, err := writeKatanaCrawlEntry(a.method, a.endpoint, a.headers, a.body)
	if err != nil {
		return err
	}
	defer cleanup()

	results, err := testutils.RunNucleiWithArgsAndGetResults(debug, "-t", filePath, "-l", crawlFile, "-im", "katana", "-dast")
	if err != nil {
		return err
	}
	return expectResultsCount(results, a.expectedResults)
}

// writeKatanaCrawlEntry writes a single katana JSONL crawl record to a temp file
// and returns its path plus a cleanup func.
func writeKatanaCrawlEntry(method, endpoint string, headers map[string]string, body string) (string, func(), error) {
	record := map[string]any{
		"request": map[string]any{
			"method":   method,
			"endpoint": endpoint,
			"headers":  headers,
			"body":     body,
		},
	}
	line, err := json.Marshal(record)
	if err != nil {
		return "", func() {}, err
	}
	f, err := os.CreateTemp("", "analyzer-katana-*.jsonl")
	if err != nil {
		return "", func() {}, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", func() {}, err
	}
	_ = f.Close()
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}

const analyzerPositionsTargetFile = "fuzz/testData/analyzer-positions.proxify.yaml"

// analyzerPositionTestCase runs an analyzer-driven template that fuzzes a
// non-query component against the captured analyzer-bench requests. Only the
// request matching the template's fuzzed component produces a finding.
type analyzerPositionTestCase struct {
	expectedResults int
}

func (a *analyzerPositionTestCase) Execute(filePath string) error {
	results, err := testutils.RunNucleiWithArgsAndGetResults(debug, "-t", filePath, "-l", analyzerPositionsTargetFile, "-im", "yaml", "-dast")
	if err != nil {
		return err
	}
	return expectResultsCount(results, a.expectedResults)
}

// analyzerFuzzTestCase runs an analyzer-driven fuzzing template against the
// running fuzz playground (localhost:8082) and asserts the number of findings.
type analyzerFuzzTestCase struct {
	route           string
	expectedResults int
}

func (a *analyzerFuzzTestCase) Execute(filePath string) error {
	target := "http://localhost:8082" + a.route
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, target, debug, "-dast")
	if err != nil {
		return err
	}
	return expectResultsCount(results, a.expectedResults)
}

type genericFuzzTestCase struct {
	expectedResults int
}

func (g *genericFuzzTestCase) Execute(filePath string) error {
	results, err := testutils.RunNucleiWithArgsAndGetResults(debug, "-t", filePath, "-l", targetFile, "-im", "yaml")
	if err != nil {
		return err
	}
	return expectResultsCount(results, g.expectedResults)
}

type httpFuzzQuery struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpFuzzQuery) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("Content-Type", "text/html")
		value := r.URL.Query().Get("id")
		_, _ = fmt.Fprintf(w, "This is test matcher text: %v", value)
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"/?id=example", debug, "-fuzz")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type fuzzModeOverride struct{}

// Execute executes a test case and returns an error if occurred
func (h *fuzzModeOverride) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("Content-Type", "text/html")
		value := r.URL.Query().Get("id")
		_, _ = fmt.Fprintf(w, "This is test matcher text: %v", value)
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"/?id=example&name=nuclei", debug, "-fuzzing-mode", "single", "-jsonl", "-fuzz")
	if err != nil {
		return err
	}
	if err = expectResultsCount(results, 1); err != nil {
		return err
	}
	var event output.ResultEvent
	err = json.Unmarshal([]byte(results[0]), &event)
	if err != nil {
		return fmt.Errorf("could not unmarshal event: %s", err)
	}

	// Check whether the matched value url query params are correct
	// default fuzzing mode is multiple in template, so all query params should be fuzzed
	// but using -fm flag we are overriding fuzzing mode to single,
	// so only one query param should be fuzzed, and the other should be the same

	//parse url to get query params
	matchedURL, err := url.Parse(event.Matched)
	if err != nil {
		return err
	}
	values, err := url.ParseQuery(matchedURL.RawQuery)
	if err != nil {
		return err
	}
	if values.Get("name") != "nuclei" {
		return fmt.Errorf("expected fuzzing should not override the name nuclei got %s", values.Get("name"))
	}
	return nil
}

type fuzzTypeOverride struct{}

// Execute executes a test case and returns an error if occurred
func (h *fuzzTypeOverride) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("Content-Type", "text/html")
		value := r.URL.Query().Get("id")
		_, _ = fmt.Fprintf(w, "This is test matcher text: %v", value)
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"?id=example", debug, "-fuzzing-type", "replace", "-jsonl", "-fuzz")
	if err != nil {
		return err
	}
	if err = expectResultsCount(results, 1); err != nil {
		return err
	}
	var event output.ResultEvent
	err = json.Unmarshal([]byte(results[0]), &event)
	if err != nil {
		return fmt.Errorf("could not unmarshal event: %s", err)
	}

	// check whether the matched url query params are fuzzed
	// default fuzzing type in template is postfix but we are overriding it to replace
	// so the matched url query param should be replaced with fuzz-word

	//parse url to get query params
	matchedURL, err := url.Parse(event.Matched)
	if err != nil {
		return err
	}
	values, err := url.ParseQuery(matchedURL.RawQuery)
	if err != nil {
		return err
	}
	if values.Get("id") != "fuzz-word" {
		return fmt.Errorf("expected id to be fuzz-word, got %s", values.Get("id"))
	}
	return nil
}

// HeadlessFuzzingQuery tests fuzzing is working not in headless mode
type HeadlessFuzzingQuery struct{}

// Execute executes a test case and returns an error if occurred
func (h *HeadlessFuzzingQuery) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		resp := fmt.Sprintf("<html><body>%s</body></html>", r.URL.Query().Get("url"))
		_, _ = fmt.Fprint(w, resp)
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	got, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"?url=https://scanme.sh", debug, "-headless", "-fuzz")
	if err != nil {
		return err
	}
	return expectResultsCount(got, 2)
}

type fuzzMultipleMode struct{}

// Execute executes a test case and returns an error if occurred
func (h *fuzzMultipleMode) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		xClientId := r.Header.Get("X-Client-Id")
		xSecretId := r.Header.Get("X-Secret-Id")
		if xClientId != "nuclei-v3" || xSecretId != "nuclei-v3" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		resp := fmt.Sprintf("<html><body><h1>This is multi-mode fuzzing test: %v <h1></body></html>", xClientId)
		_, _ = fmt.Fprint(w, resp)
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	got, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"?url=https://scanme.sh", debug, "-jsonl", "-fuzz")
	if err != nil {
		return err
	}
	return expectResultsCount(got, 1)
}
