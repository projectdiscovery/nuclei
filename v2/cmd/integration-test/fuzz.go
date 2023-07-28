package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var fuzzingTestCases = []TestCaseInfo{
	{Path: "fuzz/fuzz-mode.yaml", TestCase: &fuzzModeOverride{}},
	{Path: "fuzz/fuzz-type.yaml", TestCase: &fuzzTypeOverride{}},
	{Path: "fuzz/fuzz-query.yaml", TestCase: &httpFuzzQuery{}},
	{Path: "fuzz/fuzz-headless.yaml", TestCase: &HeadlessFuzzingQuery{}},
}

type httpFuzzQuery struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpFuzzQuery) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("Content-Type", "text/html")
		value := r.URL.Query().Get("id")
		fmt.Fprintf(w, "This is test matcher text: %v", value)
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"/?id=example", debug)
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
		fmt.Fprintf(w, "This is test matcher text: %v", value)
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"/?id=example&name=nuclei", debug, "-fuzzing-mode", "single", "-jsonl")
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
		fmt.Fprintf(w, "This is test matcher text: %v", value)
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"?id=example", debug, "-fuzzing-type", "replace", "-jsonl")
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
		fmt.Fprint(w, resp)
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	got, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"?url=https://scanme.sh", debug, "-headless")
	if err != nil {
		return err
	}
	return expectResultsCount(got, 2)
}
