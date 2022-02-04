package main

import (
	"net/http"
	"net/http/httptest"

	"github.com/julienschmidt/httprouter"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var headlessTestcases = map[string]testutils.TestCase{
	"headless/headless-basic.yaml":          &headlessBasic{},
	"headless/headless-header-action.yaml":  &headlessHeaderActions{},
	"headless/headless-extract-values.yaml": &headlessExtractValues{},
	"headless/headless-payloads.yaml":       &headlessPayloads{},
}

type headlessBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessBasic) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte("<html><body></body></html>"))
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type headlessHeaderActions struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessHeaderActions) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		testValue := r.Header.Get("test")
		if r.Header.Get("test") != "" {
			_, _ = w.Write([]byte("<html><body>" + testValue + "</body></html>"))
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type headlessExtractValues struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessExtractValues) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte("<html><body><a href='/test.html'>test</a></body></html>"))
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 3)
}

type headlessPayloads struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessPayloads) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte("<html><body>test</body></html>"))
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 4)
}
