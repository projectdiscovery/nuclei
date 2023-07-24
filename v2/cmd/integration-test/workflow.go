package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/julienschmidt/httprouter"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var workflowTestcases = []TestCaseInfo{
	{Path: "workflow/basic.yaml", TestCase: &workflowBasic{}},
	{Path: "workflow/condition-matched.yaml", TestCase: &workflowConditionMatched{}},
	{Path: "workflow/condition-unmatched.yaml", TestCase: &workflowConditionUnmatch{}},
	{Path: "workflow/matcher-name.yaml", TestCase: &workflowMatcherName{}},
	{Path: "workflow/http-value-share-workflow.yaml", TestCase: &workflowHttpKeyValueShare{}},
	{Path: "workflow/dns-value-share-workflow.yaml", TestCase: &workflowDnsKeyValueShare{}},
	{Path: "workflow/shared-cookie.yaml", TestCase: &workflowSharedCookies{}},
}

type workflowBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *workflowBasic) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiWorkflowAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 2)
}

type workflowConditionMatched struct{}

// Execute executes a test case and returns an error if occurred
func (h *workflowConditionMatched) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiWorkflowAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type workflowConditionUnmatch struct{}

// Execute executes a test case and returns an error if occurred
func (h *workflowConditionUnmatch) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiWorkflowAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 0)
}

type workflowMatcherName struct{}

// Execute executes a test case and returns an error if occurred
func (h *workflowMatcherName) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiWorkflowAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type workflowHttpKeyValueShare struct{}

// Execute executes a test case and returns an error if occurred
func (h *workflowHttpKeyValueShare) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/path1", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "href=\"test-value\"")
	})
	router.GET("/path2", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s", body)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiWorkflowAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type workflowDnsKeyValueShare struct{}

// Execute executes a test case and returns an error if occurred
func (h *workflowDnsKeyValueShare) Execute(filePath string) error {
	results, err := testutils.RunNucleiWorkflowAndGetResults(filePath, "http://scanme.sh", debug)
	if err != nil {
		return err
	}

	// no results - ensure that the variable sharing works
	return expectResultsCount(results, 1)
}

type workflowSharedCookies struct{}

// Execute executes a test case and returns an error if occurred
func (h *workflowSharedCookies) Execute(filePath string) error {
	handleFunc := func(name string, w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		cookie := &http.Cookie{Name: name, Value: name}
		http.SetCookie(w, cookie)
	}

	var gotCookies []string
	router := httprouter.New()
	router.GET("/http1", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		handleFunc("http1", w, r, p)
	})
	router.GET("/http2", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		handleFunc("http2", w, r, p)
	})
	router.GET("/headless1", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		handleFunc("headless1", w, r, p)
	})
	router.GET("/http3", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		for _, cookie := range r.Cookies() {
			gotCookies = append(gotCookies, cookie.Name)
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	_, err := testutils.RunNucleiWorkflowAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(gotCookies, 3)
}
