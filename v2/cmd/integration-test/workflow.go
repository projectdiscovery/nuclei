package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/julienschmidt/httprouter"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var workflowTestcases = map[string]testutils.TestCase{
	"workflow/basic.yaml":               &workflowBasic{},
	"workflow/condition-matched.yaml":   &workflowConditionMatched{},
	"workflow/condition-unmatched.yaml": &workflowConditionUnmatch{},
	"workflow/matcher-name.yaml":        &workflowMatcherName{},
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
