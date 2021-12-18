package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/julienschmidt/httprouter"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var loaderTestcases = map[string]testutils.TestCase{
	"loader/template-list.yaml":             &remoteTemplateList{},
	"loader/workflow-list.yaml":             &remoteWorkflowList{},
	"loader/nonexistent-template-list.yaml": &nonExistentTemplateList{},
	"loader/nonexistent-workflow-list.yaml": &nonExistentWorkflowList{},
}

type remoteTemplateList struct{}

// Execute executes a test case and returns an error if occurred
func (h *remoteTemplateList) Execute(templateList string) error {
	router := httprouter.New()

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test matcher text")
		if strings.EqualFold(r.Header.Get("test"), "nuclei") {
			fmt.Fprintf(w, "This is test headers matcher text")
		}
	})

	router.GET("/template_list", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		file, err := os.ReadFile(templateList)
		if err != nil {
			w.WriteHeader(500)
		}
		_, err = w.Write(file)
		if err != nil {
			w.WriteHeader(500)
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiBareArgsAndGetResults(debug, "-target", ts.URL, "-tu", ts.URL+"/template_list")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 2)
}

type remoteWorkflowList struct{}

// Execute executes a test case and returns an error if occurred
func (h *remoteWorkflowList) Execute(workflowList string) error {
	router := httprouter.New()

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test matcher text")
		if strings.EqualFold(r.Header.Get("test"), "nuclei") {
			fmt.Fprintf(w, "This is test headers matcher text")
		}
	})

	router.GET("/workflow_list", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		file, err := os.ReadFile(workflowList)
		if err != nil {
			w.WriteHeader(500)
		}
		_, err = w.Write(file)
		if err != nil {
			w.WriteHeader(500)
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiBareArgsAndGetResults(debug, "-target", ts.URL, "-wu", ts.URL+"/workflow_list")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 3)
}

type nonExistentTemplateList struct{}

// Execute executes a test case and returns an error if occurred
func (h *nonExistentTemplateList) Execute(nonExistingTemplateList string) error {
	router := httprouter.New()
	ts := httptest.NewServer(router)
	defer ts.Close()

	_, err := testutils.RunNucleiBareArgsAndGetResults(debug, "-target", ts.URL, "-tu", ts.URL+"/404")
	if err == nil {
		return fmt.Errorf("expected error for nonexisting workflow url")
	}

	return nil
}

type nonExistentWorkflowList struct{}

// Execute executes a test case and returns an error if occurred
func (h *nonExistentWorkflowList) Execute(nonExistingWorkflowList string) error {
	router := httprouter.New()
	ts := httptest.NewServer(router)
	defer ts.Close()

	_, err := testutils.RunNucleiBareArgsAndGetResults(debug, "-target", ts.URL, "-wu", ts.URL+"/404")
	if err == nil {
		return fmt.Errorf("expected error for nonexisting workflow url")
	}

	return nil
}
