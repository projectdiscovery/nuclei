package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var dslTestcases = []TestCaseInfo{
	{Path: "dsl/hide-version-warning.yaml", TestCase: &dslVersionWarning{}},
	{Path: "dsl/show-version-warning.yaml", TestCase: &dslShowVersionWarning{}},
}

type dslVersionWarning struct{}

func (d *dslVersionWarning) Execute(templatePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "DSL version parsing warning test")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiArgsAndGetErrors(debug, nil, "-t", templatePath, "-target", ts.URL, "-v")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 0)
}

type dslShowVersionWarning struct{}

func (d *dslShowVersionWarning) Execute(templatePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "DSL version parsing warning test")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiArgsAndGetErrors(debug, []string{"SHOW_DSL_ERRORS=true"}, "-t", templatePath, "-target", ts.URL, "-v")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
