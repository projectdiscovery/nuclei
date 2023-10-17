package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

var dslTestcases = []TestCaseInfo{
	{Path: "dsl/hide-version-warning.yaml", TestCase: &dslVersionWarning{}},
	{Path: "dsl/show-version-warning.yaml", TestCase: &dslShowVersionWarning{}},
}

var defaultDSLEnvs = []string{"HIDE_TEMPLATE_SIG_WARNING=true"}

type dslVersionWarning struct{}

func (d *dslVersionWarning) Execute(templatePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "DSL version parsing warning test")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiArgsAndGetErrors(debug, defaultDSLEnvs, "-t", templatePath, "-target", ts.URL, "-v")
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
	results, err := testutils.RunNucleiArgsAndGetErrors(debug, append(defaultDSLEnvs, "SHOW_DSL_ERRORS=true"), "-t", templatePath, "-target", ts.URL, "-v")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
