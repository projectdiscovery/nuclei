package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

var flowTestcases = []TestCaseInfo{
	{Path: "flow/conditional-flow.yaml", TestCase: &conditionalFlow{}},
	{Path: "flow/conditional-flow-negative.yaml", TestCase: &conditionalFlowNegative{}},
	{Path: "flow/iterate-values-flow.yaml", TestCase: &iterateValuesFlow{}},
	{Path: "flow/iterate-one-value-flow.yaml", TestCase: &iterateOneValueFlow{}},
	{Path: "flow/dns-ns-probe.yaml", TestCase: &dnsNsProbe{}},
	{Path: "flow/flow-hide-matcher.yaml", TestCase: &flowHideMatcher{}},
}

type conditionalFlow struct{}

func (t *conditionalFlow) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "cloud.projectdiscovery.io", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type conditionalFlowNegative struct{}

func (t *conditionalFlowNegative) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "scanme.sh", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 0)
}

type iterateValuesFlow struct{}

func (t *iterateValuesFlow) Execute(filePath string) error {
	router := httprouter.New()
	testemails := []string{
		"secrets@scanme.sh",
		"superadmin@scanme.sh",
	}
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprint(testemails)))
	})
	router.GET("/user/"+getBase64(testemails[0]), func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome ! This is test matcher text"))
	})

	router.GET("/user/"+getBase64(testemails[1]), func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome ! This is test matcher text"))
	})

	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 2)
}

type iterateOneValueFlow struct{}

func (t *iterateOneValueFlow) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "https://scanme.sh", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type dnsNsProbe struct{}

func (t *dnsNsProbe) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "oast.fun", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 2)
}

func getBase64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

type flowHideMatcher struct{}

func (t *flowHideMatcher) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "scanme.sh", debug)
	if err != nil {
		return err
	}
	// this matcher should not return any results
	return expectResultsCount(results, 0)
}
