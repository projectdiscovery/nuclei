package main

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var dnsTestCases = map[string]testutils.TestCase{
	"dns/basic.yaml": &dnsBasic{},
}

type dnsBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *dnsBasic) Execute(filePath string) error {
	var routerErr error

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "one.one.one.one", debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}
	return expectResultsCount(results, 1)
}
