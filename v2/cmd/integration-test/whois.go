package main

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var whoisTestCases = map[string]testutils.TestCase{
	"whois/basic.yaml": &whoisBasic{},
}

type whoisBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *whoisBasic) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "https://example.com", debug)
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return expectResultsCount(results, 1)
	}
	return nil
}
