//go:build integration
// +build integration

package integration_test

import (
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

var whoisTestCases = []integrationCase{
	{Path: "protocols/whois/basic.yaml", TestCase: &whoisBasic{}},
}

type whoisBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *whoisBasic) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "https://example.com", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
