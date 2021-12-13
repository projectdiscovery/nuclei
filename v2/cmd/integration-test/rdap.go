package main

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var rdapTestCases = map[string]testutils.TestCase{
	"rdap/basic.yaml": &rdapBasic{},
}

type rdapBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *rdapBasic) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "example.com", debug)
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	return nil
}
