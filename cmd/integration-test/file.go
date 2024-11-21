package main

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

var fileTestcases = []TestCaseInfo{
	{Path: "protocols/file/matcher-with-or.yaml", TestCase: &fileWithOrMatcher{}},
	{Path: "protocols/file/matcher-with-and.yaml", TestCase: &fileWithAndMatcher{}},
	{Path: "protocols/file/matcher-with-nested-and.yaml", TestCase: &fileWithAndMatcher{}},
	{Path: "protocols/file/extract.yaml", TestCase: &fileWithExtractor{}},
}

type fileWithOrMatcher struct{}

// Execute executes a test case and returns an error if occurred
func (h *fileWithOrMatcher) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "protocols/file/data/", debug, "-file")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type fileWithAndMatcher struct{}

// Execute executes a test case and returns an error if occurred
func (h *fileWithAndMatcher) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "protocols/file/data/", debug, "-file")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type fileWithExtractor struct{}

// Execute executes a test case and returns an error if occurred
func (h *fileWithExtractor) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "protocols/file/data/", debug, "-file")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}
