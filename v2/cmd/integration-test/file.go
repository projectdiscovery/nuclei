package main

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var fileTestcases = map[string]testutils.TestCase{
	"file/matcher-with-or.yaml":  &fileWithOrMatcher{},
	"file/matcher-with-and.yaml": &fileWithAndMatcher{},
	"file/extract.yaml":          &fileWithExtractor{},
}

type fileWithOrMatcher struct{}

// Execute executes a test case and returns an error if occurred
func (h *fileWithOrMatcher) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "data/", debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type fileWithAndMatcher struct{}

// Execute executes a test case and returns an error if occurred
func (h *fileWithAndMatcher) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "data/", debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type fileWithExtractor struct{}

// Execute executes a test case and returns an error if occurred
func (h *fileWithExtractor) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "data/", debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}
