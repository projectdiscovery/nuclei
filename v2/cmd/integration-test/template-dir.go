package main

import (
	"os"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func getTemplatesDir() string {
	temp := os.TempDir()
	return temp
}

var templatesDirTestCases = map[string]testutils.TestCase{
	"dns/cname-fingerprint.yaml": &templateDirWithTargetTest{},
}

type templateDirWithTargetTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *templateDirWithTargetTest) Execute(filePath string) error {
	defer os.RemoveAll(getTemplatesDir())

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "8x8exch02.8x8.com", debug, "-ud", getTemplatesDir())
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}
