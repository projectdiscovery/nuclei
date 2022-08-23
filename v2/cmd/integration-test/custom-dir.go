package main

import (
	"os"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func getCustomConfigsDir() string {
	temp := os.TempDir()
	return temp
}

type customConfigDirTest struct{}

var customConfigDirTestCases = map[string]testutils.TestCase{
	"dns/cname-fingerprint.yaml": &customConfigDirTest{},
}

// Execute executes a test case and returns an error if occurred
func (h *customConfigDirTest) Execute(filePath string) error {
	defer os.RemoveAll(getCustomConfigsDir())

	var routerErr error

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "8x8exch02.8x8.com", debug, "-config-directory", getCustomConfigsDir())
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}
	return expectResultsCount(results, 1)
}
