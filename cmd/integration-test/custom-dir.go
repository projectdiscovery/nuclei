package main

import (
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

type customConfigDirTest struct{}

var customConfigDirTestCases = []TestCaseInfo{
	{Path: "protocols/dns/cname-fingerprint.yaml", TestCase: &customConfigDirTest{}},
}

// Execute executes a test case and returns an error if occurred
func (h *customConfigDirTest) Execute(filePath string) error {
	customTempDirectory, err := os.MkdirTemp("", "")
	if err != nil {
		return err
	}
	defer os.RemoveAll(customTempDirectory)
	results, err := testutils.RunNucleiBareArgsAndGetResults(debug, []string{"NUCLEI_CONFIG_DIR=" + customTempDirectory}, "-t", filePath, "-u", "8x8exch02.8x8.com")
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return nil
	}
	files, err := os.ReadDir(customTempDirectory)
	if err != nil {
		return err
	}
	var fileNames []string
	for _, file := range files {
		fileNames = append(fileNames, file.Name())
	}
	return expectResultsCount(fileNames, 4)
}
