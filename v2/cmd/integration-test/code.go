package main

import (
	"os"
	"path/filepath"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var codeTestCases = map[string]testutils.TestCase{
	"protocols/code/py-snippet.yaml": &pySnippet{},
}

type pySnippet struct{}

func prepareEnv() {
	publicKeyAbsPath, _ := filepath.Abs("protocols/code/pub-key.pem")
	os.Setenv("NUCLEI_SIGNATURE_PUBLIC_KEY", publicKeyAbsPath)
	os.Setenv("NUCLEI_SIGNATURE_ALGORITHM", "ecdsa")
}

func tearDownEnv() {
	os.Unsetenv("NUCLEI_SIGNATURE_PUBLIC_KEY")
	os.Unsetenv("NUCLEI_SIGNATURE_ALGORITHM")
}

// Execute executes a test case and returns an error if occurred
func (h *pySnippet) Execute(filePath string) error {
	prepareEnv()
	defer tearDownEnv()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "input", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
