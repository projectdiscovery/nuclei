package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	osutils "github.com/projectdiscovery/utils/os"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

var isCodeDisabled = func() bool { return osutils.IsWindows() && os.Getenv("CI") == "true" }

var codeTestCases = []TestCaseInfo{
	{Path: "protocols/code/py-snippet.yaml", TestCase: &codeSnippet{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/py-file.yaml", TestCase: &codeFile{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/py-env-var.yaml", TestCase: &codeEnvVar{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/unsigned.yaml", TestCase: &unsignedCode{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/py-nosig.yaml", TestCase: &codePyNoSig{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/py-interactsh.yaml", TestCase: &codeSnippet{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/ps1-snippet.yaml", TestCase: &codeSnippet{}, DisableOn: func() bool { return !osutils.IsWindows() || isCodeDisabled() }},
	{Path: "protocols/code/pre-condition.yaml", TestCase: &codePreCondition{}, DisableOn: isCodeDisabled},
}

const (
	testCertFile = "protocols/keys/ci.crt"
	testKeyFile  = "protocols/keys/ci-private-key.pem"
)

var testcertpath = ""

func init() {
	if isCodeDisabled() {
		// skip executing code protocol in CI on windows
		return
	}
	// allow local file access to load content of file references in template
	// in order to sign them for testing purposes
	templates.TemplateSignerLFA()

	tsigner, err := signer.NewTemplateSignerFromFiles(testCertFile, testKeyFile)
	if err != nil {
		panic(err)
	}

	testcertpath, _ = filepath.Abs(testCertFile)

	for _, v := range codeTestCases {
		templatePath := v.Path
		testCase := v.TestCase

		if v.DisableOn != nil && v.DisableOn() {
			// skip ps1 test case on non-windows platforms
			continue
		}

		templatePath, err := filepath.Abs(templatePath)
		if err != nil {
			panic(err)
		}

		// skip
		// - unsigned test cases
		if _, ok := testCase.(*unsignedCode); ok {
			continue
		}
		if _, ok := testCase.(*codePyNoSig); ok {
			continue
		}
		if err := templates.SignTemplate(tsigner, templatePath); err != nil {
			log.Fatalf("Could not sign template %v got: %s\n", templatePath, err)
		}
	}

}

func getEnvValues() []string {
	return []string{
		signer.CertEnvVarName + "=" + testcertpath,
	}
}

type codeSnippet struct{}

// Execute executes a test case and returns an error if occurred
func (h *codeSnippet) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getEnvValues(), "-t", filePath, "-u", "input", "-code")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type codePreCondition struct{}

// Execute executes a test case and returns an error if occurred
func (h *codePreCondition) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getEnvValues(), "-t", filePath, "-u", "input", "-code", "-esc")
	if err != nil {
		return err
	}
	if osutils.IsLinux() {
		return expectResultsCount(results, 1)
	} else {
		return expectResultsCount(results, 0)

	}
}

type codeFile struct{}

// Execute executes a test case and returns an error if occurred
func (h *codeFile) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getEnvValues(), "-t", filePath, "-u", "input", "-code")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type codeEnvVar struct{}

// Execute executes a test case and returns an error if occurred
func (h *codeEnvVar) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getEnvValues(), "-t", filePath, "-u", "input", "-V", "baz=baz", "-code")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type unsignedCode struct{}

// Execute executes a test case and returns an error if occurred
func (h *unsignedCode) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getEnvValues(), "-t", filePath, "-u", "input", "-code")

	// should error out
	if err != nil {
		return nil
	}

	// this point should never be reached
	return errors.Join(expectResultsCount(results, 1), errors.New("unsigned template was executed"))
}

type codePyNoSig struct{}

// Execute executes a test case and returns an error if occurred
func (h *codePyNoSig) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getEnvValues(), "-t", filePath, "-u", "input", "-code")

	// should error out
	if err != nil {
		return nil
	}

	// this point should never be reached
	return errors.Join(expectResultsCount(results, 1), errors.New("unsigned template was executed"))
}
