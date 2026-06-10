//go:build integration
// +build integration

package integration_test

import (
	"errors"
	"os"
	"os/exec"
	"sync"

	osutils "github.com/projectdiscovery/utils/os"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
)

var isCodeDisabled = func() bool { return osutils.IsWindows() && os.Getenv("CI") == "true" }
var signedCodeTemplates sync.Once
var signedCodeTemplatesErr error

func hasAnyExecutable(names ...string) bool {
	for _, name := range names {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

var codeTestCases = []integrationCase{
	{Path: "protocols/code/py-snippet.yaml", TestCase: &codeSnippet{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/py-file.yaml", TestCase: &codeFile{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/py-env-var.yaml", TestCase: &codeEnvVar{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/unsigned.yaml", TestCase: &unsignedCode{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/py-nosig.yaml", TestCase: &codePyNoSig{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/py-interactsh.yaml", TestCase: &codeSnippet{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/ps1-snippet.yaml", TestCase: &codeSnippet{}, DisableOn: func() bool { return !osutils.IsWindows() || isCodeDisabled() }},
	{Path: "protocols/code/pre-condition.yaml", TestCase: &codePreCondition{}, DisableOn: isCodeDisabled},
	{Path: "protocols/code/sh-virtual.yaml", TestCase: &codeSnippet{}, DisableOn: func() bool { return !osutils.IsLinux() || isCodeDisabled() || !hasAnyExecutable("docker", "podman") }, Serial: true},
	{Path: "protocols/code/py-virtual.yaml", TestCase: &codeSnippet{}, DisableOn: func() bool { return !osutils.IsLinux() || isCodeDisabled() || !hasAnyExecutable("docker", "podman") }, Serial: true},
	{Path: "protocols/code/pwsh-echo.yaml", TestCase: &codeSnippet{}, DisableOn: func() bool { return isCodeDisabled() || !hasAnyExecutable("pwsh", "powershell", "powershell.exe") }},
}

const (
	testCertFile = "protocols/keys/ci.crt"
	testKeyFile  = "protocols/keys/ci-private-key.pem"
)

var testcertpath = ""

func ensureSignedCodeTemplates() error {
	if isCodeDisabled() {
		return nil
	}
	signedCodeTemplates.Do(func() {
		previousWD, err := os.Getwd()
		if err != nil {
			signedCodeTemplatesErr = err
			return
		}
		if err := os.Chdir(suite.fixturesDir); err != nil {
			signedCodeTemplatesErr = err
			return
		}
		defer func() {
			if chdirErr := os.Chdir(previousWD); chdirErr != nil && signedCodeTemplatesErr == nil {
				signedCodeTemplatesErr = chdirErr
			}
		}()

		templates.TemplateSignerLFA()

		certPath := fixturePath(testCertFile)
		keyPath := fixturePath(testKeyFile)
		testcertpath = certPath

		tsigner, err := signer.NewTemplateSignerFromFiles(certPath, keyPath)
		if err != nil {
			signedCodeTemplatesErr = err
			return
		}

		templatesToSign := []string{
			"workflow/code-template-1.yaml",
			"workflow/code-template-2.yaml",
		}
		for _, v := range codeTestCases {
			if v.DisableOn != nil && v.DisableOn() {
				continue
			}
			if _, ok := v.TestCase.(*unsignedCode); ok {
				continue
			}
			if _, ok := v.TestCase.(*codePyNoSig); ok {
				continue
			}
			templatesToSign = append(templatesToSign, v.Path)
		}
		for _, templatePath := range templatesToSign {
			if err := templates.SignTemplate(tsigner, fixturePath(templatePath)); err != nil {
				signedCodeTemplatesErr = err
				return
			}
		}
	})
	return signedCodeTemplatesErr
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
