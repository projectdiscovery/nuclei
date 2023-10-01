package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	osutils "github.com/projectdiscovery/utils/os"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var codeTestCases = []TestCaseInfo{
	{Path: "protocols/code/py-snippet.yaml", TestCase: &codeSnippet{}},
	{Path: "protocols/code/py-file.yaml", TestCase: &codeFile{}},
	{Path: "protocols/code/py-env-var.yaml", TestCase: &codeEnvVar{}},
	{Path: "protocols/code/unsigned.yaml", TestCase: &unsignedCode{}},
	{Path: "protocols/code/rsa-signed.yaml", TestCase: &rsaSignedCode{}},
	{Path: "protocols/code/py-interactsh.yaml", TestCase: &codeSnippet{}},
	{Path: "protocols/code/ps1-snippet.yaml", TestCase: &codeSnippet{}, DisableOn: func() bool { return !osutils.IsWindows() }},
}

var (
	ecdsaPrivateKeyAbsPath string
	ecdsaPublicKeyAbsPath  string

	// rsaPrivateKeyAbsPath string
	rsaPublicKeyAbsPath string
)

func init() {
	// since re-signing of code protocol templates is not supported
	// for testing purposes remove them from template
	// to test signing of code protocol templates
	for _, v := range codeTestCases {
		if v.DisableOn != nil && v.DisableOn() {
			continue
		}
		bin, err := os.ReadFile(v.Path)
		if err != nil {
			panic(err)
		}
		updated := signer.RemoveSignatureFromData(bin)
		if err := os.WriteFile(v.Path, updated, 0644); err != nil {
			panic(err)
		}
	}

	var err error
	ecdsaPrivateKeyAbsPath, err = filepath.Abs("protocols/code/ecdsa-priv-key.pem")
	if err != nil {
		panic(err)
	}
	ecdsaPublicKeyAbsPath, err = filepath.Abs("protocols/code/ecdsa-pub-key.pem")
	if err != nil {
		panic(err)
	}

	// rsaPrivateKeyAbsPath, err = filepath.Abs("protocols/code/rsa-priv-key.pem")
	// if err != nil {
	// 	panic(err)
	// }
	rsaPublicKeyAbsPath, err = filepath.Abs("protocols/code/rsa-pub-key.pem")
	if err != nil {
		panic(err)
	}

	signTemplates()
}

// signTemplates tests the signing procedure on various platforms
func signTemplates() {
	signerOptions := &signer.Options{
		PrivateKeyName: ecdsaPrivateKeyAbsPath,
		PublicKeyName:  ecdsaPublicKeyAbsPath,
		Algorithm:      signer.ECDSA,
	}
	sign, err := signer.New(signerOptions)
	if err != nil {
		log.Fatalf("couldn't create crypto engine: %s\n", err)
	}

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
		// - unsigned test case
		if _, ok := testCase.(*unsignedCode); ok {
			continue
		}
		// - already rsa signed
		if _, ok := testCase.(*rsaSignedCode); ok {
			continue
		}

		if err := templates.SignTemplate(sign, templatePath); err != nil {
			log.Fatalf("Could not walk directory: %s\n", err)
		}
	}
}

func getEnvValues() []string {
	return []string{
		"NUCLEI_SIGNATURE_PUBLIC_KEY=" + ecdsaPublicKeyAbsPath,
		"NUCLEI_SIGNATURE_ALGORITHM=ecdsa",
	}
}

func getRSAEnvValues() []string {
	return []string{
		"NUCLEI_SIGNATURE_PUBLIC_KEY=" + rsaPublicKeyAbsPath,
		"NUCLEI_SIGNATURE_ALGORITHM=rsa",
	}
}

type codeSnippet struct{}

// Execute executes a test case and returns an error if occurred
func (h *codeSnippet) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getEnvValues(), "-t", filePath, "-u", "input")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type codeFile struct{}

// Execute executes a test case and returns an error if occurred
func (h *codeFile) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getEnvValues(), "-t", filePath, "-u", "input")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type codeEnvVar struct{}

// Execute executes a test case and returns an error if occurred
func (h *codeEnvVar) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getEnvValues(), "-t", filePath, "-u", "input", "-V", "baz=baz")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type unsignedCode struct{}

// Execute executes a test case and returns an error if occurred
func (h *unsignedCode) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getEnvValues(), "-t", filePath, "-u", "input")

	// should error out
	if err != nil {
		return nil
	}

	// this point should never be reached
	return errors.Join(expectResultsCount(results, 1), errors.New("unsigned template was executed"))
}

type rsaSignedCode struct{}

// Execute executes a test case and returns an error if occurred
func (h *rsaSignedCode) Execute(filePath string) error {
	results, err := testutils.RunNucleiArgsWithEnvAndGetResults(debug, getRSAEnvValues(), "-t", filePath, "-u", "input")

	// should error out
	if err != nil {
		return nil
	}

	// this point should never be reached
	return errors.Join(expectResultsCount(results, 1), errors.New("unsigned template was executed"))
}
