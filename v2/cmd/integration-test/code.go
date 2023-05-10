package main

import (
	"log"
	"os"
	"path/filepath"

	osutils "github.com/projectdiscovery/utils/os"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

var codeTestCases = map[string]testutils.TestCase{
	"protocols/code/py-snippet.yaml": &codeSnippet{},
	"protocols/code/py-file.yaml":    &codeFile{},
	"protocols/code/py-env-var.yaml": &codeEnvVar{},
	"protocols/code/unsigned.yaml":   &unsignedCode{},
}

var (
	privateKeyAbsPath string
	publicKeyAbsPath  string
)

func init() {
	var err error
	privateKeyAbsPath, err = filepath.Abs("protocols/code/priv-key.pem")
	if err != nil {
		panic(err)
	}
	publicKeyAbsPath, err = filepath.Abs("protocols/code/pub-key.pem")
	if err != nil {
		panic(err)
	}

	if osutils.IsWindows() {
		codeTestCases["protocols/code/ps1-snippet.yaml"] = &codeSnippet{}
	}

	signTemplates()
}

// signTemplates tests the signing procedure on various platforms
func signTemplates() {
	signerOptions := &signer.Options{
		PrivateKeyName: privateKeyAbsPath,
		PublicKeyName:  publicKeyAbsPath,
		Algorithm:      signer.ECDSA,
	}
	sign, err := signer.New(signerOptions)
	if err != nil {
		log.Fatalf("couldn't create crypto engine: %s\n", err)
	}

	for templatePath, testCase := range codeTestCases {
		templatePath, err := filepath.Abs(templatePath)
		if err != nil {
			panic(err)
		}

		// skip unsigned test case
		if _, ok := testCase.(*unsignedCode); ok {
			continue
		}

		if err := utils.ProcessFile(sign, templatePath); err != nil {
			log.Fatalf("Could not walk directory: %s\n", err)
		}
	}
}

func prepareEnv() {
	os.Setenv("NUCLEI_SIGNATURE_PUBLIC_KEY", publicKeyAbsPath)
	os.Setenv("NUCLEI_SIGNATURE_ALGORITHM", "ecdsa")
}

func tearDownEnv() {
	os.Unsetenv("NUCLEI_SIGNATURE_PUBLIC_KEY")
	os.Unsetenv("NUCLEI_SIGNATURE_ALGORITHM")
}

type codeSnippet struct{}

// Execute executes a test case and returns an error if occurred
func (h *codeSnippet) Execute(filePath string) error {
	prepareEnv()
	defer tearDownEnv()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "input", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type codeFile struct{}

// Execute executes a test case and returns an error if occurred
func (h *codeFile) Execute(filePath string) error {
	prepareEnv()
	defer tearDownEnv()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "input", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type codeEnvVar struct{}

// Execute executes a test case and returns an error if occurred
func (h *codeEnvVar) Execute(filePath string) error {
	prepareEnv()
	defer tearDownEnv()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "input", debug, "-V", "baz=baz")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type unsignedCode struct{}

// Execute executes a test case and returns an error if occurred
func (h *unsignedCode) Execute(filePath string) error {
	prepareEnv()
	defer tearDownEnv()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "input", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 0)
}
