package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

var codeTestCases = map[string]testutils.TestCase{
	"protocols/code/py-snippet.yaml": &pySnippet{},
	"protocols/code/py-file.yaml":    &pyFile{},
	"protocols/code/py-env-var.yaml": &pyEnvVar{},
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

	signTemplates()
}

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

	for templatePath := range codeTestCases {
		templatePath, err := filepath.Abs(templatePath)
		if err != nil {
			panic(err)
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

type pySnippet struct{}

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

type pyFile struct{}

// Execute executes a test case and returns an error if occurred
func (h *pyFile) Execute(filePath string) error {
	prepareEnv()
	defer tearDownEnv()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "input", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type pyEnvVar struct{}

// Execute executes a test case and returns an error if occurred
func (h *pyEnvVar) Execute(filePath string) error {
	prepareEnv()
	defer tearDownEnv()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "input", debug, "-V", "baz=baz")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
