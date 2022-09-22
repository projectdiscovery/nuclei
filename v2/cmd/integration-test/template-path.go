package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

func getTemplatePath() string {
	templatePath, _ := utils.GetDefaultTemplatePath()
	return filepath.Join(templatePath, "community")
}

var templatesPathTestCases = map[string]testutils.TestCase{
	//template folder path issue
	"http/get.yaml": &folderPathTemplateTest{},
	//cwd
	"./dns/cname-fingerprint.yaml": &cwdTemplateTest{},
	//relative path
	"dns/cname-fingerprint.yaml": &relativePathTemplateTest{},
	//absolute path
	fmt.Sprintf("%v/dns/cname-fingerprint.yaml", getTemplatePath()): &absolutePathTemplateTest{},
}

type cwdTemplateTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *cwdTemplateTest) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "8x8exch02.8x8.com", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type relativePathTemplateTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *relativePathTemplateTest) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "8x8exch02.8x8.com", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type absolutePathTemplateTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *absolutePathTemplateTest) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "8x8exch02.8x8.com", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type folderPathTemplateTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *folderPathTemplateTest) Execute(filePath string) error {
	results, err := testutils.RunNucleiBinaryAndGetCombinedOutput(debug, []string{"-t", filePath, "-target", "http://example.com"})
	if err != nil {
		return err
	}
	if strings.Contains(results, "installing") {
		return fmt.Errorf("couldn't find template path,re-installing")
	}
	return nil
}
