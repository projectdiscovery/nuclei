package main

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func getTemplatePath() string {
	return config.DefaultConfig.TemplatesDirectory
}

var templatesPathTestCases = []TestCaseInfo{
	//template folder path issue
	{Path: "http/get.yaml", TestCase: &folderPathTemplateTest{}},
	//cwd
	{Path: "./dns/cname-fingerprint.yaml", TestCase: &cwdTemplateTest{}},
	//relative path
	{Path: "dns/dns-saas-service-detection.yaml", TestCase: &relativePathTemplateTest{}},
	//absolute path
	{Path: fmt.Sprintf("%v/dns/dns-saas-service-detection.yaml", getTemplatePath()), TestCase: &absolutePathTemplateTest{}},
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
