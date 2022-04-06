package main

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

func getTemplatePath() string {
	templatePath, _ := utils.GetDefaultTemplatePath()
	return templatePath
}

var templatesPathTestCases = map[string]testutils.TestCase{
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
	var routerErr error

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "8x8exch02.8x8.com", debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}
	return expectResultsCount(results, 1)
}

type relativePathTemplateTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *relativePathTemplateTest) Execute(filePath string) error {
	var routerErr error

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "8x8exch02.8x8.com", debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}
	return expectResultsCount(results, 1)
}

type absolutePathTemplateTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *absolutePathTemplateTest) Execute(filePath string) error {
	var routerErr error

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "8x8exch02.8x8.com", debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}
	return expectResultsCount(results, 1)
}
