package main

import "github.com/projectdiscovery/nuclei/v2/pkg/testutils"

var multiProtoTestcases = map[string]testutils.TestCase{
	"multi/dynamic-values.yaml":         &multiProtoDynamicExtractor{},
	"multi/evaluate-variables.yaml":     &multiProtoDynamicExtractor{}, // Not a typo execution is same as above testcase
	"multi/exported-response-vars.yaml": &multiProtoDynamicExtractor{}, // Not a typo execution is same as above testcase
}

type multiProtoDynamicExtractor struct{}

// Execute executes a test case and returns an error if occurred
func (h *multiProtoDynamicExtractor) Execute(templatePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(templatePath, "blog.projectdiscovery.io", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
