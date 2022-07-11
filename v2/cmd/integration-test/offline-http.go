package main

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var offlineHttpTestcases = map[string]testutils.TestCase{
	"offlinehttp/rfc-req-resp.yaml": &RfcRequestResponse{},
}

type RfcRequestResponse struct{}

// Execute executes a test case and returns an error if occurred
func (h *RfcRequestResponse) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "offlinehttp/data/", debug, "-passive")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}
