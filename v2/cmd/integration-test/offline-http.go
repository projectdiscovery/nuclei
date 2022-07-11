package main

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var offlineHttpTestcases = map[string]testutils.TestCase{
	"offlinehttp/rfc-req-resp.yaml":          &RfcRequestResponse{},
	"offlinehttp/offline-allowed-paths.yaml": &RequestResponseWithAllowedPaths{},
	"offlinehttp/offline-raw.yaml":           &RawRequestResponse{},
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

type RequestResponseWithAllowedPaths struct{}

// Execute executes a test case and returns an error if occurred
func (h *RequestResponseWithAllowedPaths) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "offlinehttp/data/", debug, "-passive")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type RawRequestResponse struct{}

// Execute executes a test case and returns an error if occurred
func (h *RawRequestResponse) Execute(filePath string) error {
	_, err := testutils.RunNucleiTemplateAndGetResults(filePath, "offlinehttp/data/", debug, "-passive")
	if err == nil {
		return fmt.Errorf("incorrect result: no error (actual) vs error expected")
	}
	return nil
}
