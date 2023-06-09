package main

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var dnsTestCases = map[string]testutils.TestCase{
	"dns/basic.yaml":                &dnsBasic{},
	"dns/ptr.yaml":                  &dnsPtr{},
	"dns/caa.yaml":                  &dnsCAA{},
	"dns/tlsa.yaml":                 &dnsTLSA{},
	"dns/variables.yaml":            &dnsVariables{},
	"dns/payload.yaml":              &dnsPayload{},
	"dns/dsl-matcher-variable.yaml": &dnsDSLMatcherVariable{},
}

type dnsBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *dnsBasic) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "one.one.one.one", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type dnsPtr struct{}

// Execute executes a test case and returns an error if occurred
func (h *dnsPtr) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "1.1.1.1", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type dnsCAA struct{}

// Execute executes a test case and returns an error if occurred
func (h *dnsCAA) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "google.com", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type dnsTLSA struct{}

// Execute executes a test case and returns an error if occurred
func (h *dnsTLSA) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "scanme.sh", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 0)
}

type dnsVariables struct{}

// Execute executes a test case and returns an error if occurred
func (h *dnsVariables) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "one.one.one.one", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type dnsPayload struct{}

// Execute executes a test case and returns an error if occurred
func (h *dnsPayload) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "google.com", debug)
	if err != nil {
		return err
	}
	if err := expectResultsCount(results, 3); err != nil {
		return err
	}

	// override payload from CLI
	results, err = testutils.RunNucleiTemplateAndGetResults(filePath, "google.com", debug, "-var", "subdomain_wordlist=subdomains.txt")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 4)
}

type dnsDSLMatcherVariable struct{}

// Execute executes a test case and returns an error if occurred
func (h *dnsDSLMatcherVariable) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "one.one.one.one", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
