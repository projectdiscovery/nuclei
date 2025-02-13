package main

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

var matcherStatusTestcases = []TestCaseInfo{
	{Path: "protocols/http/get.yaml", TestCase: &httpNoAccess{}},
	{Path: "protocols/network/net-https.yaml", TestCase: &networkNoAccess{}},
	{Path: "protocols/headless/headless-basic.yaml", TestCase: &headlessNoAccess{}},
	{Path: "protocols/javascript/net-https.yaml", TestCase: &javascriptNoAccess{}},
	{Path: "protocols/websocket/basic.yaml", TestCase: &websocketNoAccess{}},
	{Path: "protocols/dns/a.yaml", TestCase: &dnsNoAccess{}},
}

type httpNoAccess struct{}

func (h *httpNoAccess) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "trust_me_bro.real", debug, "-ms", "-j")
	if err != nil {
		return err
	}
	event := &output.ResultEvent{}
	_ = json.Unmarshal([]byte(results[0]), event)
	expectedError := "no address found for host"
	if !strings.Contains(event.Error, expectedError) {
		return fmt.Errorf("unexpected result: expecting \"%s\" error but got \"%s\"", expectedError, event.Error)
	}
	return nil
}

type networkNoAccess struct{}

// Execute executes a test case and returns an error if occurred
func (h *networkNoAccess) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "trust_me_bro.real", debug, "-ms", "-j")
	if err != nil {
		return err
	}
	event := &output.ResultEvent{}
	_ = json.Unmarshal([]byte(results[0]), event)

	if event.Error != "no address found for host" {
		return fmt.Errorf("unexpected result: expecting \"no address found for host\" error but got \"%s\"", event.Error)
	}
	return nil
}

type headlessNoAccess struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessNoAccess) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "trust_me_bro.real", debug, "-headless", "-ms", "-j")
	if err != nil {
		return err
	}
	event := &output.ResultEvent{}
	_ = json.Unmarshal([]byte(results[0]), event)

	if event.Error == "" {
		return fmt.Errorf("unexpected result: expecting an error but got \"%s\"", event.Error)
	}
	return nil
}

type javascriptNoAccess struct{}

// Execute executes a test case and returns an error if occurred
func (h *javascriptNoAccess) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "trust_me_bro.real", debug, "-ms", "-j")
	if err != nil {
		return err
	}
	event := &output.ResultEvent{}
	_ = json.Unmarshal([]byte(results[0]), event)

	if event.Error == "" {
		return fmt.Errorf("unexpected result: expecting an error but got \"%s\"", event.Error)
	}
	return nil
}

type websocketNoAccess struct{}

// Execute executes a test case and returns an error if occurred
func (h *websocketNoAccess) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "ws://trust_me_bro.real", debug, "-ms", "-j")
	if err != nil {
		return err
	}
	event := &output.ResultEvent{}
	_ = json.Unmarshal([]byte(results[0]), event)

	if event.Error == "" {
		return fmt.Errorf("unexpected result: expecting an error but got \"%s\"", event.Error)
	}
	return nil
}

type dnsNoAccess struct{}

// Execute executes a test case and returns an error if occurred
func (h *dnsNoAccess) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "trust_me_bro.real", debug, "-ms", "-j")
	if err != nil {
		return err
	}
	event := &output.ResultEvent{}
	_ = json.Unmarshal([]byte(results[0]), event)

	if event.Error == "" {
		return fmt.Errorf("unexpected result: expecting an error but got \"%s\"", event.Error)
	}
	return nil
}
