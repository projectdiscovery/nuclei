package main

import "github.com/projectdiscovery/nuclei/v2/pkg/testutils"

// All Interactsh related testcases
var interactshTestCases = map[string]testutils.TestCase{
	"protocols/http/interactsh.yaml":                     &httpInteractshRequest{},
	"protocols/http/interactsh-stop-at-first-match.yaml": &httpInteractshStopAtFirstMatchRequest{},
	"protocols/http/default-matcher-condition.yaml":      &httpDefaultMatcherCondition{},
}
