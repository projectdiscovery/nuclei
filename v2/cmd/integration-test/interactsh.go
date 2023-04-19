package main

import "github.com/projectdiscovery/nuclei/v2/pkg/testutils"

// All Interactsh related testcases
var interactshTestCases = map[string]testutils.TestCase{
	"http/interactsh.yaml":                     &httpInteractshRequest{},
	"http/interactsh-stop-at-first-match.yaml": &httpInteractshStopAtFirstMatchRequest{},
	"http/default-matcher-condition.yaml":      &httpDefaultMatcherCondition{},
}
