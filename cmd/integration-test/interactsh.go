package main

import osutils "github.com/projectdiscovery/utils/os"

// All Interactsh related testcases
var interactshTestCases = []TestCaseInfo{
	{Path: "protocols/http/interactsh.yaml", TestCase: &httpInteractshRequest{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/http/interactsh-stop-at-first-match.yaml", TestCase: &httpInteractshStopAtFirstMatchRequest{}, DisableOn: func() bool { return true }}, // disable this test for now
	{Path: "protocols/http/default-matcher-condition.yaml", TestCase: &httpDefaultMatcherCondition{}, DisableOn: func() bool { return true }},
	{Path: "protocols/http/interactsh-requests-mc-and.yaml", TestCase: &httpInteractshRequestsWithMCAnd{}},
}
