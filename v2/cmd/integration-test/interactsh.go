package main

import osutils "github.com/projectdiscovery/utils/os"

// All Interactsh related testcases
var interactshTestCases = []TestCaseInfo{
	{Path: "http/interactsh.yaml", TestCase: &httpInteractshRequest{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "http/interactsh-stop-at-first-match.yaml", TestCase: &httpInteractshStopAtFirstMatchRequest{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "http/default-matcher-condition.yaml", TestCase: &httpDefaultMatcherCondition{}, DisableOn: func() bool { return true }}, // disable this test for now
	{Path: "http/interactsh-requests-mc-and.yaml", TestCase: &httpInteractshRequestsWithMCAnd{}},
}
