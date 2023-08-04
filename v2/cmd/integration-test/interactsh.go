package main

import osutils "github.com/projectdiscovery/utils/os"

// All Interactsh related testcases
var interactshTestCases = []TestCaseInfo{
	{Path: "protocols/http/interactsh.yaml", TestCase: &httpInteractshRequest{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/http/interactsh-stop-at-first-match.yaml", TestCase: &httpInteractshStopAtFirstMatchRequest{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/http/default-matcher-condition.yaml", TestCase: &httpDefaultMatcherCondition{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
}
