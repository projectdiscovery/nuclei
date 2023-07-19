package main

// All Interactsh related testcases
var interactshTestCases = []TestCaseInfo{
	{DisableOn: []string{"windows"}, Path: "http/interactsh.yaml", TestCase: &httpInteractshRequest{}},
	{DisableOn: []string{"windows"}, Path: "http/interactsh-stop-at-first-match.yaml", TestCase: &httpInteractshStopAtFirstMatchRequest{}},
	{DisableOn: []string{"windows"}, Path: "http/default-matcher-condition.yaml", TestCase: &httpDefaultMatcherCondition{}},
}
