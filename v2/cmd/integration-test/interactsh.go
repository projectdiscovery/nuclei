package main

// All Interactsh related testcases
var interactshTestCases = []TestCaseInfo{
	{DisableOn: []string{"windows", "darwin"}, Path: "http/interactsh.yaml", TestCase: &httpInteractshRequest{}},
	{DisableOn: []string{"windows", "darwin"}, Path: "http/interactsh-stop-at-first-match.yaml", TestCase: &httpInteractshStopAtFirstMatchRequest{}},
	{DisableOn: []string{"windows", "darwin"}, Path: "http/default-matcher-condition.yaml", TestCase: &httpDefaultMatcherCondition{}},
}
