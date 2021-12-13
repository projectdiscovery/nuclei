package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

const customTestsVariableName = "TESTS"

var (
	debug        = os.Getenv("DEBUG") == "true"
	githubAction = os.Getenv("GH_ACTION") == "true"
	customTests  = os.Getenv(customTestsVariableName)

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()
)

func main() {
	failedTestTemplatePaths := runTests(customTests)

	if len(failedTestTemplatePaths) > 0 {
		if githubAction {
			debug = true
			fmt.Println("::group::Failed integration tests in debug mode")
			runTests(strings.Join(failedTestTemplatePaths, ","))
			fmt.Println("::endgroup::")
		}

		os.Exit(1)
	}
}

func runTests(customTemplatePaths string) []string {
	var failedTestTemplatePaths []string

	protocolTests := map[string]map[string]testutils.TestCase{
		"http":      httpTestcases,
		"network":   networkTestcases,
		"dns":       dnsTestCases,
		"workflow":  workflowTestcases,
		"loader":    loaderTestcases,
		"websocket": websocketTestCases,
		"headless":  headlessTestcases,
	}

	for proto, testCases := range protocolTests {
		for templatePath, testCase := range testCases {
			if customTemplatePaths != "" && !strings.Contains(customTemplatePaths, templatePath) {
				continue // only run tests user asked
			}

			fmt.Printf("Running test cases for %q protocol\n", aurora.Blue(proto))
			failedTemplatePath := execute(testCase, templatePath)
			if failedTemplatePath != "" {
				failedTestTemplatePaths = append(failedTestTemplatePaths, failedTemplatePath)
			}
		}
	}

	return failedTestTemplatePaths
}

func execute(testCase testutils.TestCase, templatePath string) string {
	fmt.Printf("Running test case for %q template\n", templatePath)
	if err := testCase.Execute(templatePath); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, templatePath, err)
		return templatePath
	} else {
		fmt.Printf("%s Test \"%s\" passed!\n", success, templatePath)
	}
	return ""
}

func errIncorrectResultsCount(results []string) error {
	return fmt.Errorf("incorrect number of results \n\t%s", strings.Join(results, "\n\t"))
}
