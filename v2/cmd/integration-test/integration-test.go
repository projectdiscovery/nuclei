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
	protocolTests := map[string]map[string]testutils.TestCase{
		"http":      httpTestcases,
		"network":   networkTestcases,
		"dns":       dnsTestCases,
		"workflow":  workflowTestcases,
		"loader":    loaderTestcases,
		"websocket": websocketTestCases,
		"headless":  headlessTestcases,
	}

	errored := false
	var failedTestTemplatePaths []string

	for proto, testCases := range protocolTests {
		for templatePath, testCase := range testCases {
			fmt.Printf("Custom tests: %s\n", customTests) // TODO delete
			if customTests != "" && !strings.Contains(customTests, templatePath) {
				continue // only run tests user asked
			}

			fmt.Printf("Running test cases for %q protocol\n", aurora.Blue(proto))
			failedTemplatePath := execute(testCase, templatePath)
			if failedTemplatePath != "" {
				errored = true
				failedTestTemplatePaths = append(failedTestTemplatePaths, failedTemplatePath)
			}
		}
	}

	if githubAction && len(failedTestTemplatePaths) > 0 {
		fmt.Printf("echo \"%s=%s\" > $GITHUB_ENV", customTestsVariableName, strings.Join(failedTestTemplatePaths, ","))
	}

	if errored {
		os.Exit(1)
	}
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
