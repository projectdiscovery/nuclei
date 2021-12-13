package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var (
	debug        = os.Getenv("DEBUG") == "true"
	githubAction = os.Getenv("GH_ACTION") == "true"
	customTests  = os.Getenv("TESTS")

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	protocolTests = map[string]map[string]testutils.TestCase{
		"http":      httpTestcases,
		"network":   networkTestcases,
		"dns":       dnsTestCases,
		"workflow":  workflowTestcases,
		"loader":    loaderTestcases,
		"websocket": websocketTestCases,
		"headless":  headlessTestcases,
	}
)

func main() {
	failedTestTemplatePaths := runTests(toMap(strings.Split(customTests, ",")))

	if len(failedTestTemplatePaths) > 0 {
		if githubAction {
			debug = true
			fmt.Println("::group::Failed integration tests in debug mode")
			_ = runTests(failedTestTemplatePaths)
			fmt.Println("::endgroup::")
		}

		os.Exit(1)
	}
}

func runTests(customTemplatePaths map[string]struct{}) map[string]struct{} {
	var failedTestTemplatePaths map[string]struct{}

	for proto, testCases := range protocolTests {
		if len(customTemplatePaths) == 0 {
			fmt.Printf("Running test cases for %q protocol\n", aurora.Blue(proto))
		}

		for templatePath, testCase := range testCases {
			if len(customTemplatePaths) == 0 || contains(customTemplatePaths, templatePath) {
				if err, failedTemplatePath := execute(testCase, templatePath); err != nil {
					failedTestTemplatePaths[failedTemplatePath] = struct{}{}
				}
			}
		}
	}

	return failedTestTemplatePaths
}

func execute(testCase testutils.TestCase, templatePath string) (error, string) {
	if err := testCase.Execute(templatePath); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, templatePath, err)
		return err, templatePath
	}

	fmt.Printf("%s Test \"%s\" passed!\n", success, templatePath)
	return nil, ""
}

func errIncorrectResultsCount(results []string) error {
	return fmt.Errorf("incorrect number of results \n\t%s", strings.Join(results, "\n\t"))
}

func toMap(slice []string) map[string]struct{} {
	result := make(map[string]struct{}, len(slice))
	for _, value := range slice {
		if _, ok := result[value]; !ok {
			result[value] = struct{}{}
		}
	}
	return result
}

func contains(input map[string]struct{}, value string) bool {
	_, ok := input[value]
	return ok
}
