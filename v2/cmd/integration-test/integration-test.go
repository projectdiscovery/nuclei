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
	customTest   = os.Getenv("TEST")
	protocol     = os.Getenv("PROTO")

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	errored = false
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

	ghActionGroupStart := ""
	ghActionGroupEnd := ""
	if githubAction {
		ghActionGroupStart = "::group::"
		ghActionGroupEnd = "::endgroup::"
	}

	for proto, testCases := range protocolTests {
		if protocol == "" || protocol == proto {

			fmt.Printf("%sRunning test cases for \"%s\" protocol\n", ghActionGroupStart, aurora.Blue(proto))
			for templatePath, testCase := range testCases {
				if customTest != "" && !strings.Contains(templatePath, customTest) {
					continue // only run tests user asked
				}

				execute(testCase, templatePath)
			}
			fmt.Println(ghActionGroupEnd)
		}
	}
	if errored {
		os.Exit(1)
	}
}

func execute(testCase testutils.TestCase, templatePath string) {
	if err := testCase.Execute(templatePath); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, templatePath, err)
		errored = true
	} else {
		fmt.Printf("%s Test \"%s\" passed!\n", success, templatePath)
	}
}

func errIncorrectResultsCount(results []string) error {
	return fmt.Errorf("incorrect number of results \n\t%s", strings.Join(results, "\n\t"))
}
