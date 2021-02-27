package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
)

var (
	debug      = os.Getenv("DEBUG") == "true"
	customTest = os.Getenv("TEST")
	protocol   = os.Getenv("PROTO")
)

func main() {
	success := aurora.Green("[✓]").String()
	failed := aurora.Red("[✘]").String()

	protocolTests := map[string]map[string]testutils.TestCase{
		"http":    httpTestcases,
		"network": networkTestcases,
		"dns":     dnsTestCases,
	}
	for proto, tests := range protocolTests {
		if protocol == "" || protocol == proto {
			fmt.Printf("Running test cases for \"%s\" protocol\n", aurora.Blue(proto))

			for file, test := range tests {
				if customTest != "" && !strings.Contains(file, customTest) {
					continue // only run tests user asked
				}
				err := test.Execute(file)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, file, err)
					os.Exit(1)
				} else {
					fmt.Printf("%s Test \"%s\" passed!\n", success, file)
				}
			}
		}
	}
}

func errIncorrectResultsCount(results []string) error {
	return fmt.Errorf("incorrect number of results %s", strings.Join(results, "\n\t"))
}
