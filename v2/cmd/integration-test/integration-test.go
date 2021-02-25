package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
)

var (
	debug      = os.Getenv("DEBUG") == "true"
	customTest = os.Getenv("TEST")
)

func main() {
	success := aurora.Green("[✓]").String()
	failed := aurora.Red("[✘]").String()

	for file, test := range httpTestcases {
		if customTest != "" && !strings.Contains(file, customTest) {
			continue // only run tests user asked
		}
		err := test.Execute(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, file, err)
		} else {
			fmt.Printf("%s Test \"%s\" passed!\n", success, file)
		}
	}
}

func errIncorrectResultsCount(results []string) error {
	return fmt.Errorf("incorrect number of results %s", strings.Join(results, "\n\t"))
}
