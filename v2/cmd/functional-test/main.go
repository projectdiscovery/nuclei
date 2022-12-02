package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var (
	success      = aurora.Green("[✓]").String()
	failed       = aurora.Red("[✘]").String()
	githubAction = os.Getenv("GH_ACTION") == "true"

	mainNucleiBinary = flag.String("main", "", "Main Branch Nuclei Binary")
	devNucleiBinary  = flag.String("dev", "", "Dev Branch Nuclei Binary")
	testcases        = flag.String("testcases", "", "Test cases file for nuclei functional tests")
)

func main() {
	flag.Parse()

	debug := os.Getenv("DEBUG") == "true"

	if err, errored := runFunctionalTests(debug); err != nil {
		log.Fatalf("Could not run functional tests: %s\n", err)
	} else if errored {
		os.Exit(1)
	}
}

func runFunctionalTests(debug bool) (error, bool) {
	file, err := os.Open(*testcases)
	if err != nil {
		return errors.Wrap(err, "could not open test cases"), true
	}
	defer file.Close()

	errored, failedTestCases := runTestCases(file, debug)

	if githubAction {
		fmt.Println("::group::Failed tests with debug")
		for _, failedTestCase := range failedTestCases {
			_ = runTestCase(failedTestCase, true)
		}
		fmt.Println("::endgroup::")
	}

	return nil, errored
}

func runTestCases(file *os.File, debug bool) (bool, []string) {
	errored := false
	var failedTestCases []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		testCase := strings.TrimSpace(scanner.Text())
		if testCase == "" {
			continue
		}
		// skip comments
		if strings.HasPrefix(testCase, "#") {
			continue
		}
		if runTestCase(testCase, debug) {
			errored = true
			failedTestCases = append(failedTestCases, testCase)
		}
	}
	return errored, failedTestCases
}

func runTestCase(testCase string, debug bool) bool {
	if err := runIndividualTestCase(testCase, debug); err != nil {
		fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, testCase, err)
		return true
	} else {
		fmt.Printf("%s Test \"%s\" passed!\n", success, testCase)
	}
	return false
}

func runIndividualTestCase(testcase string, debug bool) error {
	quoted := false

	// split upon unquoted spaces
	parts := strings.FieldsFunc(testcase, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == ' '
	})

	// Quoted strings containing spaces are expressions and must have trailing \" removed
	for index, part := range parts {
		if strings.Contains(part, " ") {
			parts[index] = strings.Trim(part, "\"")
		}
	}

	var finalArgs []string
	if len(parts) > 1 {
		finalArgs = parts[1:]
	}
	mainOutput, err := testutils.RunNucleiBinaryAndGetLoadedTemplates(*mainNucleiBinary, debug, finalArgs)
	if err != nil {
		return errors.Wrap(err, "could not run nuclei main test")
	}
	devOutput, err := testutils.RunNucleiBinaryAndGetLoadedTemplates(*devNucleiBinary, debug, finalArgs)
	if err != nil {
		return errors.Wrap(err, "could not run nuclei dev test")
	}
	if mainOutput == devOutput {
		return nil
	}
	return fmt.Errorf("%s main is not equal to %s dev", mainOutput, devOutput)
}
