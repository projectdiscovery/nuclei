package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/kitabisa/go-ci"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

var (
	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	mainNucleiBinary = flag.String("main", "", "Main Branch Nuclei Binary")
	devNucleiBinary  = flag.String("dev", "", "Dev Branch Nuclei Binary")
	testcases        = flag.String("testcases", "", "Test cases file for nuclei functional tests")
	workers          = flag.Int("workers", defaultWorkerCount(), "Workers for nuclei functional tests")
)

type functionalTestResult struct {
	index    int
	testCase string
	err      error
}

func main() {
	flag.Parse()

	debug := os.Getenv("DEBUG") == "true" || os.Getenv("RUNNER_DEBUG") == "1"

	if err, errored := runFunctionalTests(debug); err != nil {
		log.Fatalf("Could not run functional tests: %s\n", err)
	} else if errored {
		os.Exit(1)
	}
}

func runFunctionalTests(debug bool) (error, bool) {
	testCaseList, err := loadTestCases(*testcases)
	if err != nil {
		return errors.Wrap(err, "could not open test cases"), true
	}

	errored, failedTestCases := runTestCases(testCaseList, debug, *workers)

	if ci.IsCI() && len(failedTestCases) > 0 {
		fmt.Println("::group::Failed tests with debug")
		for _, failedTestCase := range failedTestCases {
			result := runTestCase(-1, failedTestCase, true)
			printTestCaseResult(result)
		}
		fmt.Println("::endgroup::")
	}

	return nil, errored
}

func defaultWorkerCount() int {
	if value := strings.TrimSpace(os.Getenv("FUNCTIONAL_TEST_WORKERS")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err == nil && parsed > 0 {
			return parsed
		}
	}
	return min(4, max(1, runtime.NumCPU()))
}

func loadTestCases(testCasesFile string) ([]string, error) {
	file, err := os.Open(testCasesFile)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	var loaded []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		testCase := strings.TrimSpace(scanner.Text())
		if testCase == "" || strings.HasPrefix(testCase, "#") {
			continue
		}
		loaded = append(loaded, testCase)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return loaded, nil
}

func runTestCases(testCases []string, debug bool, workerCount int) (bool, []string) {
	results := executeTestCases(testCases, debug, workerCount)
	errored := false
	failedTestCases := make([]string, 0)

	for _, result := range results {
		printTestCaseResult(result)
		if result.err != nil {
			errored = true
			failedTestCases = append(failedTestCases, result.testCase)
		}
	}
	return errored, failedTestCases
}

func executeTestCases(testCases []string, debug bool, workerCount int) []functionalTestResult {
	results := make([]functionalTestResult, len(testCases))
	if len(testCases) == 0 {
		return results
	}

	if workerCount <= 1 {
		for index, testCase := range testCases {
			results[index] = runTestCase(index, testCase, debug)
		}
		return results
	}

	jobIndexes := make(chan int)
	resultChan := make(chan functionalTestResult, len(testCases))
	workerTotal := min(workerCount, len(testCases))

	var workerGroup sync.WaitGroup
	workerGroup.Add(workerTotal)
	for range workerTotal {
		go func() {
			defer workerGroup.Done()
			for index := range jobIndexes {
				resultChan <- runTestCase(index, testCases[index], debug)
			}
		}()
	}

	for index := range testCases {
		jobIndexes <- index
	}
	close(jobIndexes)

	workerGroup.Wait()
	close(resultChan)

	for result := range resultChan {
		results[result.index] = result
	}

	return results
}

func runTestCase(index int, testCase string, debug bool) functionalTestResult {
	result := functionalTestResult{index: index, testCase: testCase}
	if err := runIndividualTestCase(testCase, debug); err != nil {
		result.err = err
	}
	return result
}

func printTestCaseResult(result functionalTestResult) {
	if result.err != nil {
		fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, result.testCase, result.err)
		return
	}
	fmt.Printf("%s Test \"%s\" passed!\n", success, result.testCase)
}

func runIndividualTestCase(testcase string, debug bool) error {
	parts := splitTestCaseArgs(testcase)

	var finalArgs []string
	if len(parts) > 1 {
		finalArgs = parts[1:]
	}
	mainOutput, err := testutils.RunNucleiBinaryWithEnvAndGetLoadedTemplates(*mainNucleiBinary, debug, nil, finalArgs)
	if err != nil {
		return errors.Wrap(err, "could not run nuclei main test")
	}
	devOutput, err := testutils.RunNucleiBinaryWithEnvAndGetLoadedTemplates(*devNucleiBinary, debug, nil, finalArgs)
	if err != nil {
		return errors.Wrap(err, "could not run nuclei dev test")
	}
	if mainOutput == devOutput {
		return nil
	}
	return fmt.Errorf("%s main is not equal to %s dev", mainOutput, devOutput)
}

func splitTestCaseArgs(testcase string) []string {
	quoted := false

	parts := strings.FieldsFunc(testcase, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == ' '
	})

	for index, part := range parts {
		parts[index] = strings.Trim(part, "\"'")
	}

	return parts
}
