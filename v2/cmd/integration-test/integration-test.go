package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type TestCaseInfo struct {
	Path      string
	TestCase  testutils.TestCase
	DisableOn func() bool
}

var (
	debug        = os.Getenv("DEBUG") == "true"
	githubAction = os.Getenv("GH_ACTION") == "true"
	customTests  = os.Getenv("TESTS")

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	protocolTests = map[string][]TestCaseInfo{
		"http":            httpTestcases,
		"interactsh":      interactshTestCases,
		"network":         networkTestcases,
		"dns":             dnsTestCases,
		"workflow":        workflowTestcases,
		"loader":          loaderTestcases,
		"websocket":       websocketTestCases,
		"headless":        headlessTestcases,
		"whois":           whoisTestCases,
		"ssl":             sslTestcases,
		"code":            codeTestcases,
		"templatesPath":   templatesPathTestCases,
		"templatesDir":    templatesDirTestCases,
		"file":            fileTestcases,
		"offlineHttp":     offlineHttpTestcases,
		"customConfigDir": customConfigDirTestCases,
		"fuzzing":         fuzzingTestCases,
		"generic":         genericTestcases,
		"dsl":             dslTestcases,
	}

	// For debug purposes
	runProtocol          = ""
	runTemplate          = ""
	extraArgs            = []string{}
	interactshRetryCount = 3
)

func main() {
	flag.StringVar(&runProtocol, "protocol", "", "run integration tests of given protocol")
	flag.StringVar(&runTemplate, "template", "", "run integration test of given template")
	flag.Parse()

	// allows passing extra args to nuclei
	eargs := os.Getenv("DebugExtraArgs")
	if eargs != "" {
		extraArgs = strings.Split(eargs, " ")
		testutils.ExtraDebugArgs = extraArgs
	}

	if runProtocol != "" {
		debugTests()
		os.Exit(1)
	}

	customTestsList := normalizeSplit(customTests)

	failedTestTemplatePaths := runTests(customTestsList)

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

// execute a testcase with retry and consider best of N
// intended for flaky tests like interactsh
func executeWithRetry(testCase testutils.TestCase, templatePath string, retryCount int) (string, error) {
	var err error
	for i := 0; i < retryCount; i++ {
		err = testCase.Execute(templatePath)
		if err == nil {
			fmt.Printf("%s Test \"%s\" passed!\n", success, templatePath)
			return "", nil
		}
	}
	_, _ = fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed after %v attempts : %s\n", failed, templatePath, retryCount, err)
	return templatePath, err
}

func debugTests() {
	testCaseInfos := protocolTests[runProtocol]
	for _, testCaseInfo := range testCaseInfos {
		if (runTemplate != "" && !strings.Contains(testCaseInfo.Path, runTemplate)) ||
			(testCaseInfo.DisableOn != nil && testCaseInfo.DisableOn()) {
			continue
		}
		if runProtocol == "interactsh" {
			if _, err := executeWithRetry(testCaseInfo.TestCase, testCaseInfo.Path, interactshRetryCount); err != nil {
				fmt.Printf("\n%v", err.Error())
			}
		} else {
			if _, err := execute(testCaseInfo.TestCase, testCaseInfo.Path); err != nil {
				fmt.Printf("\n%v", err.Error())
			}
		}
	}
}

func runTests(customTemplatePaths []string) []string {
	var failedTestTemplatePaths []string

	for proto, testCaseInfos := range protocolTests {
		if len(customTemplatePaths) == 0 {
			fmt.Printf("Running test cases for %q protocol\n", aurora.Blue(proto))
		}
		for _, testCaseInfo := range testCaseInfos {
			if testCaseInfo.DisableOn != nil && testCaseInfo.DisableOn() {
				fmt.Printf("skipping test case %v. disabled on %v.\n", aurora.Blue(testCaseInfo.Path), runtime.GOOS)
				continue
			}
			if len(customTemplatePaths) == 0 || sliceutil.Contains(customTemplatePaths, testCaseInfo.Path) {
				var failedTemplatePath string
				var err error
				if proto == "interactsh" {
					failedTemplatePath, err = executeWithRetry(testCaseInfo.TestCase, testCaseInfo.Path, interactshRetryCount)
				} else {
					failedTemplatePath, err = execute(testCaseInfo.TestCase, testCaseInfo.Path)
				}
				if err != nil {
					failedTestTemplatePaths = append(failedTestTemplatePaths, failedTemplatePath)
				}
			}
		}
	}

	return failedTestTemplatePaths
}

func execute(testCase testutils.TestCase, templatePath string) (string, error) {
	if err := testCase.Execute(templatePath); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, templatePath, err)
		return templatePath, err
	}

	fmt.Printf("%s Test \"%s\" passed!\n", success, templatePath)
	return "", nil
}

func expectResultsCount(results []string, expectedNumbers ...int) error {
	match := sliceutil.Contains(expectedNumbers, len(results))
	if !match {
		return fmt.Errorf("incorrect number of results: %d (actual) vs %v (expected) \nResults:\n\t%s\n", len(results), expectedNumbers, strings.Join(results, "\n\t"))
	}
	return nil
}

func normalizeSplit(str string) []string {
	return strings.FieldsFunc(str, func(r rune) bool {
		return r == ','
	})
}
