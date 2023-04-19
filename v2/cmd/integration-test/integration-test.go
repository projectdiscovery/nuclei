package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

var (
	debug        = os.Getenv("DEBUG") == "true"
	githubAction = os.Getenv("GH_ACTION") == "true"
	customTests  = os.Getenv("TESTS")

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	protocolTests = map[string]map[string]testutils.TestCase{
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
	keys := getMapKeys(protocolTests[runProtocol])
	for _, tpath := range keys {
		testcase := protocolTests[runProtocol][tpath]
		if runTemplate != "" && !strings.Contains(tpath, runTemplate) {
			continue
		}
		if runProtocol == "interactsh" {
			if _, err := executeWithRetry(testcase, tpath, interactshRetryCount); err != nil {
				fmt.Printf("\n%v", err.Error())
			}
		} else {
			if _, err := execute(testcase, tpath); err != nil {
				fmt.Printf("\n%v", err.Error())
			}
		}
	}
}

func runTests(customTemplatePaths []string) []string {
	var failedTestTemplatePaths []string

	for proto, testCases := range protocolTests {
		if len(customTemplatePaths) == 0 {
			fmt.Printf("Running test cases for %q protocol\n", aurora.Blue(proto))
		}
		keys := getMapKeys(testCases)

		for _, templatePath := range keys {
			testCase := testCases[templatePath]
			if len(customTemplatePaths) == 0 || sliceutil.Contains(customTemplatePaths, templatePath) {
				var failedTemplatePath string
				var err error
				if proto == "interactsh" {
					failedTemplatePath, err = executeWithRetry(testCase, templatePath, interactshRetryCount)
				} else {
					failedTemplatePath, err = execute(testCase, templatePath)
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

func getMapKeys[T any](testcases map[string]T) []string {
	keys := make([]string, 0, len(testcases))
	for k := range testcases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
