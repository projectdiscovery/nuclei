package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var (
	debug        = os.Getenv("DEBUG") == "true"
	githubAction = os.Getenv("GH_ACTION") == "true"
	customTests  = os.Getenv("TESTS")

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	protocolTests = map[string]map[string]testutils.TestCase{
		"http":            httpTestcases,
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
	runProtocol = ""
	runTemplate = ""
	extraArgs   = []string{}
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
		debug = true
		debugTests()
		os.Exit(1)
	}

	var customTestsList []string
	if stringsutil.ContainsAny(customTests, ",") {
		customTestsList = strings.Split(strings.TrimSpace(customTests), ",")
	}

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

func debugTests() {
	for tpath, testcase := range protocolTests[runProtocol] {
		if runTemplate != "" && !strings.Contains(tpath, runTemplate) {
			continue
		}
		if err := testcase.Execute(tpath); err != nil {
			fmt.Printf("\n%v", err.Error())
		}
	}
}

func runTests(customTemplatePaths []string) []string {
	var failedTestTemplatePaths []string

	for proto, testCases := range protocolTests {
		if len(customTemplatePaths) == 0 {
			fmt.Printf("Running test cases for %q protocol\n", aurora.Blue(proto))
		}

		for templatePath, testCase := range testCases {
			if len(customTemplatePaths) == 0 || sliceutil.Contains(customTemplatePaths, templatePath) {
				if failedTemplatePath, err := execute(testCase, templatePath); err != nil {
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

func expectResultsCount(results []string, expectedNumber int) error {
	if len(results) != expectedNumber {
		return fmt.Errorf("incorrect number of results: %d (actual) vs %d (expected) \nResults:\n\t%s\n", len(results), expectedNumber, strings.Join(results, "\n\t"))
	}
	return nil
}
