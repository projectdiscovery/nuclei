package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/kitabisa/go-ci"
	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils/fuzzplayground"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type TestCaseInfo struct {
	Path      string
	TestCase  testutils.TestCase
	DisableOn func() bool
}

var (
	debug       = os.Getenv("DEBUG") == "true"
	customTests = os.Getenv("TESTS")
	protocol    = os.Getenv("PROTO")

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	protocolTests = map[string][]TestCaseInfo{
		"http":            httpTestcases,
		"interactsh":      interactshTestCases,
		"network":         networkTestcases,
		"dns":             dnsTestCases,
		"workflow":        workflowTestcases,
		"loader":          loaderTestcases,
		"profile-loader":  profileLoaderTestcases,
		"websocket":       websocketTestCases,
		"headless":        headlessTestcases,
		"whois":           whoisTestCases,
		"ssl":             sslTestcases,
		"library":         libraryTestcases,
		"templatesPath":   templatesPathTestCases,
		"templatesDir":    templatesDirTestCases,
		"file":            fileTestcases,
		"offlineHttp":     offlineHttpTestcases,
		"customConfigDir": customConfigDirTestCases,
		"fuzzing":         fuzzingTestCases,
		"code":            codeTestCases,
		"multi":           multiProtoTestcases,
		"generic":         genericTestcases,
		"dsl":             dslTestcases,
		"flow":            flowTestcases,
		"javascript":      jsTestcases,
		"matcher-status":  matcherStatusTestcases,
	}
	// flakyTests are run with a retry count of 3
	flakyTests = map[string]bool{
		"protocols/http/self-contained-file-input.yaml": true,
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

	// start fuzz playground server
	defer fuzzplayground.Cleanup()
	server := fuzzplayground.GetPlaygroundServer()
	defer server.Close()
	go func() {
		if err := server.Start("localhost:8082"); err != nil {
			if !strings.Contains(err.Error(), "Server closed") {
				gologger.Fatal().Msgf("Could not start server: %s\n", err)
			}
		}
	}()

	customTestsList := normalizeSplit(customTests)

	failedTestTemplatePaths := runTests(customTestsList)

	if len(failedTestTemplatePaths) > 0 {
		if ci.IsCI() {
			// run failed tests again assuming they are flaky
			// if they fail as well only then we assume that there is an actual issue
			fmt.Println("::group::Running failed tests again")
			failedTestTemplatePaths = runTests(failedTestTemplatePaths)
			fmt.Println("::endgroup::")

			if len(failedTestTemplatePaths) > 0 {
				debug = true
				fmt.Println("::group::Failed integration tests in debug mode")
				_ = runTests(failedTestTemplatePaths)
				fmt.Println("::endgroup::")
			} else {
				fmt.Println("::group::All tests passed")
				fmt.Println("::endgroup::")
				os.Exit(0)
			}
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
		if protocol != "" {
			if !strings.EqualFold(proto, protocol) {
				continue
			}
		}
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
				if proto == "interactsh" || strings.Contains(testCaseInfo.Path, "interactsh") {
					failedTemplatePath, err = executeWithRetry(testCaseInfo.TestCase, testCaseInfo.Path, interactshRetryCount)
				} else if flakyTests[testCaseInfo.Path] {
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
	results = filterHeadlessLogs(results)
	match := sliceutil.Contains(expectedNumbers, len(results))
	if !match {
		return fmt.Errorf("incorrect number of results: %d (actual) vs %v (expected) \nResults:\n\t%s\n", len(results), expectedNumbers, strings.Join(results, "\n\t")) // nolint:all
	}
	return nil
}

func normalizeSplit(str string) []string {
	return strings.FieldsFunc(str, func(r rune) bool {
		return r == ','
	})
}

// if chromium is not installed go-rod installs it in .cache directory
// this function filters out the logs from download and installation
func filterHeadlessLogs(results []string) []string {
	// [launcher.Browser] 2021/09/23 15:24:05 [launcher] [info] Starting browser
	filtered := []string{}
	for _, result := range results {
		if strings.Contains(result, "[launcher.Browser]") {
			continue
		}
		filtered = append(filtered, result)
	}
	return filtered
}
