package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/kitabisa/go-ci"
	"github.com/logrusorgru/aurora"

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
	debug       = isDebugMode()
	customTests = os.Getenv("TESTS")
	protocol    = os.Getenv("PROTO")

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	protocolTests = map[string][]TestCaseInfo{
		"fuzzing":         fuzzingTestCases,
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
	playgroundAddress    = "127.0.0.1:8082"
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

	// start fuzz playground server
	server := fuzzplayground.GetPlaygroundServer()
	defer func() {
		fuzzplayground.Cleanup()
		_ = server.Close()
	}()

	go func() {
		fmt.Printf("Attempting to start playground server on %s...\n", playgroundAddress)
		if err := server.Start(playgroundAddress); err != nil {
			if !strings.Contains(err.Error(), "Server closed") {
				fmt.Printf("FATAL: Could not start server: %s\n", err)
				os.Exit(1)
			}
		}
	}()

	// Wait for server to be ready
	serverReady := false
	client := &http.Client{Timeout: 1 * time.Second}
	for i := 0; i < 100; i++ {
		resp, err := client.Get("http://" + playgroundAddress)
		if err == nil {
			resp.Body.Close()
			fmt.Printf("Playground server is ready on %s\n", playgroundAddress)
			serverReady = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !serverReady {
		fmt.Println("FATAL: Server failed to become ready within timeout")
		os.Exit(1)
	}

	if runProtocol != "" {
		if debugTests() {
			os.Exit(0)
		}
		os.Exit(1)
	}

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

// isDebugMode checks if debug mode is enabled via any of the supported debug
// environment variables.
func isDebugMode() bool {
	debugEnvVars := []string{
		"DEBUG",
		"ACTIONS_RUNNER_DEBUG", // GitHub Actions runner debug
		// Add more debug environment variables here as needed
	}

	truthyValues := []string{"true", "1", "yes", "on", "enabled"}

	for _, envVar := range debugEnvVars {
		envValue := strings.ToLower(strings.TrimSpace(os.Getenv(envVar)))
		if slices.Contains(truthyValues, envValue) {
			return true
		}
	}

	return false
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

func debugTests() bool {
	testCaseInfos := protocolTests[runProtocol]
	hasFailed := false
	for _, testCaseInfo := range testCaseInfos {
		if (runTemplate != "" && !strings.Contains(testCaseInfo.Path, runTemplate)) ||
			(testCaseInfo.DisableOn != nil && testCaseInfo.DisableOn()) {
			continue
		}
		if runProtocol == "interactsh" {
			if _, err := executeWithRetry(testCaseInfo.TestCase, testCaseInfo.Path, interactshRetryCount); err != nil {
				fmt.Printf("\n%v", err.Error())
				hasFailed = true
			}
		} else {
			if _, err := execute(testCaseInfo.TestCase, testCaseInfo.Path); err != nil {
				fmt.Printf("\n%v", err.Error())
				hasFailed = true
			}
		}
	}
	return !hasFailed
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
	results = filterLines(results)
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

// filterLines applies all filtering functions to the results
func filterLines(results []string) []string {
	results = filterHeadlessLogs(results)
	results = filterUnsignedTemplatesWarnings(results)
	return results
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

// filterUnsignedTemplatesWarnings filters out warning messages about unsigned templates
func filterUnsignedTemplatesWarnings(results []string) []string {
	filtered := []string{}
	unsignedTemplatesRegex := regexp.MustCompile(`Loading \d+ unsigned templates for scan\. Use with caution\.`)
	for _, result := range results {
		if unsignedTemplatesRegex.MatchString(result) {
			continue
		}
		filtered = append(filtered, result)
	}
	return filtered
}
