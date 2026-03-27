package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"slices"
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

type ProtocolSuite struct {
	Name         string
	Tests        []TestCaseInfo
	ParallelSafe bool
}

var (
	debug       = isDebugMode()
	customTests = os.Getenv("TESTS")
	protocol    = os.Getenv("PROTO")

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	protocolSuites = []ProtocolSuite{
		{Name: "http", Tests: httpTestcases, ParallelSafe: true},
		{Name: "interactsh", Tests: interactshTestCases, ParallelSafe: false},
		{Name: "network", Tests: networkTestcases, ParallelSafe: false},
		{Name: "dns", Tests: dnsTestCases, ParallelSafe: true},
		{Name: "workflow", Tests: workflowTestcases, ParallelSafe: true},
		{Name: "loader", Tests: loaderTestcases, ParallelSafe: false},
		{Name: "profile-loader", Tests: profileLoaderTestcases, ParallelSafe: true},
		{Name: "websocket", Tests: websocketTestCases, ParallelSafe: true},
		{Name: "headless", Tests: headlessTestcases, ParallelSafe: false},
		{Name: "whois", Tests: whoisTestCases, ParallelSafe: true},
		{Name: "ssl", Tests: sslTestcases, ParallelSafe: false},
		{Name: "library", Tests: libraryTestcases, ParallelSafe: false},
		{Name: "templatesPath", Tests: templatesPathTestCases, ParallelSafe: true},
		{Name: "templatesDir", Tests: templatesDirTestCases, ParallelSafe: true},
		{Name: "env_vars", Tests: templatesDirEnvTestCases, ParallelSafe: true},
		{Name: "file", Tests: fileTestcases, ParallelSafe: true},
		{Name: "offlineHttp", Tests: offlineHttpTestcases, ParallelSafe: true},
		{Name: "customConfigDir", Tests: customConfigDirTestCases, ParallelSafe: true},
		{Name: "fuzzing", Tests: fuzzingTestCases, ParallelSafe: false},
		{Name: "code", Tests: codeTestCases, ParallelSafe: true},
		{Name: "multi", Tests: multiProtoTestcases, ParallelSafe: true},
		{Name: "generic", Tests: genericTestcases, ParallelSafe: false},
		{Name: "dsl", Tests: dslTestcases, ParallelSafe: true},
		{Name: "flow", Tests: flowTestcases, ParallelSafe: true},
		{Name: "javascript", Tests: jsTestcases, ParallelSafe: false},
		{Name: "matcher-status", Tests: matcherStatusTestcases, ParallelSafe: true},
		{Name: "exporters", Tests: exportersTestCases, ParallelSafe: false},
	}
	protocolTests = buildProtocolTests(protocolSuites)

	// flakyTests are run with a retry count of 3
	flakyTests = map[string]bool{
		"protocols/http/self-contained-file-input.yaml": true,
	}

	// For debug purposes
	runProtocol          = ""
	runTemplate          = ""
	listProtocolsMode    = ""
	protocolGroupMode    = ""
	protocolGroupLanes   = 1
	extraArgs            = []string{}
	interactshRetryCount = 3
)

func main() {
	flag.StringVar(&runProtocol, "protocol", "", "run integration tests of given protocol")
	flag.StringVar(&runTemplate, "template", "", "run integration test of given template")
	flag.StringVar(&listProtocolsMode, "list-protocols", "", "list protocols for scheduling: all, parallel, or serial")
	flag.StringVar(&protocolGroupMode, "list-protocol-groups", "", "list comma-separated protocol groups for scheduling: parallel or serial")
	flag.IntVar(&protocolGroupLanes, "group-count", 1, "number of protocol groups to emit")
	flag.Parse()

	// allows passing extra args to nuclei
	eargs := os.Getenv("DebugExtraArgs")
	if eargs != "" {
		extraArgs = strings.Split(eargs, " ")
		testutils.ExtraDebugArgs = extraArgs
	}

	if runProtocol != "" {
		if debugTests() {
			os.Exit(1)
		}
		return
	}

	if listProtocolsMode != "" {
		listProtocols()
		return
	}

	if protocolGroupMode != "" {
		listProtocolGroups()
		return
	}

	customTestsList := normalizeSplit(customTests)
	stopFuzzPlayground, err := maybeStartFuzzPlayground(customTestsList)
	if err != nil {
		gologger.Fatal().Msgf("Could not start fuzz playground: %s\n", err)
	}
	defer stopFuzzPlayground()

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

func buildProtocolTests(suites []ProtocolSuite) map[string][]TestCaseInfo {
	protocolMap := make(map[string][]TestCaseInfo, len(suites))
	for _, suite := range suites {
		protocolMap[suite.Name] = suite.Tests
	}
	return protocolMap
}

func listProtocols() {
	protocols, err := protocolNames(listProtocolsMode)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	for _, name := range protocols {
		fmt.Println(name)
	}
}

func listProtocolGroups() {
	protocols, err := protocolNames(protocolGroupMode)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	for _, group := range groupProtocolNames(protocols, protocolGroupLanes) {
		fmt.Println(strings.Join(group, ","))
	}
}

func protocolNames(mode string) ([]string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	protocols := make([]string, 0, len(protocolSuites))
	for _, suite := range protocolSuites {
		switch mode {
		case "all":
			protocols = append(protocols, suite.Name)
		case "parallel":
			if suite.ParallelSafe {
				protocols = append(protocols, suite.Name)
			}
		case "serial":
			if !suite.ParallelSafe {
				protocols = append(protocols, suite.Name)
			}
		default:
			return nil, fmt.Errorf("invalid protocol mode %q", mode)
		}
	}
	return protocols, nil
}

func groupProtocolNames(protocols []string, lanes int) [][]string {
	if len(protocols) == 0 {
		return nil
	}
	if lanes < 1 {
		lanes = 1
	}
	if lanes > len(protocols) {
		lanes = len(protocols)
	}

	groups := make([][]string, 0, lanes)
	start := 0
	for lane := 0; lane < lanes; lane++ {
		remaining := len(protocols) - start
		lanesLeft := lanes - lane
		groupSize := (remaining + lanesLeft - 1) / lanesLeft
		groups = append(groups, append([]string{}, protocols[start:start+groupSize]...))
		start += groupSize
	}
	return groups
}

func maybeStartFuzzPlayground(customTemplatePaths []string) (func(), error) {
	if !shouldStartFuzzPlayground(customTemplatePaths) {
		return func() {}, nil
	}

	server := fuzzplayground.GetPlaygroundServer()
	go func() {
		if err := server.Start("localhost:8082"); err != nil {
			if !strings.Contains(err.Error(), "Server closed") {
				gologger.Fatal().Msgf("Could not start server: %s\n", err)
			}
		}
	}()

	return func() {
		fuzzplayground.Cleanup()
		_ = server.Close()
	}, nil
}

func shouldStartFuzzPlayground(customTemplatePaths []string) bool {
	selectedProtocol := strings.TrimSpace(protocol)
	if selectedProtocol != "" {
		return strings.EqualFold(selectedProtocol, "fuzzing")
	}
	if len(customTemplatePaths) == 0 {
		return true
	}
	for _, templatePath := range customTemplatePaths {
		if strings.Contains(strings.ToLower(templatePath), "fuzz/") {
			return true
		}
	}
	return false
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
	errored := false
	testCaseInfos := protocolTests[runProtocol]
	for _, testCaseInfo := range testCaseInfos {
		if (runTemplate != "" && !strings.Contains(testCaseInfo.Path, runTemplate)) ||
			(testCaseInfo.DisableOn != nil && testCaseInfo.DisableOn()) {
			continue
		}
		if runProtocol == "interactsh" {
			if _, err := executeWithRetry(testCaseInfo.TestCase, testCaseInfo.Path, interactshRetryCount); err != nil {
				errored = true
				fmt.Printf("\n%v", err.Error())
			}
		} else {
			if _, err := execute(testCaseInfo.TestCase, testCaseInfo.Path); err != nil {
				errored = true
				fmt.Printf("\n%v", err.Error())
			}
		}
	}
	return errored
}

func runTests(customTemplatePaths []string) []string {
	var failedTestTemplatePaths []string

	for _, suite := range protocolSuites {
		proto := suite.Name
		testCaseInfos := suite.Tests
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
