//go:build integration
// +build integration

package integration_test

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

type integrationCase struct {
	Path      string
	TestCase  testutils.TestCase
	DisableOn func() bool
	Serial    bool
}

type integrationFamily struct {
	Name   string
	Cases  []integrationCase
	Serial bool
}

type integrationFailures struct {
	mu    sync.Mutex
	items []failedIntegrationCase
}

type failedIntegrationCase struct {
	Family string
	Case   integrationCase
	Err    error
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, " ")
}

func (s *stringSliceFlag) Set(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	*s = append(*s, trimmed)
	return nil
}

var (
	integrationFamilyFilter   = flag.String("family", "", "run only the matching integration family")
	integrationTemplateFilter = flag.String("template", "", "run only integration cases whose template path contains this value")
	integrationExtraArgs      stringSliceFlag
)

const maxFailureReruns = 3

func init() {
	flag.Var(&integrationExtraArgs, "nuclei-args", "extra argument passed to nuclei for integration tests; repeat the flag to pass multiple arguments")
}

func TestIntegrationSuites(t *testing.T) {
	families := selectedIntegrationFamilies()
	if len(families) == 0 {
		t.Fatalf("no integration tests matched family=%q template=%q", strings.TrimSpace(*integrationFamilyFilter), strings.TrimSpace(*integrationTemplateFilter))
	}

	failed := runIntegrationPass(t, "initial", families, debug)
	if len(failed) == 0 {
		return
	}

	if isCI() {
		for attempt := 1; attempt <= maxFailureReruns && len(failed) > 0; attempt++ {
			failed = withGroupedOutput(fmt.Sprintf("Rerun failed integration tests (%d/%d)", attempt, maxFailureReruns), func() []failedIntegrationCase {
				return runIntegrationPass(t, fmt.Sprintf("rerun-%d", attempt), failedCasesByFamily(failed), debug)
			})
		}
	}

	if len(failed) > 0 && shouldDebugFailureRerun() {
		failed = withGroupedOutput("Rerun failed integration tests in debug mode", func() []failedIntegrationCase {
			return runIntegrationPass(t, "debug-rerun", failedCasesByFamily(failed), true)
		})
	}

	if len(failed) > 0 {
		t.Fatalf("integration failures remaining after reruns:\n%s", formatIntegrationFailures(failed))
	}
}

func integrationFamilies() []integrationFamily {
	return []integrationFamily{
		{Name: "http", Cases: httpTestcases},
		{Name: "interactsh", Cases: interactshTestCases},
		{Name: "code", Cases: codeTestCases},
		{Name: "workflow", Cases: workflowTestcases},
		{Name: "headless", Cases: headlessTestcases},
		{Name: "whois", Cases: whoisTestCases},
		{Name: "library", Cases: libraryTestcases},
		{Name: "template-path", Cases: templatesPathTestCases},
		{Name: "offline-http", Cases: offlineHttpTestcases},
		{Name: "fuzz", Cases: fuzzingTestCases},
		{Name: "generic", Cases: genericTestcases},
		{Name: "dsl", Cases: dslTestcases},
		{Name: "javascript", Cases: jsTestcases},
		{Name: "matcher-status", Cases: matcherStatusTestcases},
		{Name: "exporters", Cases: exportersTestCases},
		{Name: "profile-loader", Cases: profileLoaderTestcases},
		{Name: "multi-protocol", Cases: multiProtoTestcases},
	}
}

func runIntegrationPass(t *testing.T, label string, families []integrationFamily, debugMode bool) []failedIntegrationCase {
	semaphore := make(chan struct{}, parallelism())
	failures := &integrationFailures{}
	previousDebug := debug
	debug = debugMode
	defer func() {
		debug = previousDebug
	}()

	for _, family := range families {
		family := family
		t.Run(passFamilyName(label, family.Name), func(t *testing.T) {
			runIntegrationFamily(t, semaphore, failures, family)
		})
	}
	return failures.Items()
}

func runIntegrationFamily(t *testing.T, semaphore chan struct{}, failures *integrationFailures, family integrationFamily) {
	t.Helper()
	for _, testCase := range family.Cases {
		testCase := testCase
		t.Run(testNameForPath(testCase.Path), func(t *testing.T) {
			if !family.Serial && !testCase.Serial {
				t.Parallel()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()
			}
			if err := executeIntegrationCase(testCase); err != nil {
				failures.Add(failedIntegrationCase{Family: family.Name, Case: testCase, Err: err})
				t.Logf("integration case failed: %v", err)
			}
		})
	}
}

func executeIntegrationCase(testCase integrationCase) error {
	if testCase.DisableOn != nil && testCase.DisableOn() {
		return nil
	}
	if needsSignedCodeTemplates(testCase.Path) {
		if err := ensureSignedCodeTemplates(); err != nil {
			return fmt.Errorf("failed to sign code templates: %w", err)
		}
	}

	var retries int
	var err error
	for attempt := 1; attempt <= maxFailureReruns; attempt++ {
		retries++

		err = testCase.TestCase.Execute(testCase.Path)
		if err == nil {
			return nil
		}
	}
	if retries > 1 {
		return fmt.Errorf("test %s failed after %d attempts: %w", testCase.Path, retries, err)
	}
	return err
}

func parallelism() int {
	if value := strings.TrimSpace(os.Getenv("PARALLELISM")); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	parallelism := max(min(runtime.GOMAXPROCS(0), 4), 1)
	return parallelism
}

func needsSignedCodeTemplates(path string) bool {
	return strings.HasPrefix(path, "protocols/code/") || strings.Contains(path, "workflow/code-")
}

func testNameForPath(path string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ",", "__", ".yaml", "", ".yml", "", ".json", "", ".", "_")
	name := replacer.Replace(path)
	name = strings.Trim(name, "_")
	if name == "" {
		return "case"
	}
	return fmt.Sprintf("%s", name)
}

func (f *integrationFailures) Add(failure failedIntegrationCase) {
	if failure.Err == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items = append(f.items, failure)
}

func (f *integrationFailures) Items() []failedIntegrationCase {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := make([]failedIntegrationCase, len(f.items))
	copy(items, f.items)
	return items
}

func selectedIntegrationFamilies() []integrationFamily {
	familyFilter := strings.ToLower(strings.TrimSpace(*integrationFamilyFilter))
	templateFilter := strings.ToLower(strings.TrimSpace(*integrationTemplateFilter))
	selected := make([]integrationFamily, 0)
	for _, family := range integrationFamilies() {
		if familyFilter != "" && !strings.EqualFold(family.Name, familyFilter) {
			continue
		}
		if templateFilter == "" {
			selected = append(selected, family)
			continue
		}
		filteredCases := make([]integrationCase, 0, len(family.Cases))
		for _, testCase := range family.Cases {
			if strings.Contains(strings.ToLower(testCase.Path), templateFilter) {
				filteredCases = append(filteredCases, testCase)
			}
		}
		if len(filteredCases) == 0 {
			continue
		}
		family.Cases = filteredCases
		selected = append(selected, family)
	}
	return selected
}

func failedCasesByFamily(failed []failedIntegrationCase) []integrationFamily {
	orderedFamilies := make([]string, 0)
	byFamily := make(map[string][]integrationCase)
	for _, failure := range failed {
		if _, ok := byFamily[failure.Family]; !ok {
			orderedFamilies = append(orderedFamilies, failure.Family)
		}
		byFamily[failure.Family] = append(byFamily[failure.Family], failure.Case)
	}
	families := make([]integrationFamily, 0, len(orderedFamilies))
	for _, familyName := range orderedFamilies {
		serial := false
		for _, family := range integrationFamilies() {
			if family.Name == familyName {
				serial = family.Serial
				break
			}
		}
		families = append(families, integrationFamily{Name: familyName, Cases: byFamily[familyName], Serial: serial})
	}
	return families
}

func passFamilyName(label, family string) string {
	if label == "" || label == "initial" {
		return family
	}
	return label + "/" + family
}

func shouldDebugFailureRerun() bool {
	return envTruthy("DEBUG") || envTruthy("ACTIONS_STEP_DEBUG")
}

func withGroupedOutput[T any](title string, fn func() T) T {
	if isCI() {
		fmt.Printf("::group::%s\n", title)
		defer fmt.Println("::endgroup::")
	}
	return fn()
}

func formatIntegrationFailures(failed []failedIntegrationCase) string {
	lines := make([]string, 0, len(failed))
	for _, failure := range failed {
		lines = append(lines, fmt.Sprintf("- [%s] %s: %v", failure.Family, failure.Case.Path, failure.Err))
	}
	return strings.Join(lines, "\n")
}
