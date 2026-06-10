//go:build functional
// +build functional

package functional_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/shlex"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

type functionalHarness struct {
	repoRoot      string
	testcasesPath string
	configDir     string
	releaseBinary string
	currentBinary string
	releaseRunner *testutils.Runner
	currentRunner *testutils.Runner
	debug         bool
	ci            bool
	runner        *testutils.Runner
}

var suite functionalHarness

func TestMain(m *testing.M) {
	os.Exit(runTestMain(m))
}

func runTestMain(m *testing.M) int {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to determine working directory: %v\n", err)
		return 1
	}

	repoRoot := filepath.Clean(filepath.Join(wd, "../../.."))
	configDir, err := os.MkdirTemp("", "nuclei-functional-config-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create functional config dir: %v\n", err)
		return 1
	}
	suite = functionalHarness{
		repoRoot:      repoRoot,
		testcasesPath: filepath.Join(repoRoot, "internal", "tests", "functional", "testdata", "testcases.txt"),
		configDir:     configDir,
		debug:         isDebugMode(),
		ci:            isCI(),
		runner: testutils.NewRunner(
			testutils.WithWorkingDir(repoRoot),
			testutils.WithBaseEnv("NUCLEI_CONFIG_DIR="+configDir),
		),
	}
	defer func() {
		_ = os.RemoveAll(configDir)
	}()

	if suite.ci {
		releaseBinary, err := resolveFunctionalBinary(os.Getenv("RELEASE_BINARY"), "nuclei")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to find release nuclei binary on PATH: %v\n", err)
			return 1
		}
		currentBinary, err := resolveCurrentFunctionalBinary(repoRoot)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		suite.releaseBinary = releaseBinary
		suite.currentBinary = currentBinary
		suite.releaseRunner = suite.runner.Clone(testutils.WithBinaryPath(releaseBinary))
		suite.currentRunner = suite.runner.Clone(testutils.WithBinaryPath(currentBinary))
		if err := prepareFunctionalEnvironment(currentBinary, repoRoot, configDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}

	return m.Run()
}

func TestFunctionalComparison(t *testing.T) {
	if !suite.ci {
		t.Skip("functional suite requires CI=true; use make functional-dev for local release-vs-dev comparisons")
	}

	testcases, err := loadFunctionalTestcases(suite.testcasesPath)
	if err != nil {
		t.Fatalf("failed to load functional testcases: %v", err)
	}
	semaphore := make(chan struct{}, functionalParallelism())

	for index, testcase := range testcases {
		testcase := testcase
		name := functionalTestName(index, testcase.raw)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			if err := runFunctionalCase(testcase.args, suite.debug); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type functionalTestcase struct {
	raw  string
	args []string
}

func loadFunctionalTestcases(path string) ([]functionalTestcase, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var testcases []functionalTestcase
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		args := splitFunctionalArgs(line)
		if len(args) == 0 {
			continue
		}
		seen[line] = struct{}{}
		testcases = append(testcases, functionalTestcase{raw: line, args: args})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return testcases, nil
}

func splitFunctionalArgs(testcase string) []string {
	parts, err := shlex.Split(testcase)
	if err != nil {
		return nil
	}
	if len(parts) <= 1 {
		return nil
	}
	args := parts[1:]
	restoreRawFlagValues(args, "-tc", extractRawFlagValues(testcase, "-tc"))
	return args
}

func extractRawFlagValues(testcase, flagName string) []string {
	values := make([]string, 0, 1)
	for searchStart := 0; searchStart < len(testcase); {
		flagIndex := findFlagIndex(testcase[searchStart:], flagName)
		if flagIndex == -1 {
			break
		}

		flagStart := searchStart + flagIndex
		valueStart := flagStart + len(flagName)
		for valueStart < len(testcase) && isFunctionalArgSpace(testcase[valueStart]) {
			valueStart++
		}
		if valueStart >= len(testcase) {
			break
		}

		valueEnd := scanFlagValueEnd(testcase, valueStart)
		values = append(values, trimMatchingQuotes(strings.TrimSpace(testcase[valueStart:valueEnd])))
		searchStart = valueEnd
	}
	return values
}

func findFlagIndex(input, flagName string) int {
	for searchIndex := 0; searchIndex < len(input); {
		candidate := strings.Index(input[searchIndex:], flagName)
		if candidate == -1 {
			return -1
		}
		candidate += searchIndex
		if functionalFlagBoundary(input, candidate, len(flagName)) {
			return candidate
		}
		searchIndex = candidate + len(flagName)
	}
	return -1
}

func functionalFlagBoundary(input string, start, length int) bool {
	if start > 0 && !isFunctionalArgSpace(input[start-1]) {
		return false
	}
	end := start + length
	return end == len(input) || isFunctionalArgSpace(input[end])
}

func scanFlagValueEnd(input string, start int) int {
	quote := byte(0)
	for index := start; index < len(input); index++ {
		char := input[index]
		if quote != 0 {
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"':
			quote = char
		case ' ', '\t', '\n', '\r':
			next := index
			for next < len(input) && isFunctionalArgSpace(input[next]) {
				next++
			}
			if next < len(input) && input[next] == '-' && next+1 < len(input) && isFunctionalFlagStart(input[next+1]) {
				return index
			}
		}
	}
	return len(input)
}

func isFunctionalArgSpace(char byte) bool {
	switch char {
	case ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

func isFunctionalFlagStart(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}

func restoreRawFlagValues(args []string, flagName string, rawValues []string) {
	if len(rawValues) == 0 {
		return
	}

	rawIndex := 0
	for index := 0; index < len(args)-1 && rawIndex < len(rawValues); index++ {
		if args[index] != flagName {
			continue
		}
		args[index+1] = rawValues[rawIndex]
		rawIndex++
	}
}

func trimMatchingQuotes(value string) string {
	if len(value) < 2 {
		return value
	}
	if (value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"') {
		return value[1 : len(value)-1]
	}
	return value
}

func TestSplitFunctionalArgs(t *testing.T) {
	t.Run("quoted values", func(t *testing.T) {
		args := splitFunctionalArgs(`{{binary}} -tags "cve,exposure" -author "geeknik,pdteam" -severity high,critical`)
		expected := []string{"-tags", "cve,exposure", "-author", "geeknik,pdteam", "-severity", "high,critical"}
		if strings.Join(args, "\x00") != strings.Join(expected, "\x00") {
			t.Fatalf("unexpected args: got=%q want=%q", args, expected)
		}
	})

	t.Run("tc expression preserves quotes", func(t *testing.T) {
		args := splitFunctionalArgs(`{{binary}} -tags cve -author geeknik,pdteam -tc severity=='high'`)
		expected := []string{"-tags", "cve", "-author", "geeknik,pdteam", "-tc", "severity=='high'"}
		if strings.Join(args, "\x00") != strings.Join(expected, "\x00") {
			t.Fatalf("unexpected args: got=%q want=%q", args, expected)
		}
	})

	t.Run("tc expression before next flag", func(t *testing.T) {
		args := splitFunctionalArgs(`{{binary}} -tc contains(tags,'cve') -exclude-templates http/cves/2020/CVE-2020-9757.yaml`)
		expected := []string{"-tc", "contains(tags,'cve')", "-exclude-templates", "http/cves/2020/CVE-2020-9757.yaml"}
		if strings.Join(args, "\x00") != strings.Join(expected, "\x00") {
			t.Fatalf("unexpected args: got=%q want=%q", args, expected)
		}
	})
}

func functionalTestName(index int, raw string) string {
	name := raw
	name = strings.TrimPrefix(name, "{{binary}}")
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "/", "-")
	if len(name) > 80 {
		name = name[:80]
	}
	if name == "" {
		name = "binary"
	}
	return fmt.Sprintf("%03d_%s", index+1, name)
}

func functionalParallelism() int {
	for _, envName := range []string{"FUNCTIONAL_PARALLELISM", "PARALLELISM"} {
		if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
			if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
				return parsed
			}
		}
	}
	processBudget := max(min(runtime.GOMAXPROCS(0), 4), 1)
	return max((processBudget+1)/2, 1)
}

func runFunctionalCase(args []string, debug bool) error {
	if suite.releaseRunner == nil || suite.currentRunner == nil {
		return fmt.Errorf("functional runners are not initialized")
	}

	var (
		releaseOutput string
		currentOutput string
		releaseErr    error
		currentErr    error
	)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		releaseOutput, releaseErr = suite.releaseRunner.LoadedTemplates("", debug, args)
	}()
	go func() {
		defer wg.Done()
		currentOutput, currentErr = suite.currentRunner.LoadedTemplates("", debug, args)
	}()
	wg.Wait()

	if releaseErr != nil {
		return fmt.Errorf("could not run release nuclei test: %w", releaseErr)
	}
	if currentErr != nil {
		return fmt.Errorf("could not run current nuclei test: %w", currentErr)
	}
	if releaseOutput != currentOutput {
		return fmt.Errorf("release loaded %s templates but current loaded %s", releaseOutput, currentOutput)
	}
	return nil
}

func buildCurrentBinary(repoRoot, binaryPath string) error {
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
		return fmt.Errorf("failed to create bin directory: %w", err)
	}
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/nuclei")
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build current nuclei binary: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func resolveCurrentFunctionalBinary(repoRoot string) (string, error) {
	configuredBinary := strings.TrimSpace(os.Getenv("DEV_BINARY"))
	if configuredBinary != "" {
		if resolved, ok := resolveExistingBinaryPath(configuredBinary); ok {
			return resolved, nil
		}
	}
	currentBinary := filepath.Join(repoRoot, "bin", binaryName())
	if err := buildCurrentBinary(repoRoot, currentBinary); err != nil {
		return "", err
	}
	return currentBinary, nil
}

func resolveFunctionalBinary(configuredPath, executableName string) (string, error) {
	if trimmed := strings.TrimSpace(configuredPath); trimmed != "" {
		if resolved, ok := resolveExistingBinaryPath(trimmed); ok {
			return resolved, nil
		}
	}
	for _, candidate := range candidateExecutableNames(executableName) {
		resolved, err := exec.LookPath(candidate)
		if err == nil {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("could not locate %s on PATH", executableName)
}

func resolveExistingBinaryPath(candidate string) (string, bool) {
	trimmed := strings.Trim(strings.TrimSpace(candidate), `"'`)
	if trimmed == "" {
		return "", false
	}

	for _, pathCandidate := range candidateExecutableNames(trimmed) {
		absolutePath, err := filepath.Abs(pathCandidate)
		if err != nil {
			continue
		}
		info, statErr := os.Stat(absolutePath)
		if statErr == nil && !info.IsDir() {
			return absolutePath, true
		}
	}

	for _, pathCandidate := range candidateExecutableNames(trimmed) {
		resolved, err := exec.LookPath(pathCandidate)
		if err == nil {
			return resolved, true
		}
	}

	return "", false
}

func candidateExecutableNames(name string) []string {
	trimmed := strings.Trim(strings.TrimSpace(name), `"'`)
	if trimmed == "" {
		return nil
	}

	candidates := []string{trimmed}
	if runtime.GOOS == "windows" && filepath.Ext(trimmed) == "" {
		candidates = append(candidates, trimmed+".exe")
	}
	return candidates
}

func prepareFunctionalEnvironment(binaryPath, repoRoot, configDir string) error {
	configRoot := filepath.Join(configDir, "nuclei")
	if err := os.MkdirAll(configRoot, 0755); err != nil {
		return fmt.Errorf("failed to create functional nuclei config root: %w", err)
	}
	ignoreFile := filepath.Join(configRoot, ".nuclei-ignore")
	if err := os.WriteFile(ignoreFile, nil, 0644); err != nil {
		return fmt.Errorf("failed to create functional ignore file: %w", err)
	}
	for _, args := range [][]string{{"-update-templates"}, {"-validate"}} {
		cmd := exec.Command(binaryPath, args...)
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "NUCLEI_CONFIG_DIR="+configDir)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("functional setup command %v failed: %w\n%s", args, err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "nuclei.exe"
	}
	return "nuclei"
}

func isCI() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("CI")))
	return value == "true" || value == "1"
}

func isDebugMode() bool {
	for _, envVar := range []string{"DEBUG", "ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG", "RUNNER_DEBUG"} {
		if envTruthy(envVar) {
			return true
		}
	}
	return false
}

func envTruthy(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch value {
	case "true", "1", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}
