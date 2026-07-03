//go:build integration
// +build integration

package integration_test

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/fuzzplayground"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

type integrationHarness struct {
	repoRoot    string
	fixturesDir string
	binaryPath  string
	debug       bool
	tempDir     string
	runner      *testutils.Runner
}

var suite integrationHarness
var debug bool

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to determine working directory: %v\n", err)
		os.Exit(1)
	}

	repoRoot := filepath.Clean(filepath.Join(wd, "../../.."))
	tempDir, err := os.MkdirTemp("", "nuclei-integration-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create integration temp dir: %v\n", err)
		os.Exit(1)
	}

	binaryName := "nuclei"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(tempDir, binaryName)
	if err := buildNucleiBinary(repoRoot, binaryPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		_ = os.RemoveAll(tempDir)
		os.Exit(1)
	}

	workingFixturesDir := filepath.Join(tempDir, "fixtures")
	if err := copyDir(filepath.Join(repoRoot, "internal", "tests", "integration", "testdata"), workingFixturesDir); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stage integration fixtures: %v\n", err)
		_ = os.RemoveAll(tempDir)
		os.Exit(1)
	}

	previousRunner := testutils.DefaultRunner()
	runner := testutils.NewRunner(
		testutils.WithBinaryPath(binaryPath),
		testutils.WithWorkingDir(workingFixturesDir),
		testutils.WithExtraArgs(integrationExtraArgs...),
	)
	testutils.SetDefaultRunner(runner)

	suite = integrationHarness{
		repoRoot:    repoRoot,
		fixturesDir: workingFixturesDir,
		binaryPath:  binaryPath,
		debug:       isDebugMode(),
		tempDir:     tempDir,
		runner:      runner,
	}
	debug = suite.debug

	fuzzServer := fuzzplayground.GetPlaygroundServer()
	defer func() {
		fuzzplayground.Cleanup()
		_ = fuzzServer.Close()
	}()
	go func() {
		if err := fuzzServer.Start("localhost:8082"); err != nil && !strings.Contains(err.Error(), "Server closed") {
			fmt.Fprintf(os.Stderr, "failed to start fuzz playground: %v\n", err)
		}
	}()

	exitCode := m.Run()
	testutils.SetDefaultRunner(previousRunner)
	_ = os.RemoveAll(tempDir)
	os.Exit(exitCode)
}

func buildNucleiBinary(repoRoot, binaryPath string) error {
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/nuclei")
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build nuclei binary: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func isDebugMode() bool {
	for _, envVar := range []string{"DEBUG", "ACTIONS_STEP_DEBUG", "ACTIONS_RUNNER_DEBUG", "RUNNER_DEBUG"} {
		if envTruthy(envVar) {
			return true
		}
	}
	return false
}

func isCI() bool {
	return envTruthy("CI")
}

func envTruthy(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch value {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}

func fixturePath(relativePath string) string {
	if filepath.IsAbs(relativePath) {
		return relativePath
	}
	return filepath.Join(suite.fixturesDir, filepath.FromSlash(relativePath))
}

func expectResultsCount(results []string, expectedNumbers ...int) error {
	results = filterLines(results)
	actualCount := len(results)
	for _, expected := range expectedNumbers {
		if actualCount == expected {
			return nil
		}
	}
	return fmt.Errorf("incorrect number of results: %d (actual) vs %v (expected)\nresults:\n\t%s", actualCount, expectedNumbers, strings.Join(results, "\n\t"))
}

type capturedError struct {
	mu  sync.Mutex
	err error
}

func (c *capturedError) Set(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
}

func (c *capturedError) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func tempFixtureCopy(t *testing.T, relativePath string, replacements map[string]string) string {
	t.Helper()

	data, err := os.ReadFile(fixturePath(relativePath))
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", relativePath, err)
	}
	content := string(data)
	if len(replacements) > 0 {
		replacementPairs := make([]string, 0, len(replacements)*2)
		for oldValue, newValue := range replacements {
			replacementPairs = append(replacementPairs, oldValue, newValue)
		}
		content = strings.NewReplacer(replacementPairs...).Replace(content)
	}
	tempPath := filepath.Join(t.TempDir(), filepath.Base(relativePath))
	if err := os.WriteFile(tempPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp fixture %s: %v", relativePath, err)
	}
	return tempPath
}

func copyFixtureToDir(t *testing.T, relativePath, destDir string) string {
	t.Helper()

	srcPath := fixturePath(relativePath)
	destPath := filepath.Join(destDir, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		t.Fatalf("failed to create fixture destination for %s: %v", relativePath, err)
	}
	if err := copyFile(srcPath, destPath, 0644); err != nil {
		t.Fatalf("failed to copy fixture %s: %v", relativePath, err)
	}
	return destPath
}

func copyDir(srcDir, destDir string) error {
	return filepath.WalkDir(srcDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return os.MkdirAll(destDir, 0755)
		}
		targetPath := filepath.Join(destDir, relPath)
		if entry.IsDir() {
			return os.MkdirAll(targetPath, 0755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return copyFile(path, targetPath, info.Mode())
	})
}

func copyFile(srcPath, destPath string, mode fs.FileMode) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer func() { _ = destFile.Close() }()

	_, err = io.Copy(destFile, srcFile)
	return err
}

func filterLines(results []string) []string {
	results = filterHeadlessLogs(results)
	results = filterUnsignedTemplatesWarnings(results)
	return results
}

func filterHeadlessLogs(results []string) []string {
	filtered := make([]string, 0, len(results))
	for _, result := range results {
		if strings.Contains(result, "[launcher.Browser]") {
			continue
		}
		filtered = append(filtered, result)
	}
	return filtered
}

func filterUnsignedTemplatesWarnings(results []string) []string {
	filtered := make([]string, 0, len(results))
	unsignedTemplatesRegex := regexp.MustCompile(`Loading \d+ unsigned templates for scan\. Use with caution\.`)
	for _, result := range results {
		if unsignedTemplatesRegex.MatchString(result) {
			continue
		}
		filtered = append(filtered, result)
	}
	return filtered
}
