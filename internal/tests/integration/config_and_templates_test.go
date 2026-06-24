//go:build integration
// +build integration

package integration_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

func newTemplateDirTarget(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("This is test matcher text"))
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestTemplateDir(t *testing.T) {
	t.Run("WithTarget", func(t *testing.T) {
		tempDir := t.TempDir()
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/http/get.yaml", newTemplateDirTarget(t), suite.debug, "-ud", tempDir)
		if err != nil {
			t.Fatalf("template dir override request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTemplatesDirEnv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("NUCLEI_TEMPLATES_DIR integration cases are only supported on Linux")
	}
	target := newTemplateDirTarget(t)

	t.Run("Basic", func(t *testing.T) {
		tempDir := t.TempDir()
		copyFixtureToDir(t, "protocols/http/get.yaml", tempDir)
		results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, []string{"NUCLEI_TEMPLATES_DIR=" + tempDir}, "-t", "protocols/http/get.yaml", "-u", target)
		if err != nil {
			t.Fatalf("templates dir env basic request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("AbsolutePath", func(t *testing.T) {
		tempDir := t.TempDir()
		copyFixtureToDir(t, "protocols/http/get.yaml", tempDir)
		results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, []string{"NUCLEI_TEMPLATES_DIR=" + tempDir}, "-t", "protocols/http/get.yaml", "-u", target)
		if err != nil {
			t.Fatalf("templates dir env absolute path request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("RelativePath", func(t *testing.T) {
		tempDir, err := os.MkdirTemp(suite.fixturesDir, "nuclei-templates-dir-env-rel-*")
		if err != nil {
			t.Fatalf("failed to create relative templates dir: %v", err)
		}
		defer func() { _ = os.RemoveAll(tempDir) }()

		copyFixtureToDir(t, "protocols/http/get.yaml", tempDir)
		relPath := filepath.Base(tempDir)
		results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, []string{"NUCLEI_TEMPLATES_DIR=" + relPath}, "-t", "protocols/http/get.yaml", "-u", target)
		if err != nil {
			t.Fatalf("templates dir env relative path request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Precedence", func(t *testing.T) {
		envTempDir := t.TempDir()
		flagTempDir := t.TempDir()
		copyFixtureToDir(t, "protocols/http/get.yaml", flagTempDir)
		results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, []string{"NUCLEI_TEMPLATES_DIR=" + envTempDir}, "-t", "protocols/http/get.yaml", "-u", target, "-ud", flagTempDir)
		if err != nil {
			t.Fatalf("templates dir env precedence request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CustomSubdirs", func(t *testing.T) {
		tempDir := t.TempDir()
		for _, dir := range []string{"github", "s3", "gitlab", "azure"} {
			if err := os.MkdirAll(filepath.Join(tempDir, dir), 0755); err != nil {
				t.Fatalf("failed to create custom templates subdir %s: %v", dir, err)
			}
		}
		copyFixtureToDir(t, "protocols/http/get.yaml", tempDir)
		results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, []string{"NUCLEI_TEMPLATES_DIR=" + tempDir}, "-t", "protocols/http/get.yaml", "-u", target)
		if err != nil {
			t.Fatalf("templates dir env custom subdirs request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCustomConfigDir(t *testing.T) {
	t.Run("ConfigDirIsolated", func(t *testing.T) {
		customTempDir := t.TempDir()
		results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, []string{"NUCLEI_CONFIG_DIR=" + customTempDir}, "-t", "protocols/http/get.yaml", "-u", newTemplateDirTarget(t))
		if err != nil {
			t.Fatalf("custom config dir request failed: %v", err)
		}
		if len(results) != 0 {
			files, err := os.ReadDir(customTempDir)
			if err != nil {
				t.Fatalf("failed to inspect custom config dir: %v", err)
			}
			var fileNames []string
			for _, file := range files {
				fileNames = append(fileNames, file.Name())
			}
			for _, requiredFile := range []string{".templates-config.json", "config.yaml", "reporting-config.yaml"} {
				if !slices.Contains(fileNames, requiredFile) {
					t.Fatalf("missing required config file %q in custom config dir: %v", requiredFile, fileNames)
				}
			}
		}
	})
}
