package types

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

func TestGetValidAbsPathAllowsExpectedHelperPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	templatesDir := filepath.Join(home, "nuclei-templates")
	templateDir := filepath.Join(home, "custom-templates")
	outsideHomeDir := t.TempDir()

	for _, dir := range []string{templatesDir, templateDir, filepath.Join(templateDir, "payloads")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	restoreTemplatesDir(t, templatesDir)

	templatePath := filepath.Join(templateDir, "template.yaml")
	if err := os.WriteFile(templatePath, []byte("id: allowed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideHomeTemplatePath := filepath.Join(outsideHomeDir, "template.yaml")
	if err := os.WriteFile(outsideHomeTemplatePath, []byte("id: allowed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name       string
		helperPath string
		template   string
	}{
		{
			name:       "configured templates directory",
			helperPath: filepath.Join(templatesDir, "payloads.txt"),
			template:   outsideHomeTemplatePath,
		},
		{
			name:       "same template directory under home",
			helperPath: filepath.Join(templateDir, "payloads.txt"),
			template:   templatePath,
		},
		{
			name:       "child directory under home",
			helperPath: filepath.Join(templateDir, "payloads", "payloads.txt"),
			template:   templatePath,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := os.WriteFile(testCase.helperPath, []byte("dummy\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := (&Options{}).GetValidAbsPath(testCase.helperPath, testCase.template)
			if err != nil {
				t.Fatalf("expected helper path %q to be allowed: %v", testCase.helperPath, err)
			}
			if got != testCase.helperPath {
				t.Fatalf("expected %q, got %q", testCase.helperPath, got)
			}
		})
	}
}

func TestGetValidAbsPathRejectsSiblingPrefixDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	templatesDir := filepath.Join(home, "nuclei-templates")
	siblingDir := filepath.Join(home, "nuclei-templates-evil")
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(siblingDir, 0o755); err != nil {
		t.Fatal(err)
	}

	restoreTemplatesDir(t, templatesDir)

	helperPath := filepath.Join(siblingDir, "payloads.txt")
	if err := os.WriteFile(helperPath, []byte("dummy\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := (&Options{}).GetValidAbsPath(helperPath, filepath.Join(templatesDir, "template.yaml"))
	if err == nil {
		t.Fatalf("expected sibling prefix helper path %q to be denied", helperPath)
	}
}

func TestGetValidAbsPathRejectsTemplateDirSymlinkToOutside(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliable on all Windows runners")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	templatesDir := filepath.Join(home, "nuclei-templates")
	outsideDir := filepath.Join(home, "outside")
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}

	restoreTemplatesDir(t, templatesDir)

	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("dummy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	helperPath := filepath.Join(templatesDir, "linked-secret.txt")
	if err := os.Symlink(outsideFile, helperPath); err != nil {
		t.Fatal(err)
	}

	_, err := (&Options{}).GetValidAbsPath(helperPath, filepath.Join(templatesDir, "template.yaml"))
	if err == nil {
		t.Fatalf("expected helper symlink %q to outside file %q to be denied", helperPath, outsideFile)
	}
}

// TestGetValidAbsPathResolvesRelativeHelperAgainstTemplateDir locks in the
// rule-2 fix: a relative helper reference (e.g. "payloads.txt") must resolve
// against the template's own directory, not the process working directory.
// Before the fix, fileutil.CleanPath turned a bare "payloads.txt" into
// "<cwd>/payloads.txt", which made rule 2 effectively unreachable unless
// the process happened to be running from the template's directory.
func TestGetValidAbsPathResolvesRelativeHelperAgainstTemplateDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	templatesDir := filepath.Join(home, "nuclei-templates")
	templateDir := filepath.Join(home, "custom-templates")
	for _, dir := range []string{templatesDir, templateDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	restoreTemplatesDir(t, templatesDir)

	templatePath := filepath.Join(templateDir, "template.yaml")
	if err := os.WriteFile(templatePath, []byte("id: rel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	helperPath := filepath.Join(templateDir, "payloads.txt")
	if err := os.WriteFile(helperPath, []byte("dummy\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Drive the test from a CWD that is unrelated to the template directory
	// so a CWD-based resolution would not hit the right file. With the fix,
	// the relative helper must still resolve under templateDir and pass
	// the sandbox checks.
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	unrelatedCwd := t.TempDir()
	if err := os.Chdir(unrelatedCwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWd)
	})

	got, err := (&Options{}).GetValidAbsPath("payloads.txt", templatePath)
	if err != nil {
		t.Fatalf("expected relative helper to be allowed under templateDir: %v", err)
	}
	if got != helperPath {
		t.Fatalf("expected resolution under templateDir %q, got %q", helperPath, got)
	}
}

// TestGetValidAbsPathRejectsRelativeHelperEscapingTemplateDir ensures the
// new template-relative resolution does not become a traversal vector:
// "../outside.txt" still has to land inside the template's directory under
// home for rule 2 to apply.
func TestGetValidAbsPathRejectsRelativeHelperEscapingTemplateDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	templatesDir := filepath.Join(home, "nuclei-templates")
	templateDir := filepath.Join(home, "custom-templates")
	for _, dir := range []string{templatesDir, templateDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	restoreTemplatesDir(t, templatesDir)

	templatePath := filepath.Join(templateDir, "template.yaml")
	if err := os.WriteFile(templatePath, []byte("id: esc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Plant a file ABOVE templateDir (still under home) so a successful
	// traversal would otherwise satisfy isHomeDir and rule 2.
	outsideHelper := filepath.Join(home, "outside.txt")
	if err := os.WriteFile(outsideHelper, []byte("dummy\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := (&Options{}).GetValidAbsPath("../outside.txt", templatePath); err == nil {
		t.Fatalf("expected ../outside.txt to escape templateDir to be denied")
	}
}

func restoreTemplatesDir(t *testing.T, templatesDir string) {
	t.Helper()

	oldTemplatesDir := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() {
		config.DefaultConfig.SetTemplatesDir(oldTemplatesDir)
	})
}
