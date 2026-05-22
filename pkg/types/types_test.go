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

func restoreTemplatesDir(t *testing.T, templatesDir string) {
	t.Helper()

	oldTemplatesDir := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() {
		config.DefaultConfig.SetTemplatesDir(oldTemplatesDir)
	})
}
