package config

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestIsCustomTemplateUsesPathBoundaries(t *testing.T) {
	templatesDir := filepath.Join(t.TempDir(), "nuclei-templates")
	cfg := &Config{}
	cfg.SetTemplatesDir(templatesDir)

	tests := []struct {
		name         string
		templatePath string
		want         bool
	}{
		{
			name:         "official template",
			templatePath: filepath.Join(templatesDir, "http", "test.yaml"),
			want:         false,
		},
		{
			name:         "official template sibling prefix",
			templatePath: filepath.Join(templatesDir+"-evil", "test.yaml"),
			want:         true,
		},
		{
			name:         "custom template",
			templatePath: filepath.Join(cfg.CustomGitHubTemplatesDirectory, "owner", "repo", "test.yaml"),
			want:         true,
		},
		{
			name:         "custom template sibling prefix",
			templatePath: filepath.Join(cfg.CustomGitHubTemplatesDirectory+"-evil", "test.yaml"),
			want:         false,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got := cfg.IsCustomTemplate(testCase.templatePath)
			if got != testCase.want {
				t.Fatalf("expected %v, got %v", testCase.want, got)
			}
		})
	}
}

func TestTemplateRootLifecycleIgnoresLegacyDiscoverySource(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "system", BinaryName, NucleiTemplatesDirName)
	stateDir := filepath.Join(dir, "state")
	state, err := json.Marshal(map[string]string{
		"nuclei-templates-directory":        root,
		"nuclei-templates-directory-source": "xdg-system",
		"nuclei-templates-version":          "v1.0.0",
	})
	if err != nil {
		t.Fatalf("marshal templates state: %v", err)
	}
	writeTestFile(t, filepath.Join(stateDir, TemplatesStateFileName), state, 0o600)

	cfg := &Config{stateDir: stateDir, configDir: filepath.Join(dir, "config")}
	if err := cfg.ReadTemplatesConfig(); err != nil {
		t.Fatalf("read templates state: %v", err)
	}
	cfg.LatestNucleiTemplatesVersion = "v99.0.0"

	if !cfg.NeedsTemplateUpdate() {
		t.Fatal("discovered root did not request an available template update")
	}
	if !cfg.IgnoreFileNeedsUpdate("changed") {
		t.Fatal("discovered root did not request a missing ignore file")
	}
	if err := cfg.WriteActiveIgnoreFile([]byte("tags: []\n")); err != nil {
		t.Fatalf("write discovered-root ignore file: %v", err)
	}
	if err := cfg.WriteTemplatesIndex(map[string]string{"id": "path"}); err != nil {
		t.Fatalf("write discovered-root template index: %v", err)
	}
	if err := cfg.SetTemplatesVersion("v2.0.0"); err != nil {
		t.Fatalf("set discovered-root template version: %v", err)
	}

	for _, customDir := range cfg.GetAllCustomTemplateDirs() {
		if filepath.Dir(customDir) != root {
			t.Fatalf("custom directory %q is not under active root %q", customDir, root)
		}
	}
}

func TestNeedsIgnoreFileUpdateUsesActiveFile(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{}
	cfg.SetTemplatesDir(root)

	contents := []byte("tags: [weak]\n")
	latestHash := fmt.Sprintf("%x", md5.Sum(contents))

	// The compatibility field must not hide a missing active file.
	cfg.NucleiIgnoreHash = latestHash
	if !cfg.IgnoreFileNeedsUpdate(latestHash) {
		t.Fatal("missing active ignore file did not require an update")
	}

	if err := os.WriteFile(cfg.GetActiveIgnoreFilePath(), contents, 0o600); err != nil {
		t.Fatalf("write active ignore file: %v", err)
	}
	// The compatibility field must not override the active file contents.
	cfg.NucleiIgnoreHash = "stale"
	if cfg.IgnoreFileNeedsUpdate(latestHash) {
		t.Fatal("matching active ignore file required an update")
	}

	if err := os.WriteFile(cfg.GetActiveIgnoreFilePath(), []byte("tags: []\n"), 0o600); err != nil {
		t.Fatalf("replace active ignore file: %v", err)
	}
	cfg.NucleiIgnoreHash = latestHash
	if !cfg.IgnoreFileNeedsUpdate(latestHash) {
		t.Fatal("modified active ignore file did not require an update")
	}

	if cfg.IgnoreFileNeedsUpdate("") {
		t.Fatal("valid active ignore file required an update without a remote hash")
	}
}
