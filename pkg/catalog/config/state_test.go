package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadTemplatesConfigMigratesLegacyState(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	stateDir := filepath.Join(dir, "state")
	// Keep a backslash in the path so JSON escaping is exercised on all platforms.
	legacyRoot := filepath.Join(dir, `legacy\templates`)
	legacyState, err := json.Marshal(map[string]string{
		"nuclei-templates-directory": legacyRoot,
		"nuclei-templates-version":   "v1.2.3",
		"nuclei-ignore-hash":         "legacy-local-hash",
		"nuclei-latest-ignore-hash":  "legacy-remote-hash",
	})
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	writeTestFile(t, filepath.Join(configDir, legacyTemplatesConfigFileName), legacyState, 0o600)

	cfg := &Config{configDir: configDir, stateDir: stateDir}
	if err := cfg.ReadTemplatesConfig(); err != nil {
		t.Fatalf("read templates state: %v", err)
	}
	if cfg.TemplatesDirectory != legacyRoot {
		t.Fatalf("root = %q, want %q", cfg.TemplatesDirectory, legacyRoot)
	}
	if cfg.TemplateVersion != "v1.2.3" {
		t.Fatalf("template version = %q, want v1.2.3", cfg.TemplateVersion)
	}
	if cfg.NucleiIgnoreHash != "" {
		t.Fatalf("local ignore hash = %q, want empty", cfg.NucleiIgnoreHash)
	}
	if cfg.LatestNucleiIgnoreHash != "" {
		t.Fatalf("remote ignore hash = %q, want empty", cfg.LatestNucleiIgnoreHash)
	}
	cfg.NucleiIgnoreHash = "current-local-hash"
	cfg.LatestNucleiIgnoreHash = "current-remote-hash"
	if err := cfg.WriteTemplatesConfig(); err != nil {
		t.Fatalf("rewrite templates state: %v", err)
	}

	statePath := filepath.Join(stateDir, TemplatesStateFileName)
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat migrated state: %v", err)
	}
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Fatalf("state mode = %o, want 600", got)
	}
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read migrated state: %v", err)
	}
	if strings.Contains(string(state), "nuclei-ignore-hash") {
		t.Fatalf("migrated state persisted local ignore hash: %s", state)
	}
	if strings.Contains(string(state), "nuclei-latest-ignore-hash") {
		t.Fatalf("migrated state persisted remote ignore hash: %s", state)
	}
	if _, err := os.Stat(filepath.Join(configDir, legacyTemplatesConfigFileName)); err != nil {
		t.Fatalf("legacy state was removed: %v", err)
	}
}

func TestReadTemplatesConfigDoesNotHideCorruptState(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	stateDir := filepath.Join(dir, "state")
	writeTestFile(t, filepath.Join(configDir, legacyTemplatesConfigFileName), []byte(`{"nuclei-templates-directory":"legacy"}`), 0o600)
	writeTestFile(t, filepath.Join(stateDir, TemplatesStateFileName), []byte(`{"nuclei-templates-directory":`), 0o600)

	cfg := &Config{configDir: configDir, stateDir: stateDir}
	err := cfg.ReadTemplatesConfig()
	if err == nil {
		t.Fatal("expected corrupt new state to fail")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt state reported as missing: %v", err)
	}
	if cfg.TemplatesDirectory == "legacy" {
		t.Fatal("corrupt new state fell back to legacy state")
	}
}

func TestReadTemplatesConfigIgnoresLegacyRootSource(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	root := filepath.Join(dir, "system", BinaryName, NucleiTemplatesDirName)
	state, err := json.Marshal(map[string]string{
		"nuclei-templates-directory":        root,
		"nuclei-templates-directory-source": "xdg-system",
		"nuclei-templates-version":          "v1.2.3",
	})
	if err != nil {
		t.Fatalf("marshal templates state: %v", err)
	}
	statePath := filepath.Join(stateDir, TemplatesStateFileName)
	writeTestFile(t, statePath, state, 0o600)

	cfg := &Config{stateDir: stateDir, configDir: filepath.Join(dir, "config")}
	if err := cfg.ReadTemplatesConfig(); err != nil {
		t.Fatalf("read templates state: %v", err)
	}
	if cfg.TemplatesDirectory != root {
		t.Fatalf("root = %q, want %q", cfg.TemplatesDirectory, root)
	}
	if cfg.TemplateVersion != "v1.2.3" {
		t.Fatalf("template version = %q, want v1.2.3", cfg.TemplateVersion)
	}

	if err := cfg.WriteTemplatesConfig(); err != nil {
		t.Fatalf("rewrite templates state: %v", err)
	}
	rewritten, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read rewritten templates state: %v", err)
	}
	if strings.Contains(string(rewritten), "nuclei-templates-directory-source") {
		t.Fatalf("rewritten state retained legacy root source: %s", rewritten)
	}
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write test file: %v", err)
	}
}
