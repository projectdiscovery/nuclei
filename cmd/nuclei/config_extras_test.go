package main

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "nuclei-test-*.yaml")
	if err != nil {
		t.Fatalf("could not create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("could not write temp file: %v", err)
	}
	_ = f.Close()
	return f.Name()
}

// TestProcessConfigExtras_UnknownFieldsIgnored verifies that metadata fields
// (name, purpose, id) in a config file do not cause errors.
func TestProcessConfigExtras_UnknownFieldsIgnored(t *testing.T) {
	cfg := writeTemp(t, `
name: my-scan
purpose: testing
id: scan-001
description: sanity check

timeout: 30
`)
	opts := &types.Options{}
	if err := processConfigExtras(cfg, opts); err != nil {
		t.Fatalf("unexpected error for config with metadata fields: %v", err)
	}
	// no targets or secrets should have been set
	if opts.TargetsFilePath != "" {
		t.Errorf("expected TargetsFilePath to be empty, got %q", opts.TargetsFilePath)
	}
	if len(opts.SecretsFile) != 0 {
		t.Errorf("expected no secrets files, got %v", []string(opts.SecretsFile))
	}
}

// TestProcessConfigExtras_InlineListBlockScalar verifies that a block-scalar
// "list" section creates a temp targets file.
func TestProcessConfigExtras_InlineListBlockScalar(t *testing.T) {
	cfg := writeTemp(t, `
name: pd-scan
list: |
  cve.projectdiscovery.io
  chaos.projectdiscovery.io
  api.projectdiscovery.io
`)
	opts := &types.Options{}
	if err := processConfigExtras(cfg, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts.TargetsFilePath == "" {
		t.Fatal("expected TargetsFilePath to be set")
	}
	internalTempFiles = nil // reset for other tests

	content, err := os.ReadFile(opts.TargetsFilePath)
	if err != nil {
		t.Fatalf("could not read temp targets file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 targets, got %d: %v", len(lines), lines)
	}
	_ = os.Remove(opts.TargetsFilePath)
}

// TestProcessConfigExtras_InlineListYAMLSequence verifies that a YAML-sequence
// "list" section creates a temp targets file.
func TestProcessConfigExtras_InlineListYAMLSequence(t *testing.T) {
	cfg := writeTemp(t, `
list:
  - target1.example.com
  - target2.example.com
`)
	opts := &types.Options{}
	if err := processConfigExtras(cfg, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.TargetsFilePath == "" {
		t.Fatal("expected TargetsFilePath to be set")
	}
	internalTempFiles = nil

	content, err := os.ReadFile(opts.TargetsFilePath)
	if err != nil {
		t.Fatalf("could not read temp targets file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 targets, got %d: %v", len(lines), lines)
	}
	_ = os.Remove(opts.TargetsFilePath)
}

// TestProcessConfigExtras_InlineListRespectsCLI verifies that when TargetsFilePath
// already points to a real file (set via -l CLI flag), it is not overridden.
func TestProcessConfigExtras_InlineListRespectsCLI(t *testing.T) {
	// Create a real "CLI-set" targets file.
	cliFile := writeTemp(t, "cli-target.example.com\n")

	cfg := writeTemp(t, `
list:
  - config-target1.example.com
  - config-target2.example.com
`)
	opts := &types.Options{TargetsFilePath: cliFile}
	if err := processConfigExtras(cfg, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// CLI file must win.
	if opts.TargetsFilePath != cliFile {
		t.Errorf("expected TargetsFilePath to remain %q, got %q", cliFile, opts.TargetsFilePath)
	}
}

// TestProcessConfigExtras_InlineSecrets verifies that a "secrets" section is
// written to a temp file and appended to SecretsFile.
func TestProcessConfigExtras_InlineSecrets(t *testing.T) {
	cfg := writeTemp(t, `
name: pd-scan

secrets:
  static:
    - type: header
      domains:
        - api.projectdiscovery.io
      headers:
        - key: x-pdcp-key
          value: test-api-key-here
`)
	opts := &types.Options{}
	if err := processConfigExtras(cfg, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts.SecretsFile) != 1 {
		t.Fatalf("expected 1 secrets file, got %d", len(opts.SecretsFile))
	}
	tmpSecretsPath := opts.SecretsFile[0]
	internalTempFiles = nil

	if !fileutil.FileExists(tmpSecretsPath) {
		t.Fatalf("temp secrets file does not exist: %s", tmpSecretsPath)
	}
	content, err := os.ReadFile(tmpSecretsPath)
	if err != nil {
		t.Fatalf("could not read temp secrets file: %v", err)
	}
	if !strings.Contains(string(content), "x-pdcp-key") {
		t.Errorf("secrets file missing expected key content, got:\n%s", string(content))
	}
	_ = os.Remove(tmpSecretsPath)
}

// TestProcessConfigExtras_InlineSecretsAndList verifies that both "secrets" and
// "list" can be used together in a single config file.
func TestProcessConfigExtras_InlineSecretsAndList(t *testing.T) {
	cfg := writeTemp(t, `
name: combined-scan
purpose: test both features

list:
  - scanme.example.com

secrets:
  static:
    - type: header
      domains:
        - scanme.example.com
      headers:
        - key: Authorization
          value: Bearer test-token
`)
	opts := &types.Options{}
	if err := processConfigExtras(cfg, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts.TargetsFilePath == "" {
		t.Error("expected TargetsFilePath to be set")
	}
	if len(opts.SecretsFile) != 1 {
		t.Errorf("expected 1 secrets file, got %d", len(opts.SecretsFile))
	}

	// Cleanup
	for _, f := range internalTempFiles {
		_ = os.Remove(f)
	}
	internalTempFiles = nil
}

// TestProcessConfigExtras_FilePathList verifies that a single-line "list" value
// (a file path) is left alone — goflags handles that case.
func TestProcessConfigExtras_FilePathList(t *testing.T) {
	cfg := writeTemp(t, `
list: /tmp/my-targets.txt
`)
	opts := &types.Options{}
	if err := processConfigExtras(cfg, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not have created a temp file for a single-line list value.
	if opts.TargetsFilePath != "" {
		t.Errorf("expected TargetsFilePath to remain empty (goflags handles single-line list), got %q", opts.TargetsFilePath)
	}
}

// TestCleanupInternalTempFiles verifies that cleanup removes the registered files.
func TestCleanupInternalTempFiles(t *testing.T) {
	f, err := os.CreateTemp("", "nuclei-cleanup-test-*")
	if err != nil {
		t.Fatalf("could not create temp file: %v", err)
	}
	_ = f.Close()
	path := f.Name()

	internalTempFiles = []string{path}
	cleanupInternalTempFiles()
	internalTempFiles = nil

	if fileutil.FileExists(path) {
		t.Errorf("expected temp file %q to be deleted after cleanup", path)
	}
}
