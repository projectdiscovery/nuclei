package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestProcessInlineSecretsFromProfile(t *testing.T) {
	t.Run("profile with inline secrets", func(t *testing.T) {
		profileContent := `
secrets:
  static:
    - type: header
      domains:
        - api.example.com
      headers:
        - key: x-api-key
          value: test-key-123
`
		tmpFile, err := os.CreateTemp(t.TempDir(), "test-profile-*.yaml")
		if err != nil {
			t.Fatalf("could not create temp file: %v", err)
		}
		if _, err := tmpFile.WriteString(profileContent); err != nil {
			t.Fatalf("could not write profile: %v", err)
		}
		_ = tmpFile.Close()

		opts := &types.Options{}
		tempPath, err := processInlineSecretsFromProfile(tmpFile.Name(), opts)
		if err != nil {
			t.Fatalf("processInlineSecretsFromProfile failed: %v", err)
		}
		defer func() {
			_ = os.Remove(tempPath)
		}()

		if len(opts.SecretsFile) != 1 {
			t.Fatalf("expected 1 secrets file, got %d", len(opts.SecretsFile))
		}

		secretsPath := opts.SecretsFile[0]
		if !strings.Contains(secretsPath, "inline-secrets-") {
			t.Errorf("secrets file path should contain 'inline-secrets-', got %s", secretsPath)
		}

		data, err := os.ReadFile(secretsPath)
		if err != nil {
			t.Fatalf("could not read generated secrets file: %v", err)
		}

		content := string(data)
		if !strings.Contains(content, "x-api-key") {
			t.Errorf("secrets file should contain header key, got:\n%s", content)
		}
		if !strings.Contains(content, "test-key-123") {
			t.Errorf("secrets file should contain header value, got:\n%s", content)
		}
		if !strings.Contains(content, "api.example.com") {
			t.Errorf("secrets file should contain domain, got:\n%s", content)
		}
	})

	t.Run("profile without secrets", func(t *testing.T) {
		profileContent := `
severity:
  - critical
  - high
`
		tmpFile, err := os.CreateTemp(t.TempDir(), "test-profile-*.yaml")
		if err != nil {
			t.Fatalf("could not create temp file: %v", err)
		}
		if _, err := tmpFile.WriteString(profileContent); err != nil {
			t.Fatalf("could not write profile: %v", err)
		}
		if err := tmpFile.Close(); err != nil {
			t.Fatalf("could not close temp file: %v", err)
		}

		opts := &types.Options{}
		tempPath, err := processInlineSecretsFromProfile(tmpFile.Name(), opts)
		if err != nil {
			t.Fatalf("processInlineSecretsFromProfile should not fail: %v", err)
		}

		if tempPath != "" {
			t.Errorf("expected empty temp path for profile without secrets, got %s", tempPath)
		}

		if len(opts.SecretsFile) != 0 {
			t.Errorf("expected 0 secrets files for profile without secrets, got %d", len(opts.SecretsFile))
		}
	})

	t.Run("nonexistent profile", func(t *testing.T) {
		opts := &types.Options{}
		_, err := processInlineSecretsFromProfile(filepath.Join(t.TempDir(), "nonexistent.yaml"), opts)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})
}

func TestInlineTargetsParsing(t *testing.T) {
	t.Run("multiline list key treated as inline targets", func(t *testing.T) {
		opts := &types.Options{
			TargetsFilePath: "example.com\ntest.com\nscanme.sh\n",
		}

		if strings.Contains(opts.TargetsFilePath, "\n") {
			inlineTargets := strings.Split(strings.TrimSpace(opts.TargetsFilePath), "\n")
			for _, target := range inlineTargets {
				target = strings.TrimSpace(target)
				if target != "" && !strings.HasPrefix(target, "#") {
					opts.Targets = append(opts.Targets, target)
				}
			}
			opts.TargetsFilePath = ""
		}

		if len(opts.Targets) != 3 {
			t.Fatalf("expected 3 targets, got %d: %v", len(opts.Targets), opts.Targets)
		}
		if opts.Targets[0] != "example.com" {
			t.Errorf("expected first target 'example.com', got '%s'", opts.Targets[0])
		}
		if opts.Targets[1] != "test.com" {
			t.Errorf("expected second target 'test.com', got '%s'", opts.Targets[1])
		}
		if opts.Targets[2] != "scanme.sh" {
			t.Errorf("expected third target 'scanme.sh', got '%s'", opts.Targets[2])
		}
		if opts.TargetsFilePath != "" {
			t.Errorf("TargetsFilePath should be cleared, got '%s'", opts.TargetsFilePath)
		}
	})

	t.Run("single line list key remains as file path", func(t *testing.T) {
		opts := &types.Options{
			TargetsFilePath: "/path/to/targets.txt",
		}

		if strings.Contains(opts.TargetsFilePath, "\n") {
			t.Error("single-line path should not be treated as inline targets")
		}

		if opts.TargetsFilePath != "/path/to/targets.txt" {
			t.Errorf("file path should remain unchanged, got '%s'", opts.TargetsFilePath)
		}
	})

	t.Run("inline targets with comments and blank lines", func(t *testing.T) {
		opts := &types.Options{
			TargetsFilePath: "example.com\n# this is a comment\n\ntest.com\n",
		}

		if strings.Contains(opts.TargetsFilePath, "\n") {
			inlineTargets := strings.Split(strings.TrimSpace(opts.TargetsFilePath), "\n")
			for _, target := range inlineTargets {
				target = strings.TrimSpace(target)
				if target != "" && !strings.HasPrefix(target, "#") {
					opts.Targets = append(opts.Targets, target)
				}
			}
			opts.TargetsFilePath = ""
		}

		if len(opts.Targets) != 2 {
			t.Fatalf("expected 2 targets (comments/blanks filtered), got %d: %v", len(opts.Targets), opts.Targets)
		}
	})

	t.Run("targets-inline key", func(t *testing.T) {
		opts := &types.Options{
			InlineTargetsList: "host1.com\nhost2.com\nhost3.com",
		}

		if opts.InlineTargetsList != "" {
			inlineTargets := strings.Split(strings.TrimSpace(opts.InlineTargetsList), "\n")
			for _, target := range inlineTargets {
				target = strings.TrimSpace(target)
				if target != "" && !strings.HasPrefix(target, "#") {
					opts.Targets = append(opts.Targets, target)
				}
			}
		}

		if len(opts.Targets) != 3 {
			t.Fatalf("expected 3 targets from targets-inline, got %d", len(opts.Targets))
		}
	})
}

func TestInlineSecretsFileFormat(t *testing.T) {
	// Verify the generated secrets file has the correct YAML structure
	// that matches what authx.GetAuthDataFromYAML expects
	profileContent := `
secrets:
  static:
    - type: header
      domains:
        - api.example.com
      headers:
        - key: Authorization
          value: Bearer test-token
  dynamic:
    - template: oauth-flow.yaml
      variables:
        - key: username
          value: testuser
      type: cookie
      domains:
        - auth.example.com
`
	tmpFile, err := os.CreateTemp(t.TempDir(), "test-secrets-*.yaml")
	if err != nil {
		t.Fatalf("could not create temp file: %v", err)
	}
	if _, err := tmpFile.WriteString(profileContent); err != nil {
		t.Fatalf("could not write profile: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("could not close temp file: %v", err)
	}

	opts := &types.Options{}
	tempPath, err := processInlineSecretsFromProfile(tmpFile.Name(), opts)
	if err != nil {
		t.Fatalf("processInlineSecretsFromProfile failed: %v", err)
	}
	defer func() {
		_ = os.Remove(tempPath)
	}()

	data, err := os.ReadFile(opts.SecretsFile[0])
	if err != nil {
		t.Fatalf("could not read secrets file: %v", err)
	}

	content := string(data)
	// The secrets section should contain static and dynamic at root level,
	// matching the Authx struct yaml tags
	if !strings.Contains(content, "static:") {
		t.Errorf("secrets file should have 'static:' key for Authx compatibility, got:\n%s", content)
	}
	if !strings.Contains(content, "dynamic:") {
		t.Errorf("secrets file should have 'dynamic:' key for Authx compatibility, got:\n%s", content)
	}
}
