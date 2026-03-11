package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Parse / metadata tests ---

func TestParseMetadata(t *testing.T) {
	yaml := `
id: my-scan
name: My Scan
purpose: Daily scan
description: Scans example.com daily
tags: cve
exclude-tags: dos,fuzz
`
	p, err := Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ID != "my-scan" {
		t.Errorf("ID: got %q, want %q", p.ID, "my-scan")
	}
	if p.Name != "My Scan" {
		t.Errorf("Name: got %q, want %q", p.Name, "My Scan")
	}
	if p.Purpose != "Daily scan" {
		t.Errorf("Purpose: got %q, want %q", p.Purpose, "Daily scan")
	}
	if p.Description != "Scans example.com daily" {
		t.Errorf("Description: got %q, want %q", p.Description, "Scans example.com daily")
	}

	// metadata keys must NOT appear in FlagOverrides (they'd confuse goflags)
	for _, reserved := range []string{"id", "name", "purpose", "description"} {
		if _, ok := p.FlagOverrides[reserved]; ok {
			t.Errorf("reserved key %q leaked into FlagOverrides", reserved)
		}
	}

	// nuclei-flag keys MUST appear in FlagOverrides
	if _, ok := p.FlagOverrides["tags"]; !ok {
		t.Error("expected 'tags' in FlagOverrides")
	}
	if _, ok := p.FlagOverrides["exclude-tags"]; !ok {
		t.Error("expected 'exclude-tags' in FlagOverrides")
	}
}

func TestParseExtraFieldsIgnored(t *testing.T) {
	// Fields that are not nuclei flags and not our reserved keys should still be
	// carried through to FlagOverrides without causing a parse error.
	yaml := `
id: test
some-unknown-field: value
another-custom-key: 123
tags: cve
`
	p, err := Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("Parse should not fail on extra fields: %v", err)
	}
	if _, ok := p.FlagOverrides["some-unknown-field"]; !ok {
		t.Error("extra field 'some-unknown-field' should be in FlagOverrides (goflags will ignore unknowns)")
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := Parse([]byte{}, "empty.yml")
	if err == nil {
		t.Error("expected error for empty profile")
	}
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := Parse([]byte(":\tinvalid: yaml: ["), "bad.yml")
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// --- Validate tests ---

func TestValidateOK(t *testing.T) {
	p := &Profile{Metadata: Metadata{ID: "valid-id"}}
	if err := p.Validate(); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestValidateIDWithSpaces(t *testing.T) {
	p := &Profile{Metadata: Metadata{ID: "has space"}}
	if err := p.Validate(); err == nil {
		t.Error("expected validation error for ID with spaces")
	}
}

func TestValidateSecretsNotAMap(t *testing.T) {
	p := &Profile{InlineSecrets: "just a string, not a map"}
	if err := p.Validate(); err == nil {
		t.Error("expected validation error when secrets is not a mapping")
	}
}

// --- MaterializeTargets tests ---

func TestMaterializeTargets(t *testing.T) {
	p := &Profile{
		InlineTargets: `
  example.com
  api.example.com
  # this is a comment
  
  chaos.projectdiscovery.io
`,
	}

	tmpDir := t.TempDir()
	path, err := p.MaterializeTargets(tmpDir)
	if err != nil {
		t.Fatalf("MaterializeTargets: %v", err)
	}
	if path == "" {
		t.Fatal("expected non-empty path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	for _, expected := range []string{"example.com", "api.example.com", "chaos.projectdiscovery.io"} {
		if !strings.Contains(content, expected) {
			t.Errorf("expected %q in target file content", expected)
		}
	}
	// Comments should be stripped.
	if strings.Contains(content, "this is a comment") {
		t.Error("comments should be stripped from target file")
	}
	// File should be registered as a temp file.
	if len(p.TempFiles()) != 1 || p.TempFiles()[0] != path {
		t.Error("temp file not registered")
	}
}

func TestMaterializeTargetsEmpty(t *testing.T) {
	p := &Profile{}
	path, err := p.MaterializeTargets(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "" {
		t.Errorf("expected empty path for empty InlineTargets, got %q", path)
	}
}

// --- MaterializeSecrets tests ---

func TestMaterializeSecrets(t *testing.T) {
	yamlInput := `
id: test
secrets:
  static:
    - type: header
      domains:
        - example.com
      headers:
        - key: X-API-Key
          value: secret123
`
	p, err := Parse([]byte(yamlInput), "test.yml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.InlineSecrets == nil {
		t.Fatal("expected InlineSecrets to be non-nil")
	}

	tmpDir := t.TempDir()
	path, err := p.MaterializeSecrets(tmpDir)
	if err != nil {
		t.Fatalf("MaterializeSecrets: %v", err)
	}
	if path == "" {
		t.Fatal("expected non-empty path for inline secrets")
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "X-API-Key") {
		t.Errorf("expected secret header key in materialized secrets file, got: %s", content)
	}
}

func TestMaterializeSecretsNil(t *testing.T) {
	p := &Profile{}
	path, err := p.MaterializeSecrets(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "" {
		t.Errorf("expected empty path when no inline secrets, got %q", path)
	}
}

// --- WriteFlagsFile tests ---

func TestWriteFlagsFile(t *testing.T) {
	yaml := `
tags: cve
exclude-tags: dos,fuzz
template-concurrency: 5
`
	p, err := Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	tmpDir := t.TempDir()
	path, err := p.WriteFlagsFile(tmpDir)
	if err != nil {
		t.Fatalf("WriteFlagsFile: %v", err)
	}
	if path == "" {
		t.Fatal("expected non-empty path")
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "tags") {
		t.Error("flags file should contain 'tags'")
	}
	// Metadata keys must not appear in the flags file.
	for _, key := range []string{"id:", "name:", "purpose:", "description:", "list:", "secrets:"} {
		if strings.Contains(content, key) {
			t.Errorf("flags file should not contain reserved key %q", key)
		}
	}
}

// --- Summary tests ---

func TestSummary(t *testing.T) {
	cases := []struct {
		p    Profile
		want string
	}{
		{Profile{Metadata: Metadata{Name: "My Scan", Purpose: "daily"}}, "My Scan (daily)"},
		{Profile{Metadata: Metadata{ID: "vuln-scan"}}, "vuln-scan"},
		{Profile{}, "(unnamed profile)"},
	}
	for _, tc := range cases {
		got := tc.p.Summary()
		if got != tc.want {
			t.Errorf("Summary() = %q, want %q", got, tc.want)
		}
	}
}

// --- ListProfiles tests ---

func TestListProfiles(t *testing.T) {
	root := t.TempDir()
	profilesDir := filepath.Join(root, "profiles")
	if err := os.MkdirAll(profilesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write two profile files.
	profile1 := `id: cloud\nname: Cloud Scan\ntags: cloud`
	profile2 := `id: cve-scan\ntags: cve`
	if err := os.WriteFile(filepath.Join(profilesDir, "cloud.yml"), []byte(profile1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profilesDir, "cve.yaml"), []byte(profile2), 0o644); err != nil {
		t.Fatal(err)
	}
	// Write a non-YAML file that should be ignored.
	if err := os.WriteFile(filepath.Join(profilesDir, "README.txt"), []byte("ignore me"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := ListProfiles(profilesDir, root)
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}

	ids := make(map[string]bool)
	for _, e := range entries {
		ids[e.ProfileID] = true
	}
	if !ids["cloud"] || !ids["cve"] {
		t.Errorf("expected profile IDs 'cloud' and 'cve', got %v", ids)
	}
}
