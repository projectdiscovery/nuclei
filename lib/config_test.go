package nuclei

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/stretchr/testify/require"
)

func TestWithConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nuclei.yaml")
	cfg := `tags:
  - cve
severity:
  - high
  - critical
exclude-tags:
  - dos
header:
  - "X-Test: 1"
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))

	ne, err := NewNucleiEngine(WithConfigFile(cfgPath))
	require.NoError(t, err)
	defer ne.Close()

	opts := ne.Options()
	require.Contains(t, opts.Tags, "cve")
	require.Contains(t, opts.ExcludeTags, "dos")
	require.Contains(t, opts.CustomHeaders, "X-Test: 1")

	got := map[severity.Severity]bool{}
	for _, s := range opts.Severities {
		got[s] = true
	}
	require.True(t, got[severity.High])
	require.True(t, got[severity.Critical])
}

func TestWithConfigBytes(t *testing.T) {
	cfg := []byte("tags:\n  - cve\ntemplate-id:\n  - CVE-2024-0001\n")

	ne, err := NewNucleiEngine(WithConfigBytes(cfg))
	require.NoError(t, err)
	defer ne.Close()

	opts := ne.Options()
	require.Contains(t, opts.Tags, "cve")
	require.Contains(t, opts.IncludeIds, "CVE-2024-0001")
}

func TestWithConfigBytes_ScalarKnobs(t *testing.T) {
	cfg := []byte("rate-limit: 99\nbulk-size: 7\nconcurrency: 42\ntimeout: 30\nretries: 5\n")

	ne, err := NewNucleiEngine(WithConfigBytes(cfg))
	require.NoError(t, err)
	defer ne.Close()

	opts := ne.Options()
	require.Equal(t, 99, opts.RateLimit)
	require.Equal(t, 7, opts.BulkSize)
	require.Equal(t, 42, opts.TemplateThreads)
	require.Equal(t, 30, opts.Timeout)
	require.Equal(t, 5, opts.Retries)
}

func TestWithReportingConfigFile(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, "report.yaml")
	rc := `github:
  username: test-user
  owner: test-owner
  token: test-token
  project-name: test-project
  issue-label: test
`
	require.NoError(t, os.WriteFile(rcPath, []byte(rc), 0o600))

	ne, err := NewNucleiEngine(WithReportingConfigFile(rcPath))
	require.NoError(t, err)
	defer ne.Close()

	ropts := ne.reportingOptionsForTest()
	require.NotNil(t, ropts)
	require.NotNil(t, ropts.GitHub)
	require.Equal(t, "test-user", ropts.GitHub.Username)
	require.Equal(t, "test-owner", ropts.GitHub.Owner)
}

func TestWithReportingConfigBytes(t *testing.T) {
	rc := []byte(`github:
  username: test-user
  owner: test-owner
  token: test-token
  project-name: test-project
`)
	ne, err := NewNucleiEngine(WithReportingConfigBytes(rc))
	require.NoError(t, err)
	defer ne.Close()

	ropts := ne.reportingOptionsForTest()
	require.NotNil(t, ropts)
	require.NotNil(t, ropts.GitHub)
	require.Equal(t, "test-user", ropts.GitHub.Username)
}

// Invalid YAML must return an error, not a silently empty config.
func TestWithReportingConfigBytes_InvalidYAML(t *testing.T) {
	rc := []byte("this: is: not: valid: yaml: ::::\n")
	_, err := NewNucleiEngine(WithReportingConfigBytes(rc))
	require.Error(t, err)
}
