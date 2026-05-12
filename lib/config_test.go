package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	unitutils "github.com/projectdiscovery/utils/unit"
	"github.com/stretchr/testify/require"
)

func TestWithConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nuclei.yaml")
	cfg := `concurrency: 42
bulk-size: 7
severity:
  - high
  - critical
exclude-tags:
  - dos
  - intrusive
rate-limit: 99
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))

	ne, err := NewNucleiEngine(
		WithConfigFile(cfgPath),
	)
	require.NoError(t, err)
	defer ne.Close()

	opts := ne.Options()
	require.Equal(t, 42, opts.TemplateThreads, "concurrency from config should land in TemplateThreads")
	require.Equal(t, 7, opts.BulkSize, "bulk-size from config should land in BulkSize")
	require.Equal(t, 99, opts.RateLimit, "rate-limit from config should land in RateLimit")

	gotSeverities := map[severity.Severity]bool{}
	for _, s := range opts.Severities {
		gotSeverities[s] = true
	}
	require.True(t, gotSeverities[severity.High], "severity high should be set")
	require.True(t, gotSeverities[severity.Critical], "severity critical should be set")

	require.Contains(t, opts.ExcludeTags, "dos")
	require.Contains(t, opts.ExcludeTags, "intrusive")
}

func TestWithConfigBytes(t *testing.T) {
	cfg := []byte("concurrency: 17\nbulk-size: 3\n")

	ne, err := NewNucleiEngine(
		WithConfigBytes(cfg),
	)
	require.NoError(t, err)
	defer ne.Close()

	opts := ne.Options()
	require.Equal(t, 17, opts.TemplateThreads)
	require.Equal(t, 3, opts.BulkSize)
}

// Regression: prior direct-bind impl clobbered DefaultOptions values
// (Timeout 5→10, ResponseReadSize 10MB→0) when the YAML didn't mention them.
func TestWithConfigFile_PreservesDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nuclei.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("bulk-size: 7\n"), 0o600))

	ne, err := NewNucleiEngine(
		WithConfigFile(cfgPath),
	)
	require.NoError(t, err)
	defer ne.Close()

	opts := ne.Options()
	require.Equal(t, 7, opts.BulkSize, "YAML override should apply")
	require.Equal(t, 5, opts.Timeout, "DefaultOptions Timeout must survive")
	require.Equal(t, 10*unitutils.Mega, opts.ResponseReadSize, "DefaultOptions ResponseReadSize must survive")
}

// A With* option set before WithConfigFile must survive when YAML omits the field.
func TestWithConfigFile_DoesNotClobberPriorOptions(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nuclei.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("bulk-size: 7\n"), 0o600))

	ne, err := NewNucleiEngine(
		WithGlobalRateLimit(99, time.Second),
		WithConfigFile(cfgPath),
	)
	require.NoError(t, err)
	defer ne.Close()

	opts := ne.Options()
	require.Equal(t, 7, opts.BulkSize, "YAML bulk-size should apply")
	require.Equal(t, 99, opts.RateLimit, "prior WithGlobalRateLimit must survive WithConfigFile")
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

	ne, err := NewNucleiEngine(
		WithReportingConfigFile(rcPath),
	)
	require.NoError(t, err)
	defer ne.Close()

	ropts := ne.reportingOptionsForTest()
	require.NotNil(t, ropts, "reportingOpts should be populated")
	require.NotNil(t, ropts.GitHub, "GitHub tracker should be parsed from YAML")
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
	ne, err := NewNucleiEngine(
		WithReportingConfigBytes(rc),
	)
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
	_, err := NewNucleiEngine(
		WithReportingConfigBytes(rc),
	)
	require.Error(t, err)
}

// ExecuteNucleiWithOpts must reject With* options gated on e.mode == threadSafe;
// tmpEngine is built with mode=threadSafe in multi.go.
func TestPerScanOptions_RejectIncompatibleOptions(t *testing.T) {
	ne, err := NewThreadSafeNucleiEngineCtx(context.Background())
	require.NoError(t, err)
	defer ne.Close()

	err = ne.ExecuteNucleiWithOpts([]string{"scanme.sh"}, WithVerbosity(VerbosityOptions{Verbose: true}))
	require.Error(t, err, "WithVerbosity should reject per-scan use")
	require.ErrorIs(t, err, ErrOptionsNotSupported)
}
