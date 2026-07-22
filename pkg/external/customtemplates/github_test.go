package customtemplates

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestDownloadCustomTemplatesFromGitHub(t *testing.T) {
	// Capture output to check for rate limit errors
	outputBuffer := &bytes.Buffer{}
	gologger.DefaultLogger.SetWriter(&utils.CaptureWriter{Buffer: outputBuffer})
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	templatesDirectory := t.TempDir()
	config.DefaultConfig.SetTemplatesDir(templatesDirectory)

	options := testutils.DefaultOptions
	options.GitHubTemplateRepo = []string{"projectdiscovery/nuclei-templates-test"}

	ctm, err := NewCustomTemplatesManager(options)
	require.Nil(t, err, "could not create custom templates manager")

	clonedDir := filepath.Join(templatesDirectory, "github", "projectdiscovery", "nuclei-templates-test")

	// This clones the live projectdiscovery/nuclei-templates-test repo, so a
	// transient GitHub hiccup (rate limit, TLS/timeout, reset) must not fail CI.
	// Retry a few times; if the clone still fails only because of a transient
	// remote error, skip instead of failing.
	var cloned bool
	var output string
	for attempt := 1; attempt <= 3; attempt++ {
		_ = os.RemoveAll(clonedDir) // force a real re-clone on retry
		outputBuffer.Reset()
		ctm.Download(context.Background())
		output = outputBuffer.String()
		if _, statErr := os.Stat(clonedDir); statErr == nil {
			cloned = true
			break
		}
		time.Sleep(time.Duration(attempt) * time.Second)
	}

	if !cloned && isTransientRemoteError(output) {
		t.Skipf("skipping: transient GitHub error cloning test repo:\n%s", output)
	}

	require.True(t, cloned, "cloned directory does not exist:\n%s", output)
}

// isTransientRemoteError reports whether the captured log output indicates a
// transient network/GitHub failure (as opposed to a real regression), so the
// test can be skipped rather than failed on flaky CI networking.
func isTransientRemoteError(output string) bool {
	lower := strings.ToLower(output)
	for _, needle := range []string{
		"api rate limit exceeded",
		"timeout", "timed out", "deadline exceeded", "i/o timeout",
		"connection reset", "connection refused", "no such host",
		"tls handshake", "eof", "temporary failure", "dial tcp",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
