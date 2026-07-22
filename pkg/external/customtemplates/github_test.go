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
	// Authenticate the GitHub API repo lookup when a token is available (CI sets
	// GITHUB_TOKEN). The unauthenticated API is capped at 60 req/hr per IP, which
	// the shared CI egress exhausts and is the main source of this test's flake;
	// an authenticated call gets 5000/hr and resolves reliably.
	options.GitHubToken = os.Getenv("GITHUB_TOKEN")

	clonedDir := filepath.Join(templatesDirectory, "github", "projectdiscovery", "nuclei-templates-test")

	// The lookup + clone hit the live repo, so a transient GitHub/network hiccup
	// must not fail CI. Recreate the manager (re-resolving the repo) and retry a
	// few times; if it still fails only because of a transient remote error,
	// skip instead of failing. The captured log is NOT reset between attempts so
	// a rate-limit/API error logged at manager creation is still detectable.
	var cloned bool
	for attempt := 1; attempt <= 3; attempt++ {
		_ = os.RemoveAll(clonedDir) // force a real re-clone on retry
		ctm, err := NewCustomTemplatesManager(options)
		require.Nil(t, err, "could not create custom templates manager")
		ctm.Download(context.Background())
		if _, statErr := os.Stat(clonedDir); statErr == nil {
			cloned = true
			break
		}
		time.Sleep(time.Duration(attempt) * time.Second)
	}

	if !cloned && isTransientRemoteError(outputBuffer.String()) {
		t.Skipf("skipping: transient GitHub error cloning test repo:\n%s", outputBuffer.String())
	}

	require.True(t, cloned, "cloned directory does not exist:\n%s", outputBuffer.String())
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
