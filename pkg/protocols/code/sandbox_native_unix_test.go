//go:build linux || darwin

package code

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/gozero"
	gozerotypes "github.com/projectdiscovery/gozero/types"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/stretchr/testify/require"
)

// TestNativeFallbackConfinesPayload runs a real payload through the native
// fallback (seatbelt or bubblewrap): it can write its workspace, and it can
// neither write the home directory nor read files under it (such as ~/.ssh).
func TestNativeFallbackConfinesPayload(t *testing.T) {
	if _, err := detectNativeSandbox(); err != nil {
		t.Skipf("native sandbox unavailable: %v", err)
	}
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	canaryDir, err := os.MkdirTemp(home, ".nuclei-seatbelt-canary-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(canaryDir) })
	secret := "NUCLEI_SEATBELT_SECRET"
	require.NoError(t, os.WriteFile(filepath.Join(canaryDir, "secret"), []byte(secret), 0o600))
	homeWrite := filepath.Join(canaryDir, "written")

	script := `
echo ws > "$HOME/ws-file" && cat "$HOME/ws-file"
echo pwned > "$HOME_WRITE" 2>/dev/null && echo HOME_WRITE_OK || echo HOME_WRITE_DENIED
cat "$CANARY" 2>/dev/null || echo HOME_READ_DENIED
ls "$REAL_HOME/.ssh" >/dev/null 2>&1 && echo SSH_READ_OK || echo SSH_READ_DENIED
`
	src, err := gozero.NewSourceWithString(script, "", t.TempDir())
	require.NoError(t, err)
	input, err := gozero.NewSourceWithString("", "", t.TempDir())
	require.NoError(t, err)
	input.AddVariable(
		gozerotypes.Variable{Name: "HOME_WRITE", Value: homeWrite},
		gozerotypes.Variable{Name: "CANARY", Value: filepath.Join(canaryDir, "secret")},
		gozerotypes.Variable{Name: "REAL_HOME", Value: home},
	)

	options := testutils.DefaultOptions.Copy()
	request := &Request{Engine: []string{"sh"}, src: src}
	request.options = testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{})
	request.options.TemporaryDirectory = t.TempDir()

	result, err := request.evalNative(context.Background(), input)
	require.NoError(t, err, "stderr: %s", result.Stderr.String())
	out := result.Stdout.String()
	require.Contains(t, out, "ws\n")
	require.Contains(t, out, "HOME_WRITE_DENIED")
	require.Contains(t, out, "HOME_READ_DENIED")
	require.Contains(t, out, "SSH_READ_DENIED")
	require.NotContains(t, out, secret)
	require.NoFileExists(t, homeWrite)
}
