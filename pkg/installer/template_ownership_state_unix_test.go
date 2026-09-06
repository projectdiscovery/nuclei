//go:build !windows

package installer

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadTemplateRestoreStateRejectsFIFO(t *testing.T) {
	templatesDir := t.TempDir()
	root, err := os.OpenRoot(templatesDir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })

	state := templateRestoreState{
		retiredPath: "retired.yaml",
		statePath:   templateRestoreStatePrefix("retired.yaml") + strings.Repeat("a", 32),
	}
	require.NoError(t, syscall.Mkfifo(filepath.Join(templatesDir, state.statePath), 0o600))
	require.ErrorContains(t, loadTemplateRestoreState(root, &state), "is not a regular file")
}
