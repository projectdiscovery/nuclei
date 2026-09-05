package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/stretchr/testify/require"
)

func TestNewNucleiEngineRejectsCorruptActiveIgnoreFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, config.NucleiIgnoreFileName)
	require.NoError(t, os.WriteFile(path, []byte("tags: ["), 0o600))

	cfg := config.DefaultConfig
	oldRoot := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(oldRoot) })
	cfg.SetTemplatesDir(root)

	engine, err := NewNucleiEngineCtx(context.Background())
	require.Nil(t, engine)
	require.ErrorContains(t, err, "error parsing")
	require.ErrorContains(t, err, strconv.Quote(path))
}
