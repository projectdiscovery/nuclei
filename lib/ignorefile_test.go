package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// Update checks are disabled explicitly so this pins corrupt-file rejection on
// its own. The ignore file is read after init's update block, which may replace
// a corrupt file via UpdateIgnoreFile — with update checks left on, this test
// would assert rejection or repair depending on whether the process could reach
// the network.
func TestNewNucleiEngineRejectsCorruptActiveIgnoreFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, config.NucleiIgnoreFileName)
	require.NoError(t, os.WriteFile(path, []byte("tags: ["), 0o600))

	cfg := config.DefaultConfig
	oldRoot := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(oldRoot) })
	cfg.SetTemplatesDir(root)

	engine, err := NewNucleiEngineCtx(context.Background(), DisableUpdateCheck())
	require.Nil(t, engine)
	require.ErrorContains(t, err, "error parsing")
	require.ErrorContains(t, err, strconv.Quote(path))
}

// TestIgnoreFileSurvivesAuthTemplateStore pins two init orderings.
//
// The ignore file is read after the update block, so a file this same call
// creates is the one that becomes the deny-list. GetAuthTmplStore also runs
// during init whenever SecretsFile is set. It must scope a copy of the
// options: the caller's Templates and ExcludeTags stay put, and the ignore
// file is still applied on top.
//
// A static-only secrets file is enough to build that store.
func TestIgnoreFileSurvivesAuthTemplateStore(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(root, config.NucleiIgnoreFileName),
		[]byte("tags:\n  - dos\nfiles:\n  - dns/soa-detect.yaml\n"),
		0o600,
	))

	cfg := config.DefaultConfig
	oldRoot := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(oldRoot) })
	cfg.SetTemplatesDir(root)

	secrets := filepath.Join(root, "secrets.yaml")
	require.NoError(t, os.WriteFile(secrets, []byte(`static:
  - type: header
    domains:
      - example.com
    headers:
      - key: x-api-key
        value: not-a-real-secret
`), 0o600))

	opts := types.DefaultOptions()
	opts.SecretsFile = []string{secrets}
	opts.Templates = []string{"http/kept.yaml"}
	opts.ExcludeTags = []string{"custom"}

	engine, err := NewNucleiEngineCtx(context.Background(),
		WithOptions(opts),
		DisableUpdateCheck(),
	)
	require.NoError(t, err)
	t.Cleanup(engine.Close)

	require.Equal(t, []string{"http/kept.yaml"}, []string(engine.Options().Templates),
		"the auth store must not replace the caller's template list")
	require.Contains(t, []string(engine.Options().ExcludeTags), "custom",
		"the caller's own excluded tags must survive auth-store setup")
	require.Contains(t, []string(engine.Options().ExcludeTags), "dos",
		"the .nuclei-ignore deny-list must be applied after auth-store setup")
	require.Contains(t, []string(engine.Options().ExcludedTemplates), "dns/soa-detect.yaml",
		"the files section must be applied too")
}
