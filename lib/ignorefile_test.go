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

// TestIgnoreFileSurvivesAuthTemplateStore pins the ordering of the ignore-file
// read within init.
//
// GetAuthTmplStore scopes its own template store by nilling every filter field
// on the shared *types.Options — ExcludeTags and ExcludedTemplates included —
// and does not restore them. It runs whenever SecretsFile is set, so reading
// .nuclei-ignore before it leaves the engine with no deny-list for the rest of
// its lifetime, ExcludeTags never being re-read after init.
//
// A static-only secrets file is enough: the store is built, and the fields
// nilled, regardless of whether any dynamic templates are present.
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

	engine, err := NewNucleiEngineCtx(context.Background(),
		WithOptions(opts),
		DisableUpdateCheck(),
	)
	require.NoError(t, err)
	t.Cleanup(engine.Close)

	require.Contains(t, []string(engine.Options().ExcludeTags), "dos",
		"the .nuclei-ignore deny-list must survive GetAuthTmplStore nilling the filter fields")
	require.Contains(t, []string(engine.Options().ExcludedTemplates), "dns/soa-detect.yaml",
		"the files section must survive it too")
}
