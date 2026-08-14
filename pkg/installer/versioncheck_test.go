package installer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/utils/generic"
	"github.com/stretchr/testify/require"
)

func TestVersionCheck(t *testing.T) {
	err := NucleiVersionCheck()
	require.Nil(t, err)
	cfg := config.DefaultConfig
	if generic.EqualsAny("", cfg.LatestNucleiIgnoreHash, cfg.LatestNucleiVersion, cfg.LatestNucleiTemplatesVersion) {
		// all above values cannot be empty
		t.Errorf("something went wrong got empty response nuclei-version=%v templates-version=%v ignore-hash=%v", cfg.LatestNucleiVersion, cfg.LatestNucleiTemplatesVersion, cfg.LatestNucleiIgnoreHash)
	}
}

func TestWriteNucleiIgnoreFile(t *testing.T) {
	valid := []byte("tags:\n  - dos\nfiles:\n  - http/test.yaml\n")

	t.Run("valid ignore file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), config.NucleiIgnoreFileName)
		require.NoError(t, writeNucleiIgnoreFile(path, valid))

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, valid, got)
	})

	invalid := map[string][]byte{
		"proxy html response": []byte("<!DOCTYPE HTML>\n<html>\n<head>\n<meta name=\"description\" content=\"Zscaler: blocked\">\n</head>\n</html>\n"),
		"unrelated yaml":      []byte("error: access denied\nmessage: blocked by proxy\n"),
	}
	for name, data := range invalid {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), config.NucleiIgnoreFileName)
			require.NoError(t, os.WriteFile(path, valid, 0600))

			require.Error(t, writeNucleiIgnoreFile(path, data))

			got, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, valid, got, "invalid download must not overwrite the existing ignore file")
		})
	}
}
