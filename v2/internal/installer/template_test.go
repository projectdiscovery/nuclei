package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/stretchr/testify/require"
)

func TestTemplateInstallation(t *testing.T) {
	// test that the templates are installed correctly
	// along with necessary changes that are made
	HideProgressBar = true

	tm := &TemplateManager{}
	dir, err := os.MkdirTemp("", "nuclei-templates-*")
	require.Nil(t, err)
	defer os.RemoveAll(dir)
	cfgdir, err := os.MkdirTemp("", "nuclei-config-*")
	require.Nil(t, err)
	defer os.RemoveAll(cfgdir)

	// set the config directory to a temporary directory
	config.DefaultConfig.SetConfigDir(cfgdir)
	// set the templates directory to a temporary directory
	templatesTempDir := filepath.Join(dir, "templates")
	config.DefaultConfig.SetTemplatesDir(templatesTempDir)

	err = tm.FreshInstallIfNotExists()
	if err != nil {
		if strings.Contains(err.Error(), "rate limit") {
			t.Skip("Skipping test due to github rate limit")
		}
		require.Nil(t, err)
	}

	// we should switch to more fine granular tests for template
	// integrity, but for now, we just check that the templates are installed
	counter := 0
	err = filepath.Walk(templatesTempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			counter++
		}
		return nil
	})
	require.Nil(t, err)

	// we should have at least 1000 templates
	require.Greater(t, counter, 1000)
	// every time we install templates, it should override the ignore file with latest one
	require.FileExists(t, config.DefaultConfig.GetIgnoreFilePath())
	t.Logf("Installed %d templates", counter)
}
