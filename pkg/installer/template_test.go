package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/stretchr/testify/require"
)

func TestTemplateInstallation(t *testing.T) {
	// test that the templates are installed correctly
	// along with necessary changes that are made
	HideProgressBar = true

	tm := &TemplateManager{}
	dir, err := os.MkdirTemp("", "nuclei-templates-*")
	require.Nil(t, err)
	cfgdir, err := os.MkdirTemp("", "nuclei-config-*")
	require.Nil(t, err)
	defer func() {
		_ = os.RemoveAll(dir)
		_ = os.RemoveAll(cfgdir)
	}()

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

func TestIsOutdatedVersion(t *testing.T) {
	testCases := []struct {
		current  string
		latest   string
		expected bool
		desc     string
	}{
		// Test the empty latest version case (main bug fix)
		{"v10.2.7", "", false, "Empty latest version should not trigger update"},

		// Test same versions
		{"v10.2.7", "v10.2.7", false, "Same versions should not trigger update"},

		// Test outdated version
		{"v10.2.6", "v10.2.7", true, "Older version should trigger update"},

		// Test newer current version (edge case)
		{"v10.2.8", "v10.2.7", false, "Newer current version should not trigger update"},

		// Test dev versions
		{"v10.2.7-dev", "v10.2.7", false, "Dev version matching release should not trigger update"},
		{"v10.2.6-dev", "v10.2.7", true, "Outdated dev version should trigger update"},

		// Test invalid semver fallback
		{"invalid-version", "v10.2.7", true, "Invalid current version should trigger update (fallback)"},
		{"v10.2.7", "invalid-version", true, "Invalid latest version should trigger update (fallback)"},
		{"same-invalid", "same-invalid", false, "Same invalid versions should not trigger update (fallback)"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := config.IsOutdatedVersion(tc.current, tc.latest)
			require.Equal(t, tc.expected, result,
				"IsOutdatedVersion(%q, %q) = %t, expected %t",
				tc.current, tc.latest, result, tc.expected)
		})
	}
}
