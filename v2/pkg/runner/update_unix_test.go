//go:build !windows

package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCalculateTemplateAbsolutePathNegativeScenario(t *testing.T) {
	configuredTemplateDirectory := filepath.Join(os.TempDir(), "templates")
	defer os.RemoveAll(configuredTemplateDirectory)

	t.Run("negative scenarios", func(t *testing.T) {
		filePathsFromZip := []string{
			"./../nuclei-templates/../cve/test.yaml",
			"nuclei-templates/../cve/test.yaml",
			"nuclei-templates/cve/../test.yaml",
			"nuclei-templates/././../cve/test.yaml",
			"nuclei-templates/.././../cve/test.yaml",
			"nuclei-templates/.././../cve/../test.yaml",
		}

		for _, filePathFromZip := range filePathsFromZip {
			calculatedTemplateAbsPath, skipFile, err := calculateTemplateAbsolutePath(filePathFromZip, configuredTemplateDirectory)
			require.Nil(t, err)
			require.True(t, skipFile)
			require.Equal(t, "", calculatedTemplateAbsPath)
		}
	})
}
