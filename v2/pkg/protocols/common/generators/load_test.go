package generators

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	osutils "github.com/projectdiscovery/utils/os"
	"github.com/stretchr/testify/require"
)

func TestLoadPayloads(t *testing.T) {
	tempdir, err := os.MkdirTemp("", "templates-*")
	require.NoError(t, err, "could not create temp dir")
	defer os.RemoveAll(tempdir)

	generator := &PayloadGenerator{catalog: disk.NewCatalog(tempdir)}

	fullpath := filepath.Join(tempdir, "payloads.txt")
	err = os.WriteFile(fullpath, []byte("test\nanother"), 0777)
	require.NoError(t, err, "could not write payload")

	// Test sandbox
	t.Run("templates-directory", func(t *testing.T) {
		values, err := generator.loadPayloads(map[string]interface{}{
			"new": fullpath,
		}, "/test", tempdir, false)
		require.NoError(t, err, "could not load payloads")
		require.Equal(t, map[string][]string{"new": {"test", "another"}}, values, "could not get values")
	})
	t.Run("templates-path-relative", func(t *testing.T) {
		_, err := generator.loadPayloads(map[string]interface{}{
			"new": "../../../../../../../../../etc/passwd",
		}, ".", tempdir, false)
		require.Error(t, err, "could load payloads")
	})
	t.Run("template-directory", func(t *testing.T) {
		values, err := generator.loadPayloads(map[string]interface{}{
			"new": fullpath,
		}, filepath.Join(tempdir, "test.yaml"), "/test", false)
		require.NoError(t, err, "could not load payloads")
		require.Equal(t, map[string][]string{"new": {"test", "another"}}, values, "could not get values")
	})
	t.Run("no-sandbox-unix", func(t *testing.T) {
		if osutils.IsWindows() {
			return
		}
		_, err := generator.loadPayloads(map[string]interface{}{
			"new": "/etc/passwd",
		}, "/random", "/test", true)
		require.NoError(t, err, "could load payloads")
	})
	t.Run("invalid", func(t *testing.T) {
		values, err := generator.loadPayloads(map[string]interface{}{
			"new": "/etc/passwd",
		}, "/random", "/test", false)
		require.Error(t, err, "could load payloads")
		require.Equal(t, 0, len(values), "could get values")

		values, err = generator.loadPayloads(map[string]interface{}{
			"new": fullpath,
		}, "/random", "/test", false)
		require.Error(t, err, "could load payloads")
		require.Equal(t, 0, len(values), "could get values")
	})
}
