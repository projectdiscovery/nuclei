package generators

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/stretchr/testify/require"
)

func TestLoadPayloads(t *testing.T) {
	generator := &PayloadGenerator{catalog: disk.NewCatalog("")}

	loaded, err := generator.loadPayloads(map[string]interface{}{
		"data": []string{"first", "second", "third"},
	}, "", "", "", false)
	require.NoError(t, err, "could not load payloads")
	require.Equal(t, map[string][]string{"data": {"first", "second", "third"}}, loaded, "could not load correct data")

	var tests = []struct {
		noise  string
		loaded []string
	}{
		{"low", []string{"test"}},
		{"medium", []string{"test", "another", "entry"}},
		{"high", []string{"test", "another", "entry", "final", "list", "items"}},
	}
	for _, test := range tests {
		loaded, err = generator.loadPayloads(map[string]interface{}{
			"data": map[interface{}]interface{}{"low": []string{"test"}, "medium": []string{"another", "entry"}, "high": []string{"final", "list", "items"}},
		}, "", "", test.noise, false)
		require.NoError(t, err, "could not load payloads")
		require.ElementsMatch(t, test.loaded, loaded["data"], "could not get correct noise elements")
	}
}

func TestLoadPayloadsSandbox(t *testing.T) {
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
		}, "/test", tempdir, "", true)
		require.NoError(t, err, "could not load payloads")
		require.Equal(t, map[string][]string{"new": {"test", "another"}}, values, "could not get values")
	})
	t.Run("template-directory", func(t *testing.T) {
		values, err := generator.loadPayloads(map[string]interface{}{
			"new": fullpath,
		}, filepath.Join(tempdir, "test.yaml"), "/test", "", true)
		require.NoError(t, err, "could not load payloads")
		require.Equal(t, map[string][]string{"new": {"test", "another"}}, values, "could not get values")
	})
	t.Run("no-sandbox-unix", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			return
		}
		_, err := generator.loadPayloads(map[string]interface{}{
			"new": "/etc/passwd",
		}, "/random", "/test", "", false)
		require.NoError(t, err, "could load payloads")
	})
	t.Run("invalid", func(t *testing.T) {
		values, err := generator.loadPayloads(map[string]interface{}{
			"new": "/etc/passwd",
		}, "/random", "/test", "", true)
		require.Error(t, err, "could load payloads")
		require.Equal(t, 0, len(values), "could get values")

		values, err = generator.loadPayloads(map[string]interface{}{
			"new": fullpath,
		}, "/random", "/test", "", true)
		require.Error(t, err, "could load payloads")
		require.Equal(t, 0, len(values), "could get values")
	})
}
