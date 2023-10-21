package generators

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	osutils "github.com/projectdiscovery/utils/os"
	"github.com/stretchr/testify/require"
)

func TestLoadPayloads(t *testing.T) {
	// since we are changing value of global variable i.e templates directory
	// run this test as subprocess
	if os.Getenv("LOAD_PAYLOAD_NO_ACCESS") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=TestLoadPayloadsWithAccess")
		cmd.Env = append(os.Environ(), "LOAD_PAYLOAD_NO_ACCESS=1")
		err := cmd.Run()
		if e, ok := err.(*exec.ExitError); ok && !e.Success() {
			return
		}
		if err != nil {
			t.Fatalf("process ran with err %v, want exit status 1", err)
		}
	}
	templateDir := getTemplatesDir(t)
	config.DefaultConfig.SetTemplatesDir(templateDir)

	generator := &PayloadGenerator{catalog: disk.NewCatalog(templateDir), options: getOptions(false)}
	fullpath := filepath.Join(templateDir, "payloads.txt")

	// Test sandbox
	t.Run("templates-directory", func(t *testing.T) {
		// testcase when loading file from template directory and template file is in root
		// expected to succeed
		values, err := generator.loadPayloads(map[string]interface{}{
			"new": fullpath,
		}, "/test")
		require.NoError(t, err, "could not load payloads")
		require.Equal(t, map[string][]string{"new": {"test", "another"}}, values, "could not get values")
	})
	t.Run("templates-path-relative", func(t *testing.T) {
		// testcase when loading file from template directory and template file is current working directory
		// expected to fail since this is LFI
		_, err := generator.loadPayloads(map[string]interface{}{
			"new": "../../../../../../../../../etc/passwd",
		}, ".")
		require.Error(t, err, "could load payloads")
	})
	t.Run("template-directory", func(t *testing.T) {
		// testcase when loading file from template directory and template file is inside template directory
		// expected to succeed
		values, err := generator.loadPayloads(map[string]interface{}{
			"new": fullpath,
		}, filepath.Join(templateDir, "test.yaml"))
		require.NoError(t, err, "could not load payloads")
		require.Equal(t, map[string][]string{"new": {"test", "another"}}, values, "could not get values")
	})

	t.Run("invalid", func(t *testing.T) {
		// testcase when loading file from /etc/passwd and template file is at root i.e /
		// expected to fail since this is LFI
		values, err := generator.loadPayloads(map[string]interface{}{
			"new": "/etc/passwd",
		}, "/random")
		require.Error(t, err, "could load payloads got %v", values)
		require.Equal(t, 0, len(values), "could get values")

		// testcase when loading file from template directory and template file is at root i.e /
		// expected to succeed
		values, err = generator.loadPayloads(map[string]interface{}{
			"new": fullpath,
		}, "/random")
		require.NoError(t, err, "could load payloads %v", values)
		require.Equal(t, 1, len(values), "could get values")
		require.Equal(t, []string{"test", "another"}, values["new"], "could get values")
	})
}

func TestLoadPayloadsWithAccess(t *testing.T) {
	// since we are changing value of global variable i.e templates directory
	// run this test as subprocess
	if os.Getenv("LOAD_PAYLOAD_WITH_ACCESS") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=TestLoadPayloadsWithAccess")
		cmd.Env = append(os.Environ(), "LOAD_PAYLOAD_WITH_ACCESS=1")
		err := cmd.Run()
		if e, ok := err.(*exec.ExitError); ok && !e.Success() {
			return
		}
		if err != nil {
			t.Fatalf("process ran with err %v, want exit status 1", err)
		}
	}
	templateDir := getTemplatesDir(t)
	config.DefaultConfig.SetTemplatesDir(templateDir)

	generator := &PayloadGenerator{catalog: disk.NewCatalog(templateDir), options: getOptions(true)}

	t.Run("no-sandbox-unix", func(t *testing.T) {
		if osutils.IsWindows() {
			return
		}
		_, err := generator.loadPayloads(map[string]interface{}{
			"new": "/etc/passwd",
		}, "/random")
		require.NoError(t, err, "could load payloads")
	})
}

func getTemplatesDir(t *testing.T) string {
	tempdir, err := os.MkdirTemp("", "templates-*")
	require.NoError(t, err, "could not create temp dir")
	fullpath := filepath.Join(tempdir, "payloads.txt")
	err = os.WriteFile(fullpath, []byte("test\nanother"), 0777)
	require.NoError(t, err, "could not write payload")
	return tempdir
}
